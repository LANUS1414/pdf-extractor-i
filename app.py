import base64
import io
import os
import re
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI
from pydantic import BaseModel, Field

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

app = FastAPI(title="pdf-extractor-i", version="1.0.0")

UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": UA})

# ---------------------------
# Models
# ---------------------------

class Naming(BaseModel):
    pattern: str = Field(..., description="Naming pattern with pXX placeholder")
    temporada: str = Field(..., description="e.g. 2025-26")


class ExtractRequest(BaseModel):
    urls: List[str]
    drive_folder_id: str
    create_zip: bool = True
    source_hint: str = "ffib"
    naming: Naming


class FileResult(BaseModel):
    final_name: str
    status: str  # ok | failed | skipped
    reason: Optional[str] = None
    source_url: Optional[str] = None
    drive_link: Optional[str] = None


class LinkReport(BaseModel):
    url: str
    status: str  # ok | failed | partial
    files: List[FileResult] = []
    zip_drive_link: Optional[str] = None
    notes: Optional[str] = None


class ExtractResponse(BaseModel):
    status: str
    reports: List[LinkReport]
    notes: Optional[str] = None


# ---------------------------
# Google Drive helper
# ---------------------------

def _get_drive_client():
    b64 = os.environ.get("GDRIVE_SA_JSON_B64", "").strip()
    if not b64:
        raise RuntimeError("Missing env var GDRIVE_SA_JSON_B64")

    sa_json = base64.b64decode(b64).decode("utf-8")
    creds = service_account.Credentials.from_service_account_info(
        eval(sa_json) if sa_json.strip().startswith("{") is False else __import__("json").loads(sa_json),
        scopes=["https://www.googleapis.com/auth/drive"],
    )
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def drive_upload_bytes(
    drive,
    folder_id: str,
    filename: str,
    content_bytes: bytes,
    mimetype: str = "application/pdf",
) -> str:
    media = MediaIoBaseUpload(io.BytesIO(content_bytes), mimetype=mimetype, resumable=False)
    file_metadata = {"name": filename, "parents": [folder_id]}
    created = drive.files().create(body=file_metadata, media_body=media, fields="id,webViewLink").execute()
    return created.get("webViewLink") or f"https://drive.google.com/file/d/{created['id']}/view"


# ---------------------------
# FFIB scraping
# ---------------------------

@dataclass
class FFIBItem:
    match_date: Optional[str]  # YYYY-MM-DD
    is_postponed: bool
    is_admin_3_0: bool
    acta_links: List[str]      # candidate links to pdf/acta


def _extract_codjornada(url: str) -> Optional[str]:
    try:
        q = parse_qs(urlparse(url).query)
        val = q.get("CodJornada") or q.get("codjornada")
        return val[0] if val else None
    except Exception:
        return None


def _extract_cod_from_url(url: str, key: str) -> Optional[str]:
    q = parse_qs(urlparse(url).query)
    v = q.get(key) or q.get(key.lower())
    return v[0] if v else None


def _normalize_date(text: str) -> Optional[str]:
    # FFIB often uses DD-MM-YYYY
    text = (text or "").strip()
    m = re.search(r"(\d{2})-(\d{2})-(\d{4})", text)
    if not m:
        return None
    dd, mm, yyyy = m.group(1), m.group(2), m.group(3)
    return f"{yyyy}-{mm}-{dd}"


def _looks_green_icon(el) -> bool:
    # Heuristic: green icons usually have a green background class/style
    # We detect common hints: style contains green; class contains 'green'; svg/img alt/title contains 'acta' + 'pdf'
    style = (el.get("style") or "").lower()
    cls = " ".join(el.get("class") or []).lower()
    title = (el.get("title") or "").lower()
    aria = (el.get("aria-label") or "").lower()
    alt = (el.get("alt") or "").lower()
    txt = f"{title} {aria} {alt} {cls} {style}"
    if "green" in txt or "#00" in txt or "rgb(0" in txt:
        return True
    # Sometimes the <a> contains an <i> with green class
    return False


def _is_postponed_block(block_text: str) -> bool:
    return "aplazado" in (block_text or "").lower()


def _is_admin_3_0(block_text: str) -> bool:
    # your rule: 3-0 administrative for withdrawn/no acta
    t = (block_text or "").lower()
    if "retirad" in t or "incomparec" in t:
        return True
    # also if score shown 3-0 and there's mention of admin
    if "3-0" in t and ("administr" in t or "admin" in t):
        return True
    return False


def ffib_parse_jornada(url: str) -> List[FFIBItem]:
    r = SESSION.get(url, timeout=30)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "lxml")

    # FFIB pages vary. We'll treat each "match card" as a container that includes teams + score + date.
    # Heuristic: look for blocks that contain a date like DD-MM-YYYY and team names.
    items: List[FFIBItem] = []

    # Find candidate containers: any element that contains a date pattern
    date_nodes = soup.find_all(string=re.compile(r"\d{2}-\d{2}-\d{4}"))
    seen_containers = set()

    for dn in date_nodes:
        container = dn.parent
        # climb up a bit to capture whole match block
        for _ in range(5):
            if container is None:
                break
            container = container.parent
        if not container:
            continue

        cid = id(container)
        if cid in seen_containers:
            continue
        seen_containers.add(cid)

        block_text = container.get_text(" ", strip=True)
        match_date = _normalize_date(block_text)

        is_postponed = _is_postponed_block(block_text)
        is_admin = _is_admin_3_0(block_text)

        # find links that could be acta/pdf inside container
        # Often there are icons in <a> tags
        acta_links = []
        for a in container.find_all("a", href=True):
            href = a["href"]
            full = urljoin(url, href)

            a_txt = (a.get_text(" ", strip=True) or "").lower()
            title = (a.get("title") or "").lower()
            aria = (a.get("aria-label") or "").lower()
            blob = f"{a_txt} {title} {aria} {href}".lower()

            # Candidate if mentions acta/pdf or looks like pdf endpoint
            if ".pdf" in blob or "acta" in blob or "pdf" in blob:
                # If FFIB uses a green icon, try to detect it by style/class on <a> or its children
                is_green = _looks_green_icon(a)
                if not is_green:
                    # check children for green clues
                    for ch in a.find_all(True):
                        if _looks_green_icon(ch):
                            is_green = True
                            break
                # Only include if green (acta elaborada) – your rule
                if is_green and not is_postponed and not is_admin:
                    acta_links.append(full)

        # If we didn't find any green link in that container, skip it (no acta)
        items.append(
            FFIBItem(
                match_date=match_date,
                is_postponed=is_postponed,
                is_admin_3_0=is_admin,
                acta_links=acta_links,
            )
        )

    # Deduplicate items by (date + links + flags)
    uniq: List[FFIBItem] = []
    seen = set()
    for
