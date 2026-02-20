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
from fastapi.responses import PlainTextResponse

@app.get("/privacy", response_class=PlainTextResponse)
def privacy():
    return "Privacy policy: This service processes user-provided public URLs to download PDFs and upload them to the user’s Google Drive folder. No data is sold or shared with third parties."

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

import json
import binascii

def _get_drive_client():
    b64 = (os.environ.get("GDRIVE_SA_JSON_B64") or "").strip()
    if not b64:
        raise RuntimeError("Missing env var GDRIVE_SA_JSON_B64")

    # arregla padding si falta
    b64 = b64.replace("\n", "").replace("\r", "").strip()
    missing = len(b64) % 4
    if missing:
        b64 += "=" * (4 - missing)

    try:
        sa_json = base64.b64decode(b64).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as e:
        raise RuntimeError(f"Invalid base64 in GDRIVE_SA_JSON_B64: {e}")

    info = json.loads(sa_json)
    creds = service_account.Credentials.from_service_account_info(
        info,
        scopes=["https://www.googleapis.com/auth/drive"],
    )
    return build("drive", "v3", credentials=creds, cache_discovery=False)

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

        # FFIB: si hay enlace a ficha partido con CodActa, es candidato a acta
        if "NFG_CmpPartido" in href and ("CodActa=" in href or "cod_acta=" in href):
        if not is_postponed and not is_admin:
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
    for it in items:
        key = (it.match_date, it.is_postponed, it.is_admin_3_0, tuple(sorted(it.acta_links)))
        if key in seen:
            continue
        seen.add(key)
        # Keep even if no links, because we want to count postponed/admin cases for reporting
        uniq.append(it)

    return uniq


def try_download_pdf(url: str) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Returns (bytes, content_type) if it looks like a PDF.
    """
    r = SESSION.get(url, timeout=60, allow_redirects=True)
    if r.status_code >= 400:
        return None, None
    ctype = (r.headers.get("content-type") or "").lower()
    if "application/pdf" in ctype or r.content[:4] == b"%PDF":
        return r.content, ctype
    # Sometimes it returns HTML that contains an embedded pdf link; try to find it
    if "text/html" in ctype:
        soup = BeautifulSoup(r.text, "lxml")
        # find direct .pdf link
        a = soup.find("a", href=re.compile(r"\.pdf", re.I))
                # buscar botón/enlace "Generar PDF"
        btn = soup.find("a", string=re.compile(r"Generar\s*PDF", re.I))
        if btn and btn.get("href"):
            pdf_url = urljoin(url, btn["href"])
            r2 = SESSION.get(pdf_url, timeout=60, allow_redirects=True)
            ctype2 = (r2.headers.get("content-type") or "").lower()
            if "application/pdf" in ctype2 or r2.content[:4] == b"%PDF":
                return r2.content, ctype2

        # fallback: algunas veces es un onclick con URL
        for el in soup.find_all(["a", "button"]):
            onclick = (el.get("onclick") or "")
            m = re.search(r"(NFG_[^\"']+\.pdf[^\"']*|NFG_[^\"']+CodActa=\d+[^\"']*)", onclick)
            if m:
                pdf_url = urljoin(url, m.group(1))
                r2 = SESSION.get(pdf_url, timeout=60, allow_redirects=True)
                ctype2 = (r2.headers.get("content-type") or "").lower()
                if "application/pdf" in ctype2 or r2.content[:4] == b"%PDF":
                    return r2.content, ctype2

        if a and a.get("href"):
            pdf_url = urljoin(url, a["href"])
            r2 = SESSION.get(pdf_url, timeout=60, allow_redirects=True)
            ctype2 = (r2.headers.get("content-type") or "").lower()
            if "application/pdf" in ctype2 or r2.content[:4] == b"%PDF":
                return r2.content, ctype2
    return None, ctype


def build_filename(naming: Naming, comp: str, group: str, jornada: str, match_date: str, pxx: int) -> str:
    p = naming.pattern
    # Replace known tokens
    # We keep your “pattern” simple: user wants it exactly; we only fill pXX manually with p01 etc.
    out = p
    out = out.replace("Temporada", naming.temporada)
    out = out.replace("Competicion", comp)
    out = out.replace("Grupo", group)
    out = out.replace("Jornada", jornada)
    out = out.replace("fecha-jornada", match_date or "YYYY-MM-DD")

    # pXX
    out = out.replace("pXX", f"p{pxx:02d}")
    # Ensure extension
    if not out.lower().endswith(".pdf"):
        out += ".pdf"
    # Sanitize
    out = re.sub(r"\s+", "_", out)
    out = out.replace("__", "_")
    return out


# ---------------------------
# API
# ---------------------------

@app.get("/ping")
def ping():
    return {"ok": True}


@app.post("/extract-download-upload", response_model=ExtractResponse)
def extract_download_upload(req: ExtractRequest):
    drive = None
    try:
        drive = _get_drive_client()
    except Exception as e:
        # We can still scrape, but uploads will fail.
        drive = None
        drive_err = str(e)
    else:
        drive_err = None

    reports: List[LinkReport] = []

    for link in req.urls:
        comp = _extract_cod_from_url(link, "CodCompeticion") or "CompeticionXX"
        group = _extract_cod_from_url(link, "CodGrupo") or "GrupoXX"
        jornada = _extract_codjornada(link) or "JXX"

        try:
            items = ffib_parse_jornada(link)
        except Exception as e:
            reports.append(
                LinkReport(
                    url=link,
                    status="failed",
                    files=[],
                    notes=f"Failed to load/parse FFIB page: {e}",
                )
            )
            continue

        file_results: List[FileResult] = []
        zip_members: List[Tuple[str, bytes]] = []

        p_counter = 0
        green_found = 0
        postponed = 0
        admin = 0

        # For each match item, process its green acta links
        for it in items:
            if it.is_postponed:
                postponed += 1
                continue
            if it.is_admin_3_0:
                admin += 1
                continue

            for acta_url in it.acta_links:
                green_found += 1
                p_counter += 1

                match_date = it.match_date or "YYYY-MM-DD"
                final_name = build_filename(req.naming, comp, group, f"J{jornada}" if not str(jornada).startswith("J") else jornada, match_date, p_counter)

                pdf_bytes, ctype = try_download_pdf(acta_url)
                if not pdf_bytes:
                    file_results.append(
                        FileResult(
                            final_name=final_name,
                            status="failed",
                            reason=f"Could not download PDF from acta link (content-type={ctype})",
                            source_url=acta_url,
                        )
                    )
                    continue

                if drive is None:
                    file_results.append(
                        FileResult(
                            final_name=final_name,
                            status="failed",
                            reason=f"Drive client not available: {drive_err}",
                            source_url=acta_url,
                        )
                    )
                    continue

                try:
                    drive_link = drive_upload_bytes(
                        drive,
                        folder_id=req.drive_folder_id,
                        filename=final_name,
                        content_bytes=pdf_bytes,
                        mimetype="application/pdf",
                    )
                    file_results.append(
                        FileResult(
                            final_name=final_name,
                            status="ok",
                            reason=None,
                            source_url=acta_url,
                            drive_link=drive_link,
                        )
                    )
                    zip_members.append((final_name, pdf_bytes))
                except Exception as e:
                    file_results.append(
                        FileResult(
                            final_name=final_name,
                            status="failed",
                            reason=f"Drive upload failed: {e}",
                            source_url=acta_url,
                        )
                    )

        # ZIP if requested and we have at least 1 ok file
        zip_link = None
        if req.create_zip and drive is not None and zip_members:
            zip_name = f"{req.naming.temporada}_{comp}_{group}_J{jornada}_actas.zip"
            zbuf = io.BytesIO()
            with zipfile.ZipFile(zbuf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for fname, bts in zip_members:
                    zf.writestr(fname, bts)
            zbuf.seek(0)
            try:
                zip_link = drive_upload_bytes(
                    drive,
                    folder_id=req.drive_folder_id,
                    filename=zip_name,
                    content_bytes=zbuf.read(),
                    mimetype="application/zip",
                )
            except Exception as e:
                # Keep partial success
                zip_link = None
                file_results.append(
                    FileResult(
                        final_name=zip_name,
                        status="failed",
                        reason=f"ZIP upload failed: {e}",
                        source_url=None,
                    )
                )

        # Determine status
        ok_count = sum(1 for f in file_results if f.status == "ok")
        failed_count = sum(1 for f in file_results if f.status == "failed")

        if ok_count > 0 and failed_count == 0:
            status = "ok"
        elif ok_count > 0 and failed_count > 0:
            status = "partial"
        else:
            status = "failed"

        notes = (
            f"FFIB parsed. Green acta links found: {green_found}. "
            f"Postponed blocks skipped: {postponed}. "
            f"Admin/retirada blocks skipped: {admin}. "
            "Rule: only green icons => download."
        )
        if drive_err:
            notes += f" Drive not ready: {drive_err}"

        reports.append(
            LinkReport(
                url=link,
                status=status,
                files=file_results,
                zip_drive_link=zip_link,
                notes=notes,
            )
        )

    overall = "ok" if all(r.status == "ok" for r in reports) else ("partial" if any(r.status == "ok" for r in reports) else "failed")
    return ExtractResponse(status=overall, reports=reports, notes="FFIB + Drive + ZIP pipeline executed.")
