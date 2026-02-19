from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

app = FastAPI(title="PDF Extractor I API", version="1.0.0")

class NamingRules(BaseModel):
    pattern: str
    temporada: str

class PipelineRequest(BaseModel):
    urls: List[str]
    drive_folder_id: str
    create_zip: Optional[bool] = True
    source_hint: Optional[str] = None
    naming: NamingRules

@app.get("/ping")
def ping():
    return {"ok": True}

@app.post("/extract-download-upload")
def extract_download_upload(req: PipelineRequest) -> Dict[str, Any]:
    # MVP: confirma que la Action llama al backend.
    report = []
    for u in req.urls:
        report.append({
            "input_url": u,
            "files": [
                {
                    "final_name": f"{req.naming.temporada}_CompeticionXX_GrupoXX_JXX_YYYY-MM-DD_p01.pdf",
                    "status": "failed",
                    "drive_link": "",
                    "notes": "Backend OK. Falta implementar scraping/descarga/subida."
                }
            ]
        })
    return {"report": report, "zip_drive_link": ""}
