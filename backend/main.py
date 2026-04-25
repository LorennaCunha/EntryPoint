"""
FastAPI app — exibe dashboard e expõe API REST.

Endpoints:
  GET  /                       -> serve frontend (index.html)
  POST /api/scan               -> dispara scan; retorna scan_id
  GET  /api/scan/{scan_id}     -> status + saída terminal pronta + dados estruturados
  GET  /api/scans              -> lista de scans em memória
  GET  /api/wordlists          -> lista wordlists disponíveis
  POST /api/wordlists/upload   -> upload de wordlist custom
"""
from __future__ import annotations
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from .models import ScanRequest, ScanResult
from .scanner_manager import (
    start_scan_background,
    get_result,
    list_results,
)
from .security import URLValidationError, safe_filename


BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
WORDLIST_DIR = BASE_DIR / "wordlists"
WORDLIST_DIR.mkdir(exist_ok=True)


app = FastAPI(title="Pentest Recon Tool", version="1.0.0")

# Limita CORS ao localhost — esta ferramenta é local
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------- helpers de serialização ---------------

def result_to_payload(r: ScanResult) -> dict[str, Any]:
    """Payload compacto para o front. Não exporta JSON cru de scanners."""
    return {
        "scan_id": r.scan_id,
        "url": r.url,
        "scan_type": r.scan_type.value,
        "status": r.status.value,
        "score": r.score,
        "score_status": r.score_status,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "terminal_output": r.terminal_output,
        "error": r.error,
        # Sections já formatadas para consumo direto pela UI
        "sections": _build_sections(r),
    }


def _build_sections(r: ScanResult) -> dict[str, str]:
    from .formatters import (
        format_headers, format_tls, format_sitemap, format_params,
        _vuln_section,
    )
    by_name = {sc.name: sc for sc in r.scanners}
    sections = {}
    if "headers" in by_name:
        sections["headers"] = format_headers(by_name["headers"])
    if "tls" in by_name:
        sections["tls"] = format_tls(by_name["tls"])
    if "ffuf" in by_name:
        sections["sitemap"] = format_sitemap(by_name["ffuf"])
    if "arjun" in by_name:
        sections["params"] = format_params(by_name["arjun"])
    sections["vulnerabilities"] = _vuln_section(r)
    return sections


# --------------- rotas API ---------------

@app.post("/api/scan")
async def create_scan(req: ScanRequest):
    try:
        scan_id = start_scan_background(req)
    except URLValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"scan_id": scan_id}


@app.get("/api/scan/{scan_id}")
async def fetch_scan(scan_id: str):
    r = get_result(scan_id)
    if not r:
        raise HTTPException(status_code=404, detail="scan_id não encontrado")
    return result_to_payload(r)


@app.get("/api/scans")
async def all_scans():
    return [
        {
            "scan_id": r.scan_id,
            "url": r.url,
            "status": r.status.value,
            "score": r.score,
            "started_at": r.started_at.isoformat() if r.started_at else None,
        }
        for r in list_results()
    ]


@app.get("/api/wordlists")
async def list_wordlists():
    files = []
    for f in sorted(WORDLIST_DIR.iterdir()):
        if f.is_file():
            files.append({"name": f.name, "size": f.stat().st_size})
    return {"wordlists": files, "default": "raft-large-directories.txt"}


@app.post("/api/wordlists/upload")
async def upload_wordlist(file: UploadFile = File(...)):
    try:
        name = safe_filename(file.filename or "")
    except URLValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    dest = WORDLIST_DIR / name
    contents = await file.read()
    if len(contents) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Wordlist > 50MB")
    dest.write_bytes(contents)
    return {"name": name, "size": len(contents)}


# --------------- frontend ---------------

@app.get("/")
async def index():
    f = FRONTEND_DIR / "index.html"
    if not f.exists():
        return JSONResponse({"error": "frontend não encontrado"}, status_code=500)
    return FileResponse(f)


# Serve os assets do front (style.css, app.js)
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
