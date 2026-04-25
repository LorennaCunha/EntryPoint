"""
Wrapper para ffuf — fuzzing de diretórios.

- Wordlist padrão: 'raft-large-directories.txt' dentro de ./wordlists/
  (procuramos também em /usr/share/seclists/... para Docker)
- O usuário pode subir wordlists via UI; o nome (sanitizado) chega em opts['wordlist'].
- Output JSON parseado para sitemap.
"""
from __future__ import annotations
import json
import os
import tempfile

from ..models import Finding, ScannerResult, Severity, SitemapEntry
from ._proc import have, run_cmd


WORDLIST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "wordlists")
DEFAULT_WORDLIST = "raft-large-directories.txt"

SECLISTS_FALLBACK_PATHS = [
    "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt",
    "/opt/seclists/Discovery/Web-Content/raft-large-directories.txt",
]


def _resolve_wordlist(name: str | None) -> str | None:
    if name:
        p = os.path.join(WORDLIST_DIR, name)
        if os.path.isfile(p):
            return p
    p = os.path.join(WORDLIST_DIR, DEFAULT_WORDLIST)
    if os.path.isfile(p):
        return p
    for fallback in SECLISTS_FALLBACK_PATHS:
        if os.path.isfile(fallback):
            return fallback
    return None


def _ensure_minimal_wordlist() -> str:
    """Quando nada existe, gera uma wordlist mínima embutida para não falhar."""
    minimal = [
        "admin", "administrator", "login", "logout", "register", "signup",
        "api", "api/v1", "api/v2", "graphql", "config", "config.json",
        "dashboard", "panel", "portal", "uploads", "images", "static",
        "assets", "files", "robots.txt", "sitemap.xml", ".env", ".git",
        ".git/HEAD", "backup", "backup.zip", "old", "test", "dev",
        "debug", "phpinfo.php", "server-status", "actuator", "actuator/health",
        "actuator/env", "swagger", "swagger-ui", "docs", "openapi.json",
    ]
    fd, path = tempfile.mkstemp(prefix="pentest-wl-", suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(minimal))
    return path


async def run_ffuf_scan(target: str, opts: dict) -> ScannerResult:
    sc = ScannerResult(name="ffuf")
    if not have("ffuf"):
        sc.ok = False
        sc.error = "binário 'ffuf' não encontrado no PATH"
        sc.findings.append(Finding(
            source="ffuf", severity=Severity.INFO,
            title="ffuf não instalado — instale com `go install github.com/ffuf/ffuf/v2@latest`",
        ))
        return sc

    wl = _resolve_wordlist(opts.get("wordlist"))
    if not wl:
        wl = _ensure_minimal_wordlist()

    base = target.rstrip("/")
    fuzz_url = f"{base}/FUZZ"

    fd, json_out = tempfile.mkstemp(prefix="ffuf-", suffix=".json")
    os.close(fd)

    argv = [
        "ffuf",
        "-u", fuzz_url,
        "-w", wl,
        "-mc", "200,204,301,302,307,401,403",
        "-fs", "0",
        "-t", "40",
        "-timeout", "10",
        "-of", "json",
        "-o", json_out,
        "-s",  # silencioso
    ]

    try:
        rc, _, err = await run_cmd(argv, timeout=160)
        if rc not in (0, 1):
            sc.ok = False
            sc.error = f"ffuf rc={rc}: {err.decode(errors='ignore')[:300]}"
            return sc

        with open(json_out) as f:
            data = json.load(f)
        for r in data.get("results", []):
            url = r.get("url", "")
            status = int(r.get("status", 0) or 0)
            path = url.replace(base, "") or "/"
            sc.sitemap.append(SitemapEntry(path=path, status=status))
            # findings só para coisas suspeitas
            if status in (401, 403):
                sc.findings.append(Finding(
                    source="ffuf", severity=Severity.LOW,
                    title=f"Recurso protegido descoberto ({status})", target=path,
                ))
            elif path.lower() in ("/.git", "/.git/head", "/.env", "/.svn") and status == 200:
                sc.findings.append(Finding(
                    source="ffuf", severity=Severity.HIGH,
                    title="Arquivo sensível exposto", target=path,
                ))
    finally:
        try:
            os.unlink(json_out)
        except OSError:
            pass
    return sc
