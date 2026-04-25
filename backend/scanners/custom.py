"""
Scanner customizado:
  - Métodos HTTP perigosos habilitados (TRACE, PUT, DELETE, OPTIONS verbose)
  - CORS misconfiguration (Origin refletido + Allow-Credentials true,
    ou Access-Control-Allow-Origin: *)
  - Open Redirect via parâmetros comuns (?next=, ?url=, ?redirect=, ?return=)
  - Directory Listing (Index of /, autoindex)
"""
from __future__ import annotations
import re
import httpx
from urllib.parse import urlparse, urljoin

from ..models import Finding, ScannerResult, Severity

DANGEROUS_METHODS = ["TRACE", "PUT", "DELETE", "CONNECT"]
REDIRECT_PARAMS = ["next", "url", "redirect", "return", "redir", "dest", "destination"]
DIRLIST_PATHS = ["/", "/uploads/", "/static/", "/files/", "/images/", "/assets/", "/backup/"]
DIRLIST_REGEX = re.compile(r"<title>\s*Index of\s*/", re.IGNORECASE)


async def _check_methods(client: httpx.AsyncClient, base: str, sc: ScannerResult):
    try:
        r = await client.options(base, timeout=10.0)
        allow = r.headers.get("Allow", "") or r.headers.get("allow", "")
        if allow:
            sc.findings.append(Finding(
                source="custom", severity=Severity.INFO,
                title=f"OPTIONS revela métodos: {allow}", target="/",
            ))
        for m in DANGEROUS_METHODS:
            if m in allow.upper():
                sc.findings.append(Finding(
                    source="custom", severity=Severity.MEDIUM,
                    title=f"Método HTTP perigoso permitido: {m}", target="/",
                ))
    except Exception:  # noqa: BLE001
        pass

    # TRACE direto (alguns servers respondem mesmo sem listar em Allow)
    try:
        r = await client.request("TRACE", base, timeout=8.0)
        if r.status_code == 200 and "TRACE" in r.text.upper():
            sc.findings.append(Finding(
                source="custom", severity=Severity.MEDIUM,
                title="TRACE habilitado (Cross-Site Tracing)", target="/",
            ))
    except Exception:  # noqa: BLE001
        pass


async def _check_cors(client: httpx.AsyncClient, base: str, sc: ScannerResult):
    evil = "https://evil.example.com"
    try:
        r = await client.get(base, headers={"Origin": evil}, timeout=10.0)
    except Exception:  # noqa: BLE001
        return
    aco = r.headers.get("access-control-allow-origin", "")
    acc = r.headers.get("access-control-allow-credentials", "").lower()
    if aco == "*":
        sev = Severity.LOW if acc != "true" else Severity.HIGH
        sc.findings.append(Finding(
            source="custom", severity=sev,
            title="CORS misconfiguration: Allow-Origin: *"
                  + (" com Allow-Credentials: true" if acc == "true" else ""),
            target="/",
        ))
    elif evil in aco and acc == "true":
        sc.findings.append(Finding(
            source="custom", severity=Severity.HIGH,
            title=f"CORS misconfiguration: Origin refletido ({aco}) com credentials",
            target="/",
        ))


async def _check_open_redirect(client: httpx.AsyncClient, base: str, sc: ScannerResult):
    payload = "https://evil.example.com/x"
    for param in REDIRECT_PARAMS:
        url = f"{base}{'&' if '?' in base else '?'}{param}={payload}"
        try:
            r = await client.get(url, follow_redirects=False, timeout=10.0)
        except Exception:  # noqa: BLE001
            continue
        loc = r.headers.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and "evil.example.com" in loc:
            sc.findings.append(Finding(
                source="custom", severity=Severity.HIGH,
                title=f"Open redirect via parâmetro {param}", target=url,
                detail=f"Location: {loc}",
            ))
            return  # uma evidência basta


async def _check_dirlisting(client: httpx.AsyncClient, base: str, sc: ScannerResult):
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    for p in DIRLIST_PATHS:
        url = urljoin(root, p)
        try:
            r = await client.get(url, timeout=10.0)
        except Exception:  # noqa: BLE001
            continue
        if r.status_code == 200 and DIRLIST_REGEX.search(r.text):
            sc.findings.append(Finding(
                source="custom", severity=Severity.MEDIUM,
                title="Directory listing habilitado", target=p,
            ))


async def run_custom_scan(target: str, opts: dict) -> ScannerResult:
    sc = ScannerResult(name="custom")
    try:
        async with httpx.AsyncClient(verify=False, timeout=15.0,
                                     headers={"User-Agent": "pentest-tool/1.0"}) as c:
            await _check_methods(c, target, sc)
            await _check_cors(c, target, sc)
            await _check_open_redirect(c, target, sc)
            await _check_dirlisting(c, target, sc)
    except Exception as e:  # noqa: BLE001
        sc.ok = False
        sc.error = f"{type(e).__name__}: {e}"
    return sc
