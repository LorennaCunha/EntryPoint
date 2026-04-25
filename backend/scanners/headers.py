"""
Verifica headers de segurança.

Considera AUSENTE:
  - HSTS (Strict-Transport-Security)
  - X-Frame-Options
  - Content-Security-Policy
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
"""
from __future__ import annotations
import httpx

from ..models import (
    Finding,
    HeaderFinding,
    ScannerResult,
    Severity,
)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

SEVERITY_BY_HEADER = {
    "Strict-Transport-Security": Severity.MEDIUM,
    "X-Frame-Options": Severity.MEDIUM,
    "Content-Security-Policy": Severity.MEDIUM,
    "X-Content-Type-Options": Severity.LOW,
    "Referrer-Policy": Severity.LOW,
    "Permissions-Policy": Severity.LOW,
}


async def run_headers_scan(target: str, opts: dict) -> ScannerResult:
    sc = ScannerResult(name="headers")
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15.0) as client:
            r = await client.get(target, headers={"User-Agent": "pentest-tool/1.0"})
    except Exception as e:  # noqa: BLE001
        sc.ok = False
        sc.error = f"{type(e).__name__}: {e}"
        return sc

    headers_lower = {k.lower(): v for k, v in r.headers.items()}
    for h in SECURITY_HEADERS:
        val = headers_lower.get(h.lower())
        sc.headers.append(HeaderFinding(name=h, present=val is not None, value=val))
        if val is None:
            sc.findings.append(
                Finding(
                    source="headers",
                    severity=SEVERITY_BY_HEADER[h],
                    title=f"Header de segurança ausente: {h}",
                    target="/",
                )
            )

    # Server / X-Powered-By disclosure
    for disclosure in ("server", "x-powered-by"):
        if disclosure in headers_lower:
            sc.findings.append(
                Finding(
                    source="headers",
                    severity=Severity.INFO,
                    title=f"Banner exposto: {disclosure} = {headers_lower[disclosure]}",
                    target="/",
                )
            )
    return sc
