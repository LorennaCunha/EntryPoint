"""
Wrapper para nuclei.
- Saída em JSONL (-jsonl) parseada para Findings.
- Severidade do nuclei mapeada para Severity local.
"""
from __future__ import annotations
import json

from ..models import Finding, ScannerResult, Severity
from ._proc import have, run_cmd


SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


async def run_nuclei_scan(target: str, opts: dict) -> ScannerResult:
    sc = ScannerResult(name="nuclei")
    if not have("nuclei"):
        sc.ok = False
        sc.error = "binário 'nuclei' não encontrado"
        sc.findings.append(Finding(
            source="nuclei", severity=Severity.INFO,
            title="nuclei não instalado — instale com `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`",
        ))
        return sc

    severities = "low,medium,high,critical"
    if opts.get("scan_type") == "full":
        severities = "info,low,medium,high,critical"

    argv = [
        "nuclei",
        "-u", target,
        "-jsonl",
        "-silent",
        "-rate-limit", "150",
        "-timeout", "10",
        "-retries", "1",
        "-severity", severities,
        "-disable-update-check",
        "-no-color",
    ]

    try:
        rc, out, err = await run_cmd(argv, timeout=170)
    except Exception as e:  # noqa: BLE001
        sc.ok = False
        sc.error = f"falha ao executar nuclei: {e}"
        return sc

    if rc not in (0, 1, 2):
        sc.ok = False
        sc.error = f"nuclei rc={rc}: {err.decode(errors='ignore')[:200]}"
        return sc

    for line in out.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info") or {}
        sev_str = (info.get("severity") or "info").lower()
        sev = SEV_MAP.get(sev_str, Severity.INFO)
        title = info.get("name") or obj.get("template-id") or "finding"
        # target relativo
        matched = obj.get("matched-at") or obj.get("host") or obj.get("matched") or ""
        # extrair só o path
        path = ""
        if matched:
            try:
                from urllib.parse import urlparse
                p = urlparse(matched)
                path = p.path or "/"
                if p.query:
                    path += f"?{p.query}"
            except Exception:  # noqa: BLE001
                path = matched
        sc.findings.append(Finding(
            source="nuclei",
            severity=sev,
            title=title,
            target=path or "/",
        ))
    return sc
