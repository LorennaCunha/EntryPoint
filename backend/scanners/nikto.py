"""
Wrapper para nikto.

- Pede saída CSV (-Format csv -output -) para parsing previsível.
- Mapeia OSVDB/severidade textual em INFO/LOW/MEDIUM/HIGH.
"""
from __future__ import annotations
import csv
import io
import re

from ..models import Finding, ScannerResult, Severity
from ._proc import have, run_cmd


HIGH_KEYWORDS = ("XSS", "SQL", "LFI", "RFI", "RCE", "shell", "directory traversal",
                 "command injection", "auth bypass")
MEDIUM_KEYWORDS = ("default", "phpinfo", "backup", "exposed", "outdated",
                   "vulnerable", "deprecated", "tls", "ssl")
LOW_KEYWORDS = ("methods", "options", "header", "robots.txt", "trace")


def _classify(msg: str) -> tuple[Severity, str]:
    low = msg.lower()
    if any(k.lower() in low for k in HIGH_KEYWORDS):
        return Severity.HIGH, msg
    if any(k.lower() in low for k in MEDIUM_KEYWORDS):
        return Severity.MEDIUM, msg
    if any(k.lower() in low for k in LOW_KEYWORDS):
        return Severity.LOW, msg
    return Severity.INFO, msg


async def run_nikto_scan(target: str, opts: dict) -> ScannerResult:
    sc = ScannerResult(name="nikto")
    if not have("nikto"):
        sc.ok = False
        sc.error = "binário 'nikto' não encontrado"
        sc.findings.append(Finding(
            source="nikto", severity=Severity.INFO,
            title="nikto não instalado — instale via apt/brew/pacote do projeto",
        ))
        return sc

    argv = [
        "nikto",
        "-h", target,
        "-Format", "csv",
        "-output", "-",
        "-ask", "no",
        "-nointeractive",
        "-maxtime", "150s",
    ]
    try:
        rc, out, err = await run_cmd(argv, timeout=170)
    except Exception as e:  # noqa: BLE001
        sc.ok = False
        sc.error = f"falha nikto: {e}"
        return sc

    if rc not in (0, 1):
        sc.ok = False
        sc.error = f"nikto rc={rc}: {err.decode(errors='ignore')[:200]}"
        return sc

    text = out.decode(errors="ignore")
    # Linhas CSV reais começam com "host","ip","port",...
    reader = csv.reader(io.StringIO(text))
    seen = set()
    for row in reader:
        if not row or len(row) < 6:
            continue
        # row: host, ip, port, osvdb-id, method, uri, message
        try:
            uri = row[5]
            msg = row[6] if len(row) > 6 else row[-1]
        except IndexError:
            continue
        msg = re.sub(r"\s+", " ", msg).strip()
        key = (uri, msg)
        if key in seen:
            continue
        seen.add(key)
        sev, title = _classify(msg)
        sc.findings.append(Finding(
            source="nikto", severity=sev, title=title, target=uri or "/",
        ))
    return sc
