"""
Orquestrador.

- Executa scanners em paralelo via asyncio.gather.
- Aplica timeout global por scanner.
- Calcula score e gera saída de terminal final.
- Persiste resultados em memória (dict scan_id -> ScanResult).

NÃO depende da existência das ferramentas externas: cada scanner trata
sua ausência (return finding INFO + ok=False).
"""
from __future__ import annotations
import asyncio
import time
import uuid
from typing import Optional

from .models import (
    ScanRequest,
    ScanResult,
    ScanStatus,
    ScanType,
    ScannerResult,
)
from .formatters import render_terminal, calculate_score
from .security import validate_target

from .scanners.headers import run_headers_scan
from .scanners.tls import run_tls_scan
from .scanners.ffuf import run_ffuf_scan
from .scanners.arjun import run_arjun_scan
from .scanners.nuclei import run_nuclei_scan
from .scanners.nikto import run_nikto_scan
from .scanners.custom import run_custom_scan


SCANNER_TIMEOUT_S = 180  # 3 min hard cap por scanner

# Map nome -> coroutine factory.  Cada scanner aceita (target, opts) -> ScannerResult
SCANNERS_QUICK = ["headers", "tls", "custom"]
SCANNERS_FULL = ["headers", "tls", "ffuf", "arjun", "nuclei", "nikto", "custom"]


_RESULTS: dict[str, ScanResult] = {}


def _scanner_factory(name: str):
    return {
        "headers": run_headers_scan,
        "tls": run_tls_scan,
        "ffuf": run_ffuf_scan,
        "arjun": run_arjun_scan,
        "nuclei": run_nuclei_scan,
        "nikto": run_nikto_scan,
        "custom": run_custom_scan,
    }[name]


async def _run_one(name: str, target: str, opts: dict) -> ScannerResult:
    started = time.monotonic()
    try:
        coro = _scanner_factory(name)(target, opts)
        sc: ScannerResult = await asyncio.wait_for(coro, timeout=SCANNER_TIMEOUT_S)
    except asyncio.TimeoutError:
        sc = ScannerResult(name=name, ok=False, error="timeout")
    except Exception as e:  # noqa: BLE001
        sc = ScannerResult(name=name, ok=False, error=f"{type(e).__name__}: {e}")
    sc.duration_ms = int((time.monotonic() - started) * 1000)
    return sc


def list_scanners(scan_type: ScanType) -> list[str]:
    return SCANNERS_QUICK if scan_type == ScanType.QUICK else SCANNERS_FULL


def get_result(scan_id: str) -> Optional[ScanResult]:
    return _RESULTS.get(scan_id)


def list_results() -> list[ScanResult]:
    return list(_RESULTS.values())


async def run_scan(req: ScanRequest) -> ScanResult:
    """Pipeline principal — síncrono do ponto de vista do caller."""
    scan_id = uuid.uuid4().hex[:12]
    canonical = validate_target(req.url)
    result = ScanResult(
        scan_id=scan_id,
        url=canonical,
        scan_type=req.scan_type,
        status=ScanStatus.RUNNING,
    )
    _RESULTS[scan_id] = result

    opts = {
        "wordlist": req.wordlist,
        "scan_type": req.scan_type.value,
    }

    names = list_scanners(req.scan_type)
    coros = [_run_one(n, canonical, opts) for n in names]
    scanner_results = await asyncio.gather(*coros, return_exceptions=False)

    result.scanners = scanner_results
    score, status_label = calculate_score(result)
    result.score = score
    result.score_status = status_label
    result.terminal_output = render_terminal(result)
    result.status = ScanStatus.DONE
    from datetime import datetime
    result.finished_at = datetime.utcnow()
    return result


def start_scan_background(req: ScanRequest) -> str:
    """
    Cria scan_id e dispara em background (fire-and-forget).
    Retorna scan_id imediatamente.
    """
    scan_id = uuid.uuid4().hex[:12]
    placeholder = ScanResult(
        scan_id=scan_id,
        url=req.url,
        scan_type=req.scan_type,
        status=ScanStatus.PENDING,
    )
    _RESULTS[scan_id] = placeholder

    async def _runner():
        try:
            canonical = validate_target(req.url)
            placeholder.url = canonical
            placeholder.status = ScanStatus.RUNNING
            opts = {"wordlist": req.wordlist, "scan_type": req.scan_type.value}
            names = list_scanners(req.scan_type)
            coros = [_run_one(n, canonical, opts) for n in names]
            scs = await asyncio.gather(*coros)
            placeholder.scanners = scs
            score, status_label = calculate_score(placeholder)
            placeholder.score = score
            placeholder.score_status = status_label
            placeholder.terminal_output = render_terminal(placeholder)
            placeholder.status = ScanStatus.DONE
        except Exception as e:  # noqa: BLE001
            placeholder.status = ScanStatus.ERROR
            placeholder.error = f"{type(e).__name__}: {e}"
        finally:
            from datetime import datetime
            placeholder.finished_at = datetime.utcnow()

    asyncio.create_task(_runner())
    return scan_id
