"""
Wrapper para Arjun — descoberta de parâmetros HTTP.

Estratégia:
  - Roda no endpoint raiz e em endpoints já achados pelo ffuf, se opts['sitemap'] vier.
  - Sem ffuf, roda só na URL passada.
  - Output JSON parseado para [PARAM DISCOVERY].
"""
from __future__ import annotations
import json
import os
import tempfile

from ..models import ParamDiscovery, ScannerResult, Severity, Finding
from ._proc import have, run_cmd


async def _run_arjun_one(target: str) -> list[str]:
    fd, out = tempfile.mkstemp(prefix="arjun-", suffix=".json")
    os.close(fd)
    argv = [
        "arjun",
        "-u", target,
        "-oJ", out,
        "-q",
        "-t", "20",
        "--stable",
    ]
    try:
        rc, _, err = await run_cmd(argv, timeout=120)
        if rc != 0:
            return []
        try:
            with open(out) as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return []
        # Arjun produz dict {url: {"params": [...], ...}} ou lista
        params: list[str] = []
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, dict):
                    params.extend(v.get("params", []) or [])
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    params.extend(item.get("params", []) or [])
        return list(dict.fromkeys(params))  # dedupe
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass


async def run_arjun_scan(target: str, opts: dict) -> ScannerResult:
    sc = ScannerResult(name="arjun")
    if not have("arjun"):
        sc.ok = False
        sc.error = "binário 'arjun' não encontrado"
        sc.findings.append(Finding(
            source="arjun", severity=Severity.INFO,
            title="arjun não instalado — instale com `pipx install arjun`",
        ))
        return sc

    # endpoints alvo: raiz + (se o ffuf estiver no mesmo run) eventuais endpoints de API
    endpoints = [target]
    sitemap = opts.get("sitemap") or []
    for entry in sitemap:
        path = getattr(entry, "path", "") or (entry.get("path") if isinstance(entry, dict) else "")
        if any(k in path.lower() for k in ("api", "search", "login", "query")):
            endpoints.append(target.rstrip("/") + path)
    # limita
    endpoints = list(dict.fromkeys(endpoints))[:5]

    for url in endpoints:
        try:
            params = await _run_arjun_one(url)
        except Exception:  # noqa: BLE001
            params = []
        if params:
            ep_path = url.split("/", 3)[-1] if url.count("/") >= 3 else "/"
            ep_path = "/" + ep_path if not ep_path.startswith("/") else ep_path
            sc.params.append(ParamDiscovery(endpoint=ep_path, params=params))
            sc.findings.append(Finding(
                source="arjun", severity=Severity.INFO,
                title=f"{len(params)} parâmetros descobertos",
                target=ep_path,
                detail=", ".join(params),
            ))
    return sc
