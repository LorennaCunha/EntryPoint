#!/usr/bin/env python3
"""
CLI runner — executa um scan sem precisar do servidor web.

Uso:
  python cli.py <url>                          # scan rápido
  python cli.py <url> --full                   # scan completo
  python cli.py <url> --full --wordlist X.txt  # com wordlist específica
"""
from __future__ import annotations
import argparse
import asyncio
import sys

from backend.models import ScanRequest, ScanType
from backend.scanner_manager import run_scan
from backend.security import URLValidationError


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Pentest Recon CLI")
    p.add_argument("url", help="URL alvo (ex: https://example.com)")
    p.add_argument("--full", action="store_true", help="scan completo (todos os scanners)")
    p.add_argument("--wordlist", default=None, help="nome de wordlist em ./wordlists")
    return p.parse_args()


async def main_async() -> int:
    args = parse_args()
    req = ScanRequest(
        url=args.url,
        scan_type=ScanType.FULL if args.full else ScanType.QUICK,
        wordlist=args.wordlist,
    )
    try:
        result = await run_scan(req)
    except URLValidationError as e:
        print(f"ERRO: URL inválida — {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        print(f"ERRO: {type(e).__name__}: {e}", file=sys.stderr)
        return 1

    print(result.terminal_output)
    return 0


def main():
    try:
        sys.exit(asyncio.run(main_async()))
    except KeyboardInterrupt:
        print("\nInterrompido.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
