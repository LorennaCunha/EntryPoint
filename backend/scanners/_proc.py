"""Helper: subprocess assíncrono com timeout + check de binário."""
from __future__ import annotations
import asyncio
import shutil
from typing import Optional


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


async def run_cmd(
    argv: list[str],
    timeout: float = 120.0,
    input_data: Optional[bytes] = None,
) -> tuple[int, bytes, bytes]:
    """
    Retorna (returncode, stdout, stderr).
    Em caso de timeout, mata o processo e levanta asyncio.TimeoutError.
    """
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if input_data else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(input=input_data), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode or 0, out, err
