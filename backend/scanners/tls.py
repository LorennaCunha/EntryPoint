"""
Análise TLS:
  - Detecta versão e cifra negociadas
  - Lê certificado (subject/issuer/expiração)
  - Para cada protocolo testado (TLSv1, TLSv1.1, TLSv1.2, TLSv1.3) tenta
    enumerar cifras suportadas e marca as fracas conforme heurística.

Sem dependências externas além de cryptography (já em requirements).
"""
from __future__ import annotations
import asyncio
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

from ..models import (
    Finding,
    ScannerResult,
    Severity,
    TLSInfo,
)

# Cifras consideradas fracas (CBC, RC4, 3DES, NULL, EXPORT, MD5, anon, RSA-key-exchange)
WEAK_PATTERNS = (
    "_CBC_",
    "_RC4_",
    "_3DES_",
    "_DES_",
    "_NULL_",
    "_EXPORT",
    "_MD5",
    "_anon_",
)
# Adicionalmente, cifras com troca de chave RSA (sem PFS) também são fracas.
WEAK_KEX_PATTERNS = ("TLS_RSA_WITH_",)

PROTOCOLS_TO_TEST = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
]


def _is_weak(cipher_name: str) -> bool:
    name = cipher_name.upper()
    if any(p in name for p in WEAK_PATTERNS):
        return True
    if any(name.startswith(p) for p in WEAK_KEX_PATTERNS):
        return True
    return False


def _connect_with_protocol(host: str, port: int, version: ssl.TLSVersion):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        # OpenSSL pode recusar TLS 1.0/1.1
        return None, None, None
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with socket.create_connection((host, port), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ss:
                cipher = ss.cipher()
                cert = ss.getpeercert(binary_form=True)
                proto = ss.version()
                return proto, cipher, cert
    except Exception:  # noqa: BLE001
        return None, None, None


def _parse_cert(der_bytes: bytes) -> tuple[str, str, str]:
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(der_bytes, default_backend())
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
        if isinstance(not_after, datetime):
            expires = not_after.strftime("%Y-%m-%d")
        else:
            expires = str(not_after)
        return subject, issuer, expires
    except Exception:  # noqa: BLE001
        return "", "", ""


def _enumerate_supported_ciphers(host: str, port: int, version: ssl.TLSVersion) -> list[str]:
    """Heurística leve: pega lista do SSLContext após negociar este protocolo."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return []
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass

    # Para 1.3, set_ciphers não controla; OpenSSL fixa 5 suítes.
    # Sondamos com a sessão real e listamos do contexto.
    try:
        with socket.create_connection((host, port), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                pass
    except Exception:  # noqa: BLE001
        return []
    return [c["name"] for c in ctx.get_ciphers()]


async def run_tls_scan(target: str, opts: dict) -> ScannerResult:
    sc = ScannerResult(name="tls")
    parsed = urlparse(target)
    if parsed.scheme != "https":
        sc.tls = TLSInfo(error="alvo não usa HTTPS")
        return sc

    host = parsed.hostname or ""
    port = parsed.port or 443

    loop = asyncio.get_running_loop()

    # 1) Negociação default
    proto_default, cipher_default, cert_default = await loop.run_in_executor(
        None, _connect_with_protocol, host, port, ssl.TLSVersion.TLSv1_2
    )
    if proto_default is None:
        # tenta 1.3
        proto_default, cipher_default, cert_default = await loop.run_in_executor(
            None, _connect_with_protocol, host, port, ssl.TLSVersion.TLSv1_3
        )

    tls = TLSInfo()
    tls.protocol = proto_default
    if cipher_default:
        tls.cipher = cipher_default[0]
    if cert_default:
        s, i, e = _parse_cert(cert_default)
        tls.cert_subject, tls.cert_issuer, tls.cert_expires = s, i, e

    # 2) Para cada protocolo, enumera suítes e marca fracas
    weak_map: dict[str, list[str]] = {}
    for label, ver in PROTOCOLS_TO_TEST:
        ciphers = await loop.run_in_executor(
            None, _enumerate_supported_ciphers, host, port, ver
        )
        weak = sorted({c for c in ciphers if _is_weak(c)})
        weak_map[label] = weak
        # Findings explícitos
        if label in ("TLS 1.0", "TLS 1.1") and ciphers:
            sc.findings.append(
                Finding(
                    source="tls",
                    severity=Severity.HIGH,
                    title=f"Protocolo legado habilitado: {label}",
                    target=f"{host}:{port}",
                )
            )
        if weak:
            sc.findings.append(
                Finding(
                    source="tls",
                    severity=Severity.MEDIUM,
                    title=f"Cifras fracas suportadas em {label}",
                    target=f"{host}:{port}",
                    detail=", ".join(weak),
                )
            )

    tls.weak_ciphers_by_protocol = weak_map

    # Cert expirando em <30 dias
    if tls.cert_expires:
        try:
            d = datetime.strptime(tls.cert_expires, "%Y-%m-%d")
            days = (d - datetime.utcnow()).days
            if days < 0:
                sc.findings.append(Finding(
                    source="tls", severity=Severity.HIGH,
                    title="Certificado expirado", target=f"{host}:{port}",
                    detail=tls.cert_expires,
                ))
            elif days < 30:
                sc.findings.append(Finding(
                    source="tls", severity=Severity.LOW,
                    title=f"Certificado expira em {days} dias",
                    target=f"{host}:{port}", detail=tls.cert_expires,
                ))
        except ValueError:
            pass

    sc.tls = tls
    return sc
