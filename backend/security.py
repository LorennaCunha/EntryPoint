"""
Sanitização de URL e bloqueio de alvos internos.

Regras:
  - Apenas http/https
  - Resolve DNS e bloqueia se cair em IP privado/loopback/link-local
  - Bloqueia hostnames óbvios (localhost, *.local, *.internal, metadata.google, 169.254.*)
"""
from __future__ import annotations
import ipaddress
import socket
from urllib.parse import urlparse, urlunparse


BLOCKED_HOSTNAMES = {
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata",
}

BLOCKED_HOSTNAME_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".lan",
)


class URLValidationError(ValueError):
    pass


def normalize_url(raw: str) -> str:
    """Aceita 'example.com' ou 'http://example.com/path?x=1'.
    Retorna URL canônica com scheme."""
    raw = (raw or "").strip()
    if not raw:
        raise URLValidationError("URL vazia")

    if "://" not in raw:
        raw = "http://" + raw

    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise URLValidationError(f"Scheme não suportado: {parsed.scheme!r}")

    if not parsed.hostname:
        raise URLValidationError("URL sem hostname")

    # remove credenciais embutidas, mantém porta/path/query
    netloc = parsed.hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse((parsed.scheme, netloc, parsed.path or "/", "", parsed.query, ""))


def _is_blocked_hostname(host: str) -> bool:
    h = host.lower()
    if h in BLOCKED_HOSTNAMES:
        return True
    return any(h.endswith(suf) for suf in BLOCKED_HOSTNAME_SUFFIXES)


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_target(url: str) -> str:
    """
    Normaliza, faz resolução DNS e impede ataques contra alvos internos.
    Retorna a URL canônica caso seja segura.
    """
    canonical = normalize_url(url)
    host = urlparse(canonical).hostname or ""

    if _is_blocked_hostname(host):
        raise URLValidationError(f"Alvo bloqueado: {host!r}")

    # se for IP literal, valida diretamente
    try:
        ipaddress.ip_address(host)
        if _is_blocked_ip(host):
            raise URLValidationError(f"IP interno/reservado bloqueado: {host}")
        return canonical
    except ValueError:
        pass

    # resolução DNS — bloqueia se *qualquer* registro apontar para rede interna
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise URLValidationError(f"Falha ao resolver host {host!r}: {e}") from e

    for fam, _t, _p, _c, sa in infos:
        ip = sa[0]
        if _is_blocked_ip(ip):
            raise URLValidationError(
                f"Host {host!r} resolve para IP interno {ip} — bloqueado por segurança"
            )

    return canonical


def safe_filename(name: str) -> str:
    """Sanitiza nome de wordlist para impedir path traversal."""
    name = (name or "").strip().replace("\\", "/").split("/")[-1]
    keep = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    cleaned = "".join(c for c in name if c in keep)
    if not cleaned or cleaned in (".", ".."):
        raise URLValidationError("Nome de wordlist inválido")
    return cleaned
