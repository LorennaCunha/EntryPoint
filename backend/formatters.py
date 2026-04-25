"""
Formatadores de saída.

Convertem o modelo interno (ScanResult) em texto plano copy/paste friendly,
no formato exato pedido pelo usuário. Nunca emitem JSON.
"""
from __future__ import annotations
from .models import (
    ScanResult,
    ScannerResult,
    Severity,
    Finding,
)


# ---------------- helpers ----------------

def _section(title: str, body: str) -> str:
    body = body.rstrip()
    if not body:
        body = "(sem dados)"
    return f"[{title}]\n{body}"


# ---------------- por scanner ----------------

def format_headers(sc: ScannerResult) -> str:
    if sc.error:
        return f"[HEADERS] erro: {sc.error}"
    lines: list[str] = []
    for h in sc.headers:
        if h.present:
            val = h.value or ""
            lines.append(f"[HEADER] {h.name}: {val}")
        else:
            lines.append(f"[HEADER] {h.name}: AUSENTE")
    return "\n".join(lines) if lines else "[HEADERS] (sem dados)"


def format_tls(sc: ScannerResult) -> str:
    tls = sc.tls
    if sc.error or tls is None:
        return f"[TLS] erro: {sc.error or 'indisponível'}"
    if tls.error:
        return f"[TLS] erro: {tls.error}"

    lines = [
        f"[TLS] Versão negociada: {tls.protocol or 'desconhecida'}",
        f"[TLS] Cifra negociada: {tls.cipher or 'desconhecida'}",
    ]
    if tls.cert_subject:
        lines.append(f"[TLS] Certificado subject: {tls.cert_subject}")
    if tls.cert_issuer:
        lines.append(f"[TLS] Certificado issuer: {tls.cert_issuer}")
    if tls.cert_expires:
        lines.append(f"[TLS] Certificado expira em: {tls.cert_expires}")

    weak_any = any(v for v in tls.weak_ciphers_by_protocol.values())
    if not weak_any:
        lines.append("O protocolo não utiliza cifras fracas")
    else:
        for proto, ciphers in tls.weak_ciphers_by_protocol.items():
            if ciphers:
                joined = ", ".join(ciphers)
                lines.append(f"Cifras fracas {proto}: {{{joined}}}")
    return "\n".join(lines)


def format_sitemap(sc: ScannerResult) -> str:
    if sc.error:
        return f"[SITEMAP] erro: {sc.error}"
    if not sc.sitemap:
        return "[SITEMAP] (nenhum recurso encontrado)"
    parts = [f"{e.path} ({e.status})" for e in sc.sitemap]
    return "[SITEMAP]\n" + " ".join(parts)


def format_params(sc: ScannerResult) -> str:
    if sc.error:
        return f"[PARAM DISCOVERY] erro: {sc.error}"
    if not sc.params:
        return "[PARAM DISCOVERY] (nenhum parâmetro encontrado)"
    lines = ["[PARAM DISCOVERY]"]
    for p in sc.params:
        lines.append(f"{p.endpoint} → {', '.join(p.params)}")
    return "\n".join(lines)


def format_findings(sc: ScannerResult, prefix: str) -> str:
    if sc.error:
        return f"[{prefix}] erro: {sc.error}"
    if not sc.findings:
        return f"[{prefix}] (nenhum achado)"
    lines = []
    for f in sc.findings:
        sev = f.severity.value
        target = f" → {f.target}" if f.target else ""
        lines.append(f"[{prefix}][{sev}] {f.title}{target}")
    return "\n".join(lines)


# ---------------- agregadores ----------------

def _vuln_section(result: ScanResult) -> str:
    """Junta achados de scanners de vulnerabilidade (nuclei, nikto, custom)."""
    rows: list[str] = []
    for sc in result.scanners:
        if sc.name in ("nuclei", "nikto", "custom"):
            for f in sc.findings:
                sev = f.severity.value
                tag = sc.name.upper()
                target = f" → {f.target}" if f.target else ""
                rows.append(f"[{tag}][{sev}] {f.title}{target}")
    if not rows:
        return "[VULNERABILITIES] (nenhum achado)"
    return "[VULNERABILITIES]\n" + "\n".join(rows)


def render_terminal(result: ScanResult) -> str:
    """
    Saída final no formato:
      ===== SCAN RESULTS =====
      [HEADERS] ...
      [TLS] ...
      [SITEMAP] ...
      [PARAM DISCOVERY] ...
      [VULNERABILITIES] ...
      ========================
      Score: 72/100  Status: Atenção
    """
    by_name = {sc.name: sc for sc in result.scanners}
    blocks: list[str] = []
    blocks.append("===== SCAN RESULTS =====")
    blocks.append(f"Target: {result.url}    Tipo: {result.scan_type.value}")

    if "headers" in by_name:
        blocks.append(format_headers(by_name["headers"]))
    if "tls" in by_name:
        blocks.append(format_tls(by_name["tls"]))
    if "ffuf" in by_name:
        blocks.append(format_sitemap(by_name["ffuf"]))
    if "arjun" in by_name:
        blocks.append(format_params(by_name["arjun"]))

    blocks.append(_vuln_section(result))

    blocks.append("========================")
    blocks.append(f"Score: {result.score}/100   Status: {result.score_status}")
    return "\n".join(blocks)


def calculate_score(result: ScanResult) -> tuple[int, str]:
    """Score começa em 100 e cai com base na severidade dos achados."""
    from .models import SEVERITY_WEIGHT

    penalty = 0
    for sc in result.scanners:
        for f in sc.findings:
            penalty += SEVERITY_WEIGHT[f.severity]
    score = max(0, 100 - penalty)

    if score >= 85:
        status = "OK"
    elif score >= 60:
        status = "Atenção"
    elif score >= 30:
        status = "Crítico"
    else:
        status = "Risco extremo"
    return score, status
