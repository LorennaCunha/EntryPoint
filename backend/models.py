"""
Modelos internos unificados.
Todos os scanners retornam Findings/ScanResult, mas a UI/CLI mostra apenas
texto formatado — nunca JSON cru.
"""
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanType(str, Enum):
    QUICK = "quick"
    FULL = "full"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"


SEVERITY_WEIGHT = {
    Severity.INFO: 1,
    Severity.LOW: 3,
    Severity.MEDIUM: 7,
    Severity.HIGH: 14,
    Severity.CRITICAL: 25,
}


class Finding(BaseModel):
    """Achado normalizado a partir de qualquer scanner."""
    source: str                      # 'headers', 'tls', 'ffuf', 'arjun', 'nuclei', 'nikto', 'custom'
    severity: Severity = Severity.INFO
    title: str
    target: Optional[str] = None     # ex: '/admin'
    detail: Optional[str] = None
    evidence: Optional[dict[str, Any]] = None  # uso interno


class HeaderFinding(BaseModel):
    name: str
    present: bool
    value: Optional[str] = None


class SitemapEntry(BaseModel):
    path: str
    status: int


class ParamDiscovery(BaseModel):
    endpoint: str
    params: list[str] = Field(default_factory=list)


class TLSInfo(BaseModel):
    protocol: Optional[str] = None
    cipher: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_expires: Optional[str] = None
    weak_ciphers_by_protocol: dict[str, list[str]] = Field(default_factory=dict)
    error: Optional[str] = None


class ScannerResult(BaseModel):
    name: str
    ok: bool = True
    duration_ms: int = 0
    error: Optional[str] = None
    findings: list[Finding] = Field(default_factory=list)
    # Estruturas auxiliares (uso interno):
    headers: list[HeaderFinding] = Field(default_factory=list)
    sitemap: list[SitemapEntry] = Field(default_factory=list)
    params: list[ParamDiscovery] = Field(default_factory=list)
    tls: Optional[TLSInfo] = None


class ScanRequest(BaseModel):
    url: str
    scan_type: ScanType = ScanType.QUICK
    wordlist: Optional[str] = None   # nome de arquivo já presente em /wordlists


class ScanResult(BaseModel):
    scan_id: str
    url: str
    scan_type: ScanType
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=datetime.utcnow)
    finished_at: Optional[datetime] = None
    scanners: list[ScannerResult] = Field(default_factory=list)
    score: int = 100
    score_status: str = "OK"
    terminal_output: str = ""
    error: Optional[str] = None
