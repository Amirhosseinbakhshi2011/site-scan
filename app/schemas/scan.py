from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel

from app.models.scan import ConfidenceLevel, RiskLevel, ScanStatus


class FindingOut(BaseModel):
    id: int
    check_name: str
    title: str
    description: str
    risk_level: RiskLevel
    confidence: ConfidenceLevel
    evidence: Optional[str]
    affected_url: Optional[str]
    http_status: Optional[int]
    remediation: Optional[str]
    cwe_id: Optional[str]
    is_false_positive: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanCreate(BaseModel):
    domain_id: int
    enabled_checks: Optional[List[str]] = None


class ScanOut(BaseModel):
    id: int
    domain_id: int
    status: ScanStatus
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    progress: float
    overall_score: Optional[float]
    summary: Optional[str]
    error_message: Optional[str]
    created_at: datetime
    findings: List[FindingOut] = []

    model_config = {"from_attributes": True}


class ScanSummaryOut(BaseModel):
    id: int
    domain_id: int
    status: ScanStatus
    overall_score: Optional[float]
    summary: Optional[str]
    started_at: Optional[datetime]
    finished_at: Optional[datetime]
    findings_count: int = 0

    model_config = {"from_attributes": True}
