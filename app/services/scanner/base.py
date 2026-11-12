"""Base classes and result structures for security checks."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from app.models.scan import ConfidenceLevel, RiskLevel


@dataclass
class CheckResult:
    """Result of a single security check."""

    check_name: str
    title: str
    description: str
    risk_level: RiskLevel
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    evidence: Optional[str] = None
    affected_url: Optional[str] = None
    http_status: Optional[int] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    references: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_finding_dict(self) -> dict[str, Any]:
        return {
            "check_name": self.check_name,
            "title": self.title,
            "description": self.description,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "affected_url": self.affected_url,
            "http_status": self.http_status,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "references": self.references,
        }


class BaseChecker:
    """Abstract base for all security checkers."""

    name: str = "base"
    description: str = ""

    async def run(self, target: str, context: dict[str, Any]) -> list[CheckResult]:
        """Execute the check against the target hostname/URL.

        Args:
            target: Primary hostname (e.g. example.com)
            context: Shared context (client, settings, allowed paths, etc.)

        Returns:
            List of CheckResult (empty if nothing found or check skipped).
        """
        raise NotImplementedError
