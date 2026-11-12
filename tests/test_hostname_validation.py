"""Unit tests for domain hostname validation and scoring helpers."""

import pytest
from pydantic import ValidationError

from app.schemas.domain import DomainCreate
from app.services.scanner.engine import ScanEngine
from app.services.scanner.base import CheckResult
from app.models.scan import RiskLevel, ConfidenceLevel


def test_valid_hostname():
    d = DomainCreate(hostname="example.com")
    assert d.hostname == "example.com"


def test_hostname_rejects_url():
    with pytest.raises(ValidationError):
        DomainCreate(hostname="https://example.com")


def test_hostname_rejects_path():
    with pytest.raises(ValidationError):
        DomainCreate(hostname="example.com/admin")


def test_score_calculation():
    engine = ScanEngine(db=None)  # type: ignore
    results = [
        CheckResult(
            check_name="t",
            title="c",
            description="d",
            risk_level=RiskLevel.CRITICAL,
            confidence=ConfidenceLevel.CONFIRMED,
        ),
        CheckResult(
            check_name="t",
            title="i",
            description="d",
            risk_level=RiskLevel.INFORMATIONAL,
            confidence=ConfidenceLevel.CONFIRMED,
        ),
    ]
    score = engine._calculate_score(results)
    assert score == 75.0  # 100 - 25
