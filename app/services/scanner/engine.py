"""Main security assessment engine."""

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.domain import Domain, DomainStatus
from app.models.scan import Finding, RiskLevel, Scan, ScanStatus, ConfidenceLevel
from app.services.scanner.http_client import SafeHTTPClient
from app.services.checks.ssl_tls import SSLTLSChecker
from app.services.checks.headers import SecurityHeadersChecker
from app.services.checks.cookies import CookieSecurityChecker
from app.services.checks.exposure import PublicExposureChecker
from app.services.checks.dns_sec import DNSSecurityChecker
from app.services.checks.webapp import WebAppSecurityChecker
from app.services.scanner.base import CheckResult

logger = get_logger(__name__)

ALL_CHECKERS = [
    SSLTLSChecker(),
    SecurityHeadersChecker(),
    CookieSecurityChecker(),
    PublicExposureChecker(),
    DNSSecurityChecker(),
    WebAppSecurityChecker(),
]


class ScanEngine:
    """Orchestrates non-destructive security assessments for a verified domain."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.settings = get_settings()

    async def start_scan(
        self,
        domain_id: int,
        triggered_by: Optional[int] = None,
        enabled_checks: Optional[list[str]] = None,
        progress_callback: Optional[Callable[[float, str], Any]] = None,
    ) -> Scan:
        """Create and run a scan job."""
        result = await self.db.execute(
            select(Domain).where(Domain.id == domain_id)
        )
        domain = result.scalar_one_or_none()
        if not domain:
            raise ValueError("دامنه یافت نشد")
        if domain.status != DomainStatus.VERIFIED:
            raise ValueError("دامنه هنوز تأیید مالکیت نشده است")

        scan = Scan(
            domain_id=domain.id,
            status=ScanStatus.PENDING,
            triggered_by=triggered_by,
            checks_enabled=json.dumps(enabled_checks) if enabled_checks else None,
        )
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)

        # Run in background-ish (same process for simplicity; use Celery in prod)
        try:
            await self._execute_scan(scan, domain, enabled_checks, progress_callback)
        except Exception as e:
            logger.exception("scan_failed", scan_id=scan.id, error=str(e))
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)[:1000]
            scan.finished_at = datetime.now(timezone.utc)
            await self.db.commit()

        return scan

    async def _execute_scan(
        self,
        scan: Scan,
        domain: Domain,
        enabled_checks: Optional[list[str]],
        progress_callback: Optional[Callable],
    ) -> None:
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        scan.progress = 0.0
        await self.db.commit()

        checkers = ALL_CHECKERS
        if enabled_checks:
            checkers = [c for c in ALL_CHECKERS if c.name in enabled_checks]

        total = len(checkers) or 1
        all_results: list[CheckResult] = []

        async with SafeHTTPClient() as client:
            context = {
                "client": client,
                "settings": self.settings,
                "domain": domain,
            }
            for idx, checker in enumerate(checkers):
                try:
                    logger.info("running_check", check=checker.name, domain=domain.hostname)
                    if progress_callback:
                        await progress_callback((idx / total) * 100, checker.name)
                    results = await checker.run(domain.hostname, context)
                    all_results.extend(results)
                except Exception as e:
                    logger.warning("check_error", check=checker.name, error=str(e))
                    all_results.append(
                        CheckResult(
                            check_name=checker.name,
                            title=f"خطا در اجرای بررسی {checker.name}",
                            description=str(e)[:500],
                            risk_level=RiskLevel.INFORMATIONAL,
                            confidence=ConfidenceLevel.LOW,
                        )
                    )
                scan.progress = ((idx + 1) / total) * 100
                await self.db.commit()

        # Persist findings
        for r in all_results:
            finding = Finding(
                scan_id=scan.id,
                check_name=r.check_name,
                title=r.title,
                description=r.description,
                risk_level=r.risk_level,
                confidence=r.confidence,
                evidence=r.evidence,
                affected_url=r.affected_url,
                http_status=r.http_status,
                remediation=r.remediation,
                cwe_id=r.cwe_id,
                references=json.dumps(r.references) if r.references else None,
            )
            self.db.add(finding)

        # Score calculation (simple weighted)
        score = self._calculate_score(all_results)
        scan.overall_score = score
        scan.status = ScanStatus.COMPLETED
        scan.finished_at = datetime.now(timezone.utc)
        scan.progress = 100.0
        scan.summary = self._build_summary(all_results, score)
        await self.db.commit()

        if progress_callback:
            await progress_callback(100.0, "completed")

        logger.info("scan_completed", scan_id=scan.id, score=score, findings=len(all_results))

    def _calculate_score(self, results: list[CheckResult]) -> float:
        """0-100 score. Higher is better."""
        weights = {
            RiskLevel.CRITICAL: 25,
            RiskLevel.HIGH: 15,
            RiskLevel.MEDIUM: 7,
            RiskLevel.LOW: 2,
            RiskLevel.INFORMATIONAL: 0,
        }
        penalty = 0.0
        for r in results:
            if r.risk_level != RiskLevel.INFORMATIONAL:
                conf_mult = {
                    ConfidenceLevel.CONFIRMED: 1.0,
                    ConfidenceLevel.HIGH: 0.85,
                    ConfidenceLevel.MEDIUM: 0.6,
                    ConfidenceLevel.LOW: 0.3,
                    ConfidenceLevel.SUSPECTED: 0.2,
                }.get(r.confidence, 0.5)
                penalty += weights.get(r.risk_level, 0) * conf_mult
        score = max(0.0, 100.0 - penalty)
        return round(score, 1)

    def _build_summary(self, results: list[CheckResult], score: float) -> str:
        counts = {level: 0 for level in RiskLevel}
        for r in results:
            counts[r.risk_level] += 1
        return (
            f"امتیاز کلی: {score}/100 | "
            f"بحرانی: {counts[RiskLevel.CRITICAL]} | "
            f"بالا: {counts[RiskLevel.HIGH]} | "
            f"متوسط: {counts[RiskLevel.MEDIUM]} | "
            f"پایین: {counts[RiskLevel.LOW]} | "
            f"اطلاعاتی: {counts[RiskLevel.INFORMATIONAL]}"
        )
