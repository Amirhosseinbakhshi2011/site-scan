"""SSL/TLS security checks using standard library + httpx."""

import ssl
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from app.models.scan import ConfidenceLevel, RiskLevel
from app.services.scanner.base import BaseChecker, CheckResult
from app.core.logging import get_logger

logger = get_logger(__name__)


class SSLTLSChecker(BaseChecker):
    name = "ssl_tls"
    description = "Certificate validity, expiration, HTTPS availability, redirects, protocol"

    async def run(self, target: str, context: dict[str, Any]) -> list[CheckResult]:
        results: list[CheckResult] = []
        client = context["client"]
        host = target.lower().strip().rstrip(".")

        # 1. HTTPS availability
        https_url = f"https://{host}/"
        http_url = f"http://{host}/"

        https_ok = False
        try:
            resp = await client.get(https_url, follow_redirects=True)
            https_ok = resp.status_code < 500
            if https_ok:
                results.append(
                    CheckResult(
                        check_name=self.name,
                        title="HTTPS در دسترس است",
                        description="وب‌سایت از طریق HTTPS قابل دسترسی است.",
                        risk_level=RiskLevel.INFORMATIONAL,
                        confidence=ConfidenceLevel.CONFIRMED,
                        affected_url=https_url,
                        http_status=resp.status_code,
                    )
                )
        except Exception as e:
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="HTTPS در دسترس نیست",
                    description=f"اتصال HTTPS به دامنه برقرار نشد: {type(e).__name__}",
                    risk_level=RiskLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    affected_url=https_url,
                    remediation="پیکربندی صحیح گواهی SSL/TLS و باز بودن پورت 443 را بررسی کنید.",
                    cwe_id="CWE-319",
                )
            )
            return results  # no point continuing deep TLS if HTTPS fails

        # 2. Certificate details via ssl module
        try:
            cert_info = await self._get_cert_info(host)
            if cert_info:
                results.extend(self._analyze_cert(cert_info, host))
        except Exception as e:
            logger.warning("cert_analysis_failed", host=host, error=str(e))
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="خطا در تحلیل گواهی",
                    description=f"امکان استخراج اطلاعات گواهی وجود نداشت: {e}",
                    risk_level=RiskLevel.MEDIUM,
                    confidence=ConfidenceLevel.MEDIUM,
                    affected_url=https_url,
                )
            )

        # 3. HTTP -> HTTPS redirect
        try:
            resp = await client.get(http_url, follow_redirects=False)
            location = resp.headers.get("location", "")
            if resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
                results.append(
                    CheckResult(
                        check_name=self.name,
                        title="ریدایرکت HTTP به HTTPS فعال است",
                        description="درخواست‌های HTTP به درستی به HTTPS هدایت می‌شوند.",
                        risk_level=RiskLevel.INFORMATIONAL,
                        confidence=ConfidenceLevel.CONFIRMED,
                        affected_url=http_url,
                        http_status=resp.status_code,
                        evidence=f"Location: {location}",
                    )
                )
            elif resp.status_code < 400:
                results.append(
                    CheckResult(
                        check_name=self.name,
                        title="ریدایرکت HTTP به HTTPS وجود ندارد",
                        description="سایت از طریق HTTP نیز در دسترس است و ریدایرکت اجباری به HTTPS ندارد.",
                        risk_level=RiskLevel.MEDIUM,
                        confidence=ConfidenceLevel.HIGH,
                        affected_url=http_url,
                        http_status=resp.status_code,
                        remediation="یک ریدایرکت دائمی (301) از HTTP به HTTPS تنظیم کنید و HSTS را فعال نمایید.",
                        cwe_id="CWE-319",
                    )
                )
        except Exception:
            pass  # HTTP may be closed, which is fine

        return results

    async def _get_cert_info(self, host: str, port: int = 443) -> dict[str, Any] | None:
        """Retrieve certificate info using ssl module (blocking, run in thread)."""
        import asyncio

        def _sync_get() -> dict[str, Any] | None:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return {
                        "cert": cert,
                        "cipher": cipher,
                        "tls_version": version,
                        "peercert_binary": ssock.getpeercert(binary_form=True),
                    }

        return await asyncio.to_thread(_sync_get)

    def _analyze_cert(self, info: dict[str, Any], host: str) -> list[CheckResult]:
        results: list[CheckResult] = []
        cert = info.get("cert") or {}
        tls_version = info.get("tls_version")

        # Expiration
        not_after = cert.get("notAfter")
        if not_after:
            try:
                # format: 'Jun 15 12:00:00 2025 GMT'
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                now = datetime.now(timezone.utc)
                days_left = (exp - now).days
                if days_left < 0:
                    results.append(
                        CheckResult(
                            check_name=self.name,
                            title="گواهی SSL منقضی شده است",
                            description=f"گواهی در تاریخ {not_after} منقضی شده است.",
                            risk_level=RiskLevel.CRITICAL,
                            confidence=ConfidenceLevel.CONFIRMED,
                            evidence=f"notAfter={not_after}",
                            remediation="فوراً گواهی جدید صادر و نصب کنید.",
                            cwe_id="CWE-295",
                        )
                    )
                elif days_left < 14:
                    results.append(
                        CheckResult(
                            check_name=self.name,
                            title="گواهی SSL به زودی منقضی می‌شود",
                            description=f"کمتر از {days_left} روز تا انقضای گواهی باقی مانده است.",
                            risk_level=RiskLevel.HIGH,
                            confidence=ConfidenceLevel.CONFIRMED,
                            evidence=f"days_left={days_left}, notAfter={not_after}",
                            remediation="گواهی را قبل از انقضا تمدید کنید.",
                        )
                    )
                elif days_left < 30:
                    results.append(
                        CheckResult(
                            check_name=self.name,
                            title="گواهی SSL نزدیک به انقضا",
                            description=f"{days_left} روز تا انقضای گواهی باقی مانده است.",
                            risk_level=RiskLevel.MEDIUM,
                            confidence=ConfidenceLevel.CONFIRMED,
                            evidence=f"days_left={days_left}",
                            remediation="برنامه‌ریزی برای تمدید گواهی انجام دهید.",
                        )
                    )
                else:
                    results.append(
                        CheckResult(
                            check_name=self.name,
                            title="گواهی SSL معتبر است",
                            description=f"گواهی تا {not_after} معتبر است ({days_left} روز باقی‌مانده).",
                            risk_level=RiskLevel.INFORMATIONAL,
                            confidence=ConfidenceLevel.CONFIRMED,
                            evidence=f"notAfter={not_after}",
                        )
                    )
            except Exception as e:
                logger.debug("parse_notAfter_failed", error=str(e))

        # Hostname match (basic)
        subject = cert.get("subject", ())
        san = cert.get("subjectAltName", ())
        names = []
        for part in subject:
            for key, val in part:
                if key == "commonName":
                    names.append(val)
        for typ, val in san:
            if typ == "DNS":
                names.append(val)

        host_matched = any(
            n == host or (n.startswith("*.") and host.endswith(n[1:])) for n in names
        )
        if names and not host_matched:
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="عدم تطابق نام دامنه با گواهی",
                    description=f"نام دامنه {host} با نام‌های موجود در گواهی همخوانی ندارد.",
                    risk_level=RiskLevel.HIGH,
                    confidence=ConfidenceLevel.HIGH,
                    evidence=f"cert_names={names}",
                    remediation="گواهی با SAN صحیح برای دامنه صادر کنید.",
                    cwe_id="CWE-297",
                )
            )

        # TLS version
        if tls_version:
            if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                results.append(
                    CheckResult(
                        check_name=self.name,
                        title=f"نسخه ناامن TLS: {tls_version}",
                        description="نسخه‌های قدیمی TLS آسیب‌پذیر هستند و باید غیرفعال شوند.",
                        risk_level=RiskLevel.HIGH,
                        confidence=ConfidenceLevel.CONFIRMED,
                        evidence=f"negotiated={tls_version}",
                        remediation="فقط TLS 1.2 و TLS 1.3 را فعال نگه دارید.",
                        cwe_id="CWE-326",
                    )
                )
            else:
                results.append(
                    CheckResult(
                        check_name=self.name,
                        title=f"نسخه TLS مناسب: {tls_version}",
                        description="نسخه پروتکل TLS مذاکره‌شده امن است.",
                        risk_level=RiskLevel.INFORMATIONAL,
                        confidence=ConfidenceLevel.CONFIRMED,
                        evidence=f"negotiated={tls_version}",
                    )
                )

        return results
