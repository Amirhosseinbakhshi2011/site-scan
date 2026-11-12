"""DNS security related checks (SPF, DMARC, basic records)."""

from typing import Any

import dns.resolver
import dns.exception

from app.models.scan import ConfidenceLevel, RiskLevel
from app.services.scanner.base import BaseChecker, CheckResult
from app.core.logging import get_logger

logger = get_logger(__name__)


class DNSSecurityChecker(BaseChecker):
    name = "dns_security"
    description = "تحلیل رکوردهای DNS، SPF، DMARC و پیکربندی‌های مرتبط"

    async def run(self, target: str, context: dict[str, Any]) -> list[CheckResult]:
        results: list[CheckResult] = []
        host = target.lower().strip().rstrip(".")

        # A / AAAA
        try:
            answers = dns.resolver.resolve(host, "A")
            a_records = [r.to_text() for r in answers]
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="رکوردهای A",
                    description=f"آدرس‌های IPv4: {', '.join(a_records)}",
                    risk_level=RiskLevel.INFORMATIONAL,
                    confidence=ConfidenceLevel.CONFIRMED,
                    evidence="; ".join(a_records),
                )
            )
        except Exception as e:
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="رکورد A یافت نشد",
                    description=str(e),
                    risk_level=RiskLevel.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                )
            )

        # SPF
        spf_found = False
        try:
            answers = dns.resolver.resolve(host, "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if txt.lower().startswith("v=spf1"):
                    spf_found = True
                    results.append(
                        CheckResult(
                            check_name=self.name,
                            title="رکورد SPF موجود است",
                            description=f"SPF: {txt[:200]}",
                            risk_level=RiskLevel.INFORMATIONAL,
                            confidence=ConfidenceLevel.CONFIRMED,
                            evidence=txt,
                        )
                    )
                    if "+all" in txt.lower().replace(" ", ""):
                        results.append(
                            CheckResult(
                                check_name=self.name,
                                title="SPF با +all (خیلی باز)",
                                description="سیاست SPF اجازه ارسال از هر منبعی را می‌دهد که خطرناک است.",
                                risk_level=RiskLevel.HIGH,
                                confidence=ConfidenceLevel.HIGH,
                                evidence=txt,
                                remediation="از ~all یا -all استفاده کنید و مکانیزم‌های مجاز را محدود کنید.",
                            )
                        )
                    break
        except Exception:
            pass

        if not spf_found:
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="رکورد SPF وجود ندارد",
                    description="عدم وجود SPF امکان جعل ایمیل از دامنه را افزایش می‌دهد.",
                    risk_level=RiskLevel.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    remediation="یک رکورد TXT با v=spf1 مناسب اضافه کنید.",
                    cwe_id="CWE-290",
                )
            )

        # DMARC
        dmarc_found = False
        try:
            answers = dns.resolver.resolve(f"_dmarc.{host}", "TXT")
            for r in answers:
                txt = r.to_text().strip('"')
                if "v=dmarc1" in txt.lower():
                    dmarc_found = True
                    results.append(
                        CheckResult(
                            check_name=self.name,
                            title="رکورد DMARC موجود است",
                            description=f"DMARC: {txt[:250]}",
                            risk_level=RiskLevel.INFORMATIONAL,
                            confidence=ConfidenceLevel.CONFIRMED,
                            evidence=txt,
                        )
                    )
                    if "p=none" in txt.lower().replace(" ", ""):
                        results.append(
                            CheckResult(
                                check_name=self.name,
                                title="DMARC با سیاست none",
                                description="سیاست فعلی فقط نظارت است و ایمیلی را رد نمی‌کند.",
                                risk_level=RiskLevel.LOW,
                                confidence=ConfidenceLevel.HIGH,
                                evidence=txt,
                                remediation="پس از تست، سیاست را به quarantine یا reject ارتقا دهید.",
                            )
                        )
                    break
        except Exception:
            pass

        if not dmarc_found:
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="رکورد DMARC وجود ندارد",
                    description="بدون DMARC، محافظت در برابر جعل دامنه ایمیل ناقص است.",
                    risk_level=RiskLevel.MEDIUM,
                    confidence=ConfidenceLevel.HIGH,
                    remediation="رکورد TXT برای _dmarc.example.com با v=DMARC1 اضافه کنید.",
                )
            )

        # MX presence (informational)
        try:
            answers = dns.resolver.resolve(host, "MX")
            mx = [r.to_text() for r in answers]
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="رکوردهای MX",
                    description=f"سرورهای ایمیل: {', '.join(mx[:5])}",
                    risk_level=RiskLevel.INFORMATIONAL,
                    confidence=ConfidenceLevel.CONFIRMED,
                    evidence="; ".join(mx),
                )
            )
        except Exception:
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="رکورد MX یافت نشد",
                    description="دامنه ممکن است برای ایمیل پیکربندی نشده باشد.",
                    risk_level=RiskLevel.INFORMATIONAL,
                    confidence=ConfidenceLevel.MEDIUM,
                )
            )

        return results
