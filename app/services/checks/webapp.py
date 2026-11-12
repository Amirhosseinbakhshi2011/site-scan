"""Passive / harmless web application security indicators."""

from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from app.models.scan import ConfidenceLevel, RiskLevel
from app.services.scanner.base import BaseChecker, CheckResult
from app.core.logging import get_logger

logger = get_logger(__name__)


class WebAppSecurityChecker(BaseChecker):
    name = "webapp_security"
    description = "شاخص‌های امنیتی اپلیکیشن وب (CORS، ریدایرکت ناامن، افشای اطلاعات) - فقط تست‌های بی‌ضرر"

    async def run(self, target: str, context: dict[str, Any]) -> list[CheckResult]:
        results: list[CheckResult] = []
        client = context["client"]
        base = f"https://{target}/"

        # 1. Basic response analysis
        try:
            resp = await client.get(base, follow_redirects=True)
            results.extend(self._analyze_response(resp, base))
        except Exception as e:
            logger.debug("webapp_base_failed", error=str(e))

        # 2. CORS reflection test (harmless Origin)
        try:
            results.extend(await self._check_cors(client, base))
        except Exception as e:
            logger.debug("cors_check_failed", error=str(e))

        # 3. Open redirect indicator (harmless probe on common params)
        try:
            results.extend(await self._check_open_redirect_indicators(client, target))
        except Exception as e:
            logger.debug("redirect_check_failed", error=str(e))

        return results

    def _analyze_response(self, resp, url: str) -> list[CheckResult]:
        results = []
        # Information disclosure in body (very light)
        try:
            text = (resp.text or "")[:5000].lower()
            if "stack trace" in text or "traceback (most recent call last)" in text:
                results.append(
                    CheckResult(
                        check_name=self.name,
                        title="احتمال افشای stack trace",
                        description="متن پاسخ حاوی نشانه‌هایی از stack trace است که می‌تواند اطلاعات حساس افشا کند.",
                        risk_level=RiskLevel.MEDIUM,
                        confidence=ConfidenceLevel.MEDIUM,
                        affected_url=url,
                        http_status=resp.status_code,
                        remediation="صفحات خطای تولید را غیرفعال و پیام‌های عمومی نمایش دهید.",
                        cwe_id="CWE-209",
                    )
                )
            if "sql syntax" in text or "mysql_fetch" in text or "ora-" in text:
                results.append(
                    CheckResult(
                        check_name=self.name,
                        title="احتمال افشای خطای دیتابیس",
                        description="نشانه‌هایی از پیام خطای پایگاه داده در پاسخ مشاهده شد.",
                        risk_level=RiskLevel.MEDIUM,
                        confidence=ConfidenceLevel.LOW,
                        affected_url=url,
                        remediation="پیام‌های خطای دقیق دیتابیس را در محیط تولید پنهان کنید.",
                        cwe_id="CWE-209",
                    )
                )
        except Exception:
            pass
        return results

    async def _check_cors(self, client, url: str) -> list[CheckResult]:
        results = []
        evil_origin = "https://evil-aegis-test.example"
        try:
            resp = await client.get(
                url,
                headers={"Origin": evil_origin},
                follow_redirects=True,
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                results.append(
                    CheckResult(
                        check_name=self.name,
                        title="CORS با Access-Control-Allow-Origin: *",
                        description="هر دامنه‌ای می‌تواند به منابع دسترسی داشته باشد.",
                        risk_level=RiskLevel.MEDIUM if acac.lower() != "true" else RiskLevel.HIGH,
                        confidence=ConfidenceLevel.HIGH,
                        affected_url=url,
                        evidence=f"ACAO={acao}, ACAC={acac}",
                        remediation="Origin را به دامنه‌های مورد اعتماد محدود کنید. هرگز * را با credentials ترکیب نکنید.",
                        cwe_id="CWE-942",
                    )
                )
            elif acao == evil_origin:
                results.append(
                    CheckResult(
                        check_name=self.name,
                        title="CORS Origin reflection (خطرناک)",
                        description="سرور Origin ارسال‌شده را منعکس می‌کند که می‌تواند منجر به CORS ناامن شود.",
                        risk_level=RiskLevel.HIGH,
                        confidence=ConfidenceLevel.HIGH,
                        affected_url=url,
                        evidence=f"ACAO={acao}",
                        remediation="لیست سفید Originهای مجاز را پیاده‌سازی کنید و از reflection خودداری کنید.",
                        cwe_id="CWE-942",
                    )
                )
            elif acao:
                results.append(
                    CheckResult(
                        check_name=self.name,
                        title="CORS پیکربندی شده",
                        description=f"Access-Control-Allow-Origin: {acao}",
                        risk_level=RiskLevel.INFORMATIONAL,
                        confidence=ConfidenceLevel.CONFIRMED,
                        affected_url=url,
                        evidence=f"ACAO={acao}, ACAC={acac}",
                    )
                )
        except Exception:
            pass
        return results

    async def _check_open_redirect_indicators(self, client, host: str) -> list[CheckResult]:
        """Only probe common parameter names with a safe external URL; do not follow."""
        results = []
        test_target = "https://example.com/aegis-redirect-test"
        common_params = ["url", "redirect", "next", "return", "returnTo", "goto", "dest", "destination", "redir"]

        # We only check a couple of likely entry points to stay light
        candidates = [
            f"https://{host}/",
            f"https://{host}/login",
            f"https://{host}/logout",
        ]

        for base in candidates:
            for param in common_params[:3]:  # limit
                try:
                    parsed = urlparse(base)
                    qs = parse_qs(parsed.query)
                    qs[param] = [test_target]
                    new_query = urlencode(qs, doseq=True)
                    test_url = urlunparse(
                        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
                    )
                    resp = await client.get(test_url, follow_redirects=False)
                    loc = resp.headers.get("location", "")
                    if resp.status_code in (301, 302, 303, 307, 308) and test_target in loc:
                        results.append(
                            CheckResult(
                                check_name=self.name,
                                title="شاخص ریدایرکت باز (Open Redirect)",
                                description=f"پارامتر {param} به نظر می‌رسد مقصد ریدایرکت را کنترل می‌کند.",
                                risk_level=RiskLevel.MEDIUM,
                                confidence=ConfidenceLevel.MEDIUM,
                                affected_url=test_url,
                                http_status=resp.status_code,
                                evidence=f"Location: {loc[:200]}",
                                remediation="مقاصد ریدایرکت را به لیست سفید دامنه‌های داخلی محدود کنید.",
                                cwe_id="CWE-601",
                            )
                        )
                        return results  # one finding is enough
                except Exception:
                    continue
        return results
