"""HTTP Security Headers checks."""

from typing import Any

from app.models.scan import ConfidenceLevel, RiskLevel
from app.services.scanner.base import BaseChecker, CheckResult


SECURITY_HEADERS = {
    "content-security-policy": {
        "title": "Content-Security-Policy",
        "missing_risk": RiskLevel.MEDIUM,
        "desc": "سیاست امنیت محتوا (CSP) از حملات XSS و injection جلوگیری می‌کند.",
        "remediation": "هدر Content-Security-Policy را با سیاست مناسب تنظیم کنید.",
        "cwe": "CWE-1021",
    },
    "strict-transport-security": {
        "title": "Strict-Transport-Security (HSTS)",
        "missing_risk": RiskLevel.MEDIUM,
        "desc": "HSTS مرورگر را مجبور به استفاده از HTTPS می‌کند.",
        "remediation": "هدر Strict-Transport-Security با max-age مناسب (حداقل 31536000) اضافه کنید.",
        "cwe": "CWE-319",
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options",
        "missing_risk": RiskLevel.LOW,
        "desc": "از MIME-sniffing جلوگیری می‌کند.",
        "remediation": "مقدار nosniff را تنظیم کنید: X-Content-Type-Options: nosniff",
        "cwe": "CWE-693",
    },
    "x-frame-options": {
        "title": "X-Frame-Options",
        "missing_risk": RiskLevel.MEDIUM,
        "desc": "از clickjacking جلوگیری می‌کند (یا از frame-ancestors در CSP استفاده کنید).",
        "remediation": "X-Frame-Options: DENY یا SAMEORIGIN تنظیم کنید.",
        "cwe": "CWE-1021",
    },
    "referrer-policy": {
        "title": "Referrer-Policy",
        "missing_risk": RiskLevel.LOW,
        "desc": "کنترل می‌کند چه اطلاعاتی در Referer ارسال شود.",
        "remediation": "Referrer-Policy: strict-origin-when-cross-origin یا no-referrer توصیه می‌شود.",
        "cwe": None,
    },
    "permissions-policy": {
        "title": "Permissions-Policy",
        "missing_risk": RiskLevel.LOW,
        "desc": "دسترسی به ویژگی‌های مرورگر (دوربین، موقعیت و ...) را محدود می‌کند.",
        "remediation": "Permissions-Policy را با سیاست مناسب پیکربندی کنید.",
        "cwe": None,
    },
}


class SecurityHeadersChecker(BaseChecker):
    name = "security_headers"
    description = "بررسی هدرهای امنیتی HTTP"

    async def run(self, target: str, context: dict[str, Any]) -> list[CheckResult]:
        results: list[CheckResult] = []
        client = context["client"]
        url = f"https://{target}/"

        try:
            resp = await client.get(url, follow_redirects=True)
        except Exception as e:
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="عدم امکان دریافت هدرها",
                    description=f"درخواست به {url} ناموفق بود: {e}",
                    risk_level=RiskLevel.INFORMATIONAL,
                    confidence=ConfidenceLevel.HIGH,
                    affected_url=url,
                )
            )
            return results

        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header_key, meta in SECURITY_HEADERS.items():
            if header_key in headers:
                value = headers[header_key]
                results.append(
                    CheckResult(
                        check_name=self.name,
                        title=f"هدر {meta['title']} موجود است",
                        description=f"{meta['desc']} مقدار فعلی: {value[:200]}",
                        risk_level=RiskLevel.INFORMATIONAL,
                        confidence=ConfidenceLevel.CONFIRMED,
                        affected_url=url,
                        http_status=resp.status_code,
                        evidence=f"{header_key}: {value[:300]}",
                    )
                )
                # Light validation for HSTS
                if header_key == "strict-transport-security":
                    if "max-age=0" in value.replace(" ", "").lower():
                        results.append(
                            CheckResult(
                                check_name=self.name,
                                title="HSTS با max-age=0",
                                description="HSTS عملاً غیرفعال است.",
                                risk_level=RiskLevel.MEDIUM,
                                confidence=ConfidenceLevel.HIGH,
                                affected_url=url,
                                evidence=value,
                                remediation="max-age را به مقدار بزرگ (مثلاً 31536000) تنظیم کنید.",
                            )
                        )
            else:
                results.append(
                    CheckResult(
                        check_name=self.name,
                        title=f"هدر {meta['title']} وجود ندارد",
                        description=meta["desc"],
                        risk_level=meta["missing_risk"],
                        confidence=ConfidenceLevel.CONFIRMED,
                        affected_url=url,
                        http_status=resp.status_code,
                        remediation=meta["remediation"],
                        cwe_id=meta.get("cwe"),
                    )
                )

        # Server header disclosure
        server = headers.get("server")
        if server:
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="افشای اطلاعات سرور",
                    description=f"هدر Server مقدار '{server}' را افشا می‌کند که می‌تواند به مهاجم کمک کند.",
                    risk_level=RiskLevel.LOW,
                    confidence=ConfidenceLevel.CONFIRMED,
                    affected_url=url,
                    evidence=f"Server: {server}",
                    remediation="هدر Server را حذف یا به مقدار عمومی تغییر دهید.",
                    cwe_id="CWE-200",
                )
            )

        x_powered = headers.get("x-powered-by")
        if x_powered:
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="افشای فناوری (X-Powered-By)",
                    description=f"هدر X-Powered-By مقدار '{x_powered}' را افشا می‌کند.",
                    risk_level=RiskLevel.LOW,
                    confidence=ConfidenceLevel.CONFIRMED,
                    affected_url=url,
                    evidence=f"X-Powered-By: {x_powered}",
                    remediation="این هدر را حذف کنید.",
                    cwe_id="CWE-200",
                )
            )

        return results
