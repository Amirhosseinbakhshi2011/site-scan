"""Public exposure detection - only safe, common paths. Never downloads large/sensitive content."""

from typing import Any

from app.models.scan import ConfidenceLevel, RiskLevel
from app.services.scanner.base import BaseChecker, CheckResult
from app.core.logging import get_logger

logger = get_logger(__name__)

# Only well-known public indicators. No credential harvesting, no deep crawling.
SAFE_PATHS_TO_PROBE = [
    ("/robots.txt", "فایل robots.txt"),
    ("/sitemap.xml", "نقشه سایت"),
    ("/.well-known/security.txt", "security.txt"),
    ("/admin", "صفحه مدیریت احتمالی"),
    ("/administrator", "صفحه مدیریت احتمالی"),
    ("/login", "صفحه ورود"),
    ("/wp-login.php", "وردپرس login"),
    ("/wp-admin", "وردپرس admin"),
    ("/phpinfo.php", "صفحه phpinfo"),
    ("/server-status", "Apache server-status"),
    ("/server-info", "Apache server-info"),
    ("/.git/HEAD", "افشای مخزن Git"),
    ("/.env", "فایل محیطی"),
    ("/.env.example", "نمونه env"),
    ("/backup.sql", "بکاپ دیتابیس"),
    ("/backup.zip", "فایل بکاپ"),
    ("/config.php.bak", "بکاپ کانفیگ"),
    ("/web.config", "فایل web.config"),
    ("/crossdomain.xml", "crossdomain.xml"),
    ("/clientaccesspolicy.xml", "clientaccesspolicy"),
]


class PublicExposureChecker(BaseChecker):
    name = "public_exposure"
    description = "تشخیص صفحات مدیریت عمومی، directory listing و فایل‌های حساس احتمالی (فقط مسیرهای امن)"

    async def run(self, target: str, context: dict[str, Any]) -> list[CheckResult]:
        results: list[CheckResult] = []
        client = context["client"]
        base = f"https://{target}"

        for path, label in SAFE_PATHS_TO_PROBE:
            url = base + path
            try:
                # Prefer HEAD, fallback to GET with size limit
                try:
                    resp = await client.head(url, follow_redirects=False)
                    status = resp.status_code
                    # Some servers don't support HEAD well
                    if status in (405, 501):
                        resp = await client.get(url, follow_redirects=False)
                        status = resp.status_code
                except Exception:
                    resp = await client.get(url, follow_redirects=False)
                    status = resp.status_code

                if status == 200:
                    content_type = resp.headers.get("content-type", "")
                    # Very light body check only for known text indicators
                    body_preview = ""
                    try:
                        body_preview = (resp.text or "")[:300].lower()
                    except Exception:
                        pass

                    risk = RiskLevel.MEDIUM
                    title = f"منبع عمومی قابل دسترس: {label}"
                    desc = f"مسیر {path} با کد 200 پاسخ می‌دهد."
                    remediation = "دسترسی به این مسیر را محدود یا حذف کنید اگر لازم نیست."

                    if any(x in path for x in [".git", ".env", "backup", "phpinfo", "server-status", "config"]):
                        risk = RiskLevel.HIGH
                        title = f"افشای احتمالی فایل/مسیر حساس: {label}"
                        remediation = "فوراً دسترسی عمومی به این مسیر را مسدود کنید."

                    if "index of" in body_preview or "directory listing" in body_preview:
                        risk = RiskLevel.MEDIUM
                        title = "Directory Listing فعال است"
                        desc = f"مسیر {path} به نظر می‌رسد directory listing را نمایش می‌دهد."

                    results.append(
                        CheckResult(
                            check_name=self.name,
                            title=title,
                            description=desc,
                            risk_level=risk,
                            confidence=ConfidenceLevel.MEDIUM if risk != RiskLevel.HIGH else ConfidenceLevel.HIGH,
                            affected_url=url,
                            http_status=status,
                            evidence=f"status={status}, content-type={content_type}",
                            remediation=remediation,
                            cwe_id="CWE-200" if risk == RiskLevel.HIGH else None,
                        )
                    )
                elif status in (301, 302, 307, 308):
                    loc = resp.headers.get("location", "")
                    # Only note interesting redirects to admin-like
                    if any(k in path for k in ["admin", "login", "wp-"]):
                        results.append(
                            CheckResult(
                                check_name=self.name,
                                title=f"ریدایرکت از مسیر {label}",
                                description=f"مسیر {path} به {loc[:100]} ریدایرکت می‌شود.",
                                risk_level=RiskLevel.INFORMATIONAL,
                                confidence=ConfidenceLevel.MEDIUM,
                                affected_url=url,
                                http_status=status,
                                evidence=f"Location: {loc[:200]}",
                            )
                        )
            except Exception as e:
                logger.debug("probe_failed", path=path, error=str(e))
                continue

        if not any(r.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM) for r in results):
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="مسیرهای حساس رایج در دسترس عموم نیستند",
                    description="بررسی مسیرهای متداول افشا نتیجه‌ای نشان نداد (این تضمین کامل نیست).",
                    risk_level=RiskLevel.INFORMATIONAL,
                    confidence=ConfidenceLevel.MEDIUM,
                    affected_url=base,
                )
            )

        return results
