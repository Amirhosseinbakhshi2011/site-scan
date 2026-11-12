"""Cookie security attributes checks."""

from typing import Any
from http.cookies import SimpleCookie

from app.models.scan import ConfidenceLevel, RiskLevel
from app.services.scanner.base import BaseChecker, CheckResult


class CookieSecurityChecker(BaseChecker):
    name = "cookie_security"
    description = "بررسی ویژگی‌های امنیتی کوکی‌ها (Secure, HttpOnly, SameSite)"

    async def run(self, target: str, context: dict[str, Any]) -> list[CheckResult]:
        results: list[CheckResult] = []
        client = context["client"]
        url = f"https://{target}/"

        try:
            resp = await client.get(url, follow_redirects=True)
        except Exception:
            return results

        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
        if not set_cookie_headers:
            # httpx may expose as multiple or single
            sc = resp.headers.get("set-cookie")
            if sc:
                set_cookie_headers = [sc]

        if not set_cookie_headers:
            results.append(
                CheckResult(
                    check_name=self.name,
                    title="هیچ کوکی Set-Cookie مشاهده نشد",
                    description="در پاسخ صفحه اصلی هیچ کوکی‌ای تنظیم نشده است (ممکن است در مسیرهای دیگر باشد).",
                    risk_level=RiskLevel.INFORMATIONAL,
                    confidence=ConfidenceLevel.MEDIUM,
                    affected_url=url,
                )
            )
            return results

        for raw in set_cookie_headers:
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except Exception:
                continue

            for key, morsel in cookie.items():
                name = key
                secure = morsel["secure"] is True or "secure" in raw.lower().split(";")
                httponly = morsel["httponly"] is True or "httponly" in raw.lower().split(";")
                samesite = morsel.get("samesite") or ""
                if not samesite:
                    # parse manually
                    for part in raw.lower().split(";"):
                        if "samesite=" in part:
                            samesite = part.split("=", 1)[-1].strip()

                issues = []
                if not secure:
                    issues.append("فاقد پرچم Secure")
                if not httponly:
                    issues.append("فاقد پرچم HttpOnly")
                if not samesite or samesite.lower() not in ("strict", "lax"):
                    issues.append(f"SameSite نامناسب یا غایب (فعلی: {samesite or 'none'})")

                if issues:
                    risk = RiskLevel.MEDIUM if ("Secure" in str(issues) or "HttpOnly" in str(issues)) else RiskLevel.LOW
                    results.append(
                        CheckResult(
                            check_name=self.name,
                            title=f"مشکل امنیتی در کوکی «{name}»",
                            description="؛ ".join(issues),
                            risk_level=risk,
                            confidence=ConfidenceLevel.HIGH,
                            affected_url=url,
                            evidence=raw[:400],
                            remediation=(
                                "برای کوکی‌های حساس (نشست) حتماً Secure، HttpOnly و SameSite=Lax یا Strict تنظیم کنید."
                            ),
                            cwe_id="CWE-614",
                        )
                    )
                else:
                    results.append(
                        CheckResult(
                            check_name=self.name,
                            title=f"کوکی «{name}» پیکربندی امن دارد",
                            description="Secure، HttpOnly و SameSite مناسب تنظیم شده‌اند.",
                            risk_level=RiskLevel.INFORMATIONAL,
                            confidence=ConfidenceLevel.HIGH,
                            affected_url=url,
                            evidence=raw[:300],
                        )
                    )

        return results
