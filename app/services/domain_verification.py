"""Domain ownership verification via DNS TXT or well-known file."""

import secrets
from datetime import datetime, timezone
from typing import Optional

import dns.resolver
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.domain import Domain, DomainStatus

logger = get_logger(__name__)


def generate_verification_token() -> str:
    settings = get_settings()
    return settings.domain_verification_token_prefix + secrets.token_urlsafe(24)


async def verify_domain_ownership(domain: Domain) -> tuple[bool, str]:
    """Try DNS TXT first, then well-known file. Returns (success, message)."""
    settings = get_settings()
    host = domain.hostname.lower().strip().rstrip(".")
    token = domain.verification_token

    # Method 1: DNS TXT
    try:
        answers = dns.resolver.resolve(host, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if token in txt:
                return True, "تأیید از طریق رکورد DNS TXT موفق بود."
    except Exception as e:
        logger.debug("dns_txt_check_failed", host=host, error=str(e))

    # Method 2: well-known file
    paths = [
        settings.domain_verification_file_path,
        f"/{token}.txt",
        f"/.well-known/{token}.txt",
    ]
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        for path in paths:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and token in (resp.text or ""):
                        return True, f"تأیید از طریق فایل {path} موفق بود."
                except Exception:
                    continue

    return False, (
        "تأیید مالکیت ناموفق. یکی از روش‌های زیر را انجام دهید:\n"
        f"1. یک رکورد TXT برای {host} با مقدار دقیق زیر ایجاد کنید:\n"
        f"   {token}\n"
        f"2. یا فایلی در مسیر {settings.domain_verification_file_path} "
        f"با محتوای {token} قرار دهید."
    )


async def mark_domain_verified(domain: Domain) -> None:
    domain.status = DomainStatus.VERIFIED
    domain.last_verified_at = datetime.now(timezone.utc)
