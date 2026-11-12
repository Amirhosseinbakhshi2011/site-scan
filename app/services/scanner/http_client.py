"""Safe, rate-limited HTTP client for assessments."""

import asyncio
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class SafeHTTPClient:
    """HTTP client with safety limits: timeout, size, rate, no redirects by default for some checks."""

    def __init__(self) -> None:
        settings = get_settings()
        self.timeout = settings.scanner_request_timeout
        self.max_size = settings.scanner_max_response_size_kb * 1024
        self.user_agent = settings.scanner_user_agent
        self._semaphore = asyncio.Semaphore(settings.scanner_max_concurrent_requests)
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "SafeHTTPClient":
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=False,  # controlled per request
            headers={"User-Agent": self.user_agent},
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            verify=True,  # always verify TLS by default
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.aclose()

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(multiplier=0.5, min=0.5, max=3))
    async def get(
        self,
        url: str,
        *,
        follow_redirects: bool = False,
        allow_large: bool = False,
        headers: Optional[dict[str, str]] = None,
    ) -> httpx.Response:
        async with self._semaphore:
            assert self._client is not None
            req_headers = headers or {}
            response = await self._client.get(
                url,
                follow_redirects=follow_redirects,
                headers=req_headers,
            )
            # Soft size limit
            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > self.max_size and not allow_large:
                logger.warning("response_too_large", url=url, size=content_length)
            return response

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        async with self._semaphore:
            assert self._client is not None
            return await self._client.head(url, **kwargs)

    def build_url(self, host: str, path: str = "/", scheme: str = "https") -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{scheme}://{host}{path}"

    @staticmethod
    def is_same_origin(base: str, candidate: str) -> bool:
        try:
            b = urlparse(base)
            c = urlparse(candidate)
            return b.netloc == c.netloc and b.scheme in ("http", "https")
        except Exception:
            return False
