from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator
import re

from app.models.domain import DomainStatus


class DomainCreate(BaseModel):
    hostname: str = Field(..., min_length=3, max_length=255)
    display_name: Optional[str] = None
    allowed_subdomains: Optional[str] = None  # "*" or comma list
    notes: Optional[str] = None

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        v = v.lower().strip().rstrip(".")
        # Basic hostname validation - no scheme, no path
        if "://" in v or "/" in v or " " in v:
            raise ValueError("فقط نام دامنه (مثلاً example.com) وارد کنید")
        if not re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", v):
            raise ValueError("فرمت دامنه نامعتبر است")
        return v


class DomainOut(BaseModel):
    id: int
    hostname: str
    display_name: Optional[str]
    status: DomainStatus
    is_active: bool
    last_verified_at: Optional[datetime]
    created_at: datetime
    verification_token: str  # shown so user can set DNS/file

    model_config = {"from_attributes": True}


class DomainVerifyResponse(BaseModel):
    success: bool
    message: str
    domain: Optional[DomainOut] = None
