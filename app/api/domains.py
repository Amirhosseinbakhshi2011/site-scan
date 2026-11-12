"""Domain management endpoints."""

from typing import Annotated, List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.base import get_db
from app.models.domain import Domain, DomainStatus
from app.models.user import User
from app.schemas.domain import DomainCreate, DomainOut, DomainVerifyResponse
from app.services.domain_verification import (
    generate_verification_token,
    mark_domain_verified,
    verify_domain_ownership,
)

router = APIRouter(prefix="/domains", tags=["دامنه‌ها"])


@router.get("", response_model=List[DomainOut])
async def list_domains(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> List[Domain]:
    q = select(Domain).where(Domain.owner_id == current_user.id).order_by(Domain.created_at.desc())
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("", response_model=DomainOut, status_code=201)
async def add_domain(
    data: DomainCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> Domain:
    existing = await db.execute(select(Domain).where(Domain.hostname == data.hostname))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="این دامنه قبلاً ثبت شده است")
    domain = Domain(
        hostname=data.hostname,
        display_name=data.display_name or data.hostname,
        verification_token=generate_verification_token(),
        allowed_subdomains=data.allowed_subdomains,
        notes=data.notes,
        owner_id=current_user.id,
        status=DomainStatus.PENDING_VERIFICATION,
    )
    db.add(domain)
    await db.commit()
    await db.refresh(domain)
    return domain


@router.get("/{domain_id}", response_model=DomainOut)
async def get_domain(
    domain_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> Domain:
    domain = await _get_owned_domain(db, domain_id, current_user)
    return domain


@router.post("/{domain_id}/verify", response_model=DomainVerifyResponse)
async def verify_domain(
    domain_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> DomainVerifyResponse:
    domain = await _get_owned_domain(db, domain_id, current_user)
    if domain.status == DomainStatus.VERIFIED:
        return DomainVerifyResponse(success=True, message="قبلاً تأیید شده است", domain=domain)
    ok, msg = await verify_domain_ownership(domain)
    if ok:
        await mark_domain_verified(domain)
        await db.commit()
        await db.refresh(domain)
        return DomainVerifyResponse(success=True, message=msg, domain=domain)
    return DomainVerifyResponse(success=False, message=msg, domain=domain)


@router.delete("/{domain_id}", status_code=204)
async def delete_domain(
    domain_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> None:
    domain = await _get_owned_domain(db, domain_id, current_user)
    await db.delete(domain)
    await db.commit()


async def _get_owned_domain(db: AsyncSession, domain_id: int, user: User) -> Domain:
    result = await db.execute(
        select(Domain).where(Domain.id == domain_id, Domain.owner_id == user.id)
    )
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="دامنه یافت نشد")
    return domain
