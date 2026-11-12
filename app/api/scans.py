"""Scan management and results."""

from typing import Annotated, List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_user
from app.db.base import get_db
from app.models.domain import Domain, DomainStatus
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanOut, ScanSummaryOut
from app.services.scanner.engine import ScanEngine

router = APIRouter(prefix="/scans", tags=["اسکن‌ها"])


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(
    data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> Scan:
    # Verify ownership and status
    result = await db.execute(
        select(Domain).where(Domain.id == data.domain_id, Domain.owner_id == current_user.id)
    )
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="دامنه یافت نشد")
    if domain.status != DomainStatus.VERIFIED:
        raise HTTPException(status_code=400, detail="ابتدا مالکیت دامنه را تأیید کنید")

    engine = ScanEngine(db)
    # For simplicity we run synchronously here (can take 10-60s).
    # In production move to Celery / BackgroundTasks with separate session.
    scan = await engine.start_scan(
        domain_id=domain.id,
        triggered_by=current_user.id,
        enabled_checks=data.enabled_checks,
    )
    # Reload with findings
    result = await db.execute(
        select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan.id)
    )
    return result.scalar_one()


@router.get("", response_model=List[ScanSummaryOut])
async def list_scans(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
    domain_id: int | None = None,
) -> List[ScanSummaryOut]:
    q = (
        select(Scan)
        .join(Domain)
        .where(Domain.owner_id == current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(50)
    )
    if domain_id:
        q = q.where(Scan.domain_id == domain_id)
    result = await db.execute(q)
    scans = result.scalars().all()
    out = []
    for s in scans:
        cnt_result = await db.execute(
            select(func.count()).select_from(Scan).where(Scan.id == s.id)  # simplified
        )
        # actual findings count
        from app.models.scan import Finding
        fcount = await db.execute(
            select(func.count()).select_from(Finding).where(Finding.scan_id == s.id)
        )
        out.append(
            ScanSummaryOut(
                id=s.id,
                domain_id=s.domain_id,
                status=s.status,
                overall_score=s.overall_score,
                summary=s.summary,
                started_at=s.started_at,
                finished_at=s.finished_at,
                findings_count=fcount.scalar() or 0,
            )
        )
    return out


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: int,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> Scan:
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.findings))
        .join(Domain)
        .where(Scan.id == scan_id, Domain.owner_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="اسکن یافت نشد")
    return scan
