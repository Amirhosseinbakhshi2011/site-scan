"""Aegis Sentinel AI - Main application entrypoint."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select

from app.api import auth, domains, scans
from app.core.config import get_settings
from app.core.logging import setup_logging, get_logger
from app.core.security import get_password_hash
from app.db.base import init_db, AsyncSessionLocal
from app.models.user import User

setup_logging()
logger = get_logger(__name__)
settings = get_settings()

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "dashboard" / "templates"
STATIC_DIR = BASE_DIR / "dashboard" / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting_aegis_sentinel")
    Path("data").mkdir(exist_ok=True)
    await init_db()
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(User).where(User.email == settings.first_superuser_email)
        )
        user = result.scalar_one_or_none()
        if not user:
            user = User(
                email=settings.first_superuser_email,
                hashed_password=get_password_hash(settings.first_superuser_password),
                full_name="Administrator",
                is_superuser=True,
                is_active=True,
            )
            db.add(user)
            await db.commit()
            logger.info("superuser_created", email=settings.first_superuser_email)
    yield
    logger.info("shutting_down")


app = FastAPI(
    title=settings.app_name,
    description="سیستم ارزیابی امنیتی و پایش آسیب‌پذیری وب‌سایت (فقط ارزیابی مجاز و غیرتخریبی)",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix=settings.api_v1_prefix)
app.include_router(domains.router, prefix=settings.api_v1_prefix)
app.include_router(scans.router, prefix=settings.api_v1_prefix)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR)) if TEMPLATES_DIR.exists() else None


@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    if templates:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "app_name": settings.app_name,
            },
        )
    return HTMLResponse(
        "<h1>Aegis Sentinel AI</h1><p>Dashboard templates not found. API at /api/docs</p>"
    )


@app.get("/health")
async def health():
    return {"status": "ok", "service": settings.app_name}