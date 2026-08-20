"""
AI-Powered Intelligent Sandbox — FastAPI application entrypoint.

Run locally:
    uvicorn app.main:app --reload --port 8000

Interactive API docs:
    http://localhost:8000/docs
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.database import init_db
from app.routers import dashboard, investigations, upload

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s (env=%s)", settings.app_name, settings.environment)
    init_db()
    yield
    logger.info("Shutting down %s", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="AI-Powered Intelligent Sandbox for Secure File Analysis (B.E. Major Project).",
    lifespan=lifespan,
    docs_url="/docs" if settings.environment == "development" else None,
    redoc_url="/redoc" if settings.environment == "development" else None,
)

# --- CORS ---------------------------------------------------------------
origins = settings.cors_origin_list
if "*" in origins:
    logger.warning("CORS configured with wildcard origin — restrict in production")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials="*" not in origins,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)

# --- Security headers ---------------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    if settings.environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# --- Global error handler ------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "code": "INTERNAL_ERROR"},
    )


API_PREFIX = "/api"
app.include_router(dashboard.router, prefix=API_PREFIX)
app.include_router(investigations.router, prefix=API_PREFIX)
app.include_router(upload.router, prefix=API_PREFIX)


@app.get("/api/health", tags=["system"])
def health():
    """Health check — exposes no internal infrastructure details."""
    from app.services.ai.providers import is_ai_available
    return {
        "status": "operational",
        "app": settings.app_name,
        "environment": settings.environment,
        "components": {
            "api": "operational",
            "static_analysis": "operational",
            "ai_engine": "available" if is_ai_available() else "unavailable",
            "threat_intel_feeds": "pending",
        },
    }


@app.get("/", tags=["system"])
def root():
    return {
        "name": settings.app_name,
        "docs": "/docs" if settings.environment == "development" else "disabled",
        "health": "/api/health",
    }
