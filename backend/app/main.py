"""
AI-Powered Intelligent Sandbox — FastAPI application entrypoint.

Run locally:
    uvicorn app.main:app --reload --port 8000

Interactive API docs:
    http://localhost:8000/docs
"""
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings
from app.database import init_db
from app.logging_config import generate_request_id, request_id_var, setup_logging
from app.routers import dashboard, investigations, upload

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging(settings.log_level)
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


# --- Request ID + structured access logging -------------------------------
@app.middleware("http")
async def request_id_and_access_logging(request: Request, call_next):
    """Assign a request ID, return it in the response, and log the request.

    A client-supplied ``X-Request-ID`` is honored only if it is short and
    made of safe characters; otherwise a UUID is generated. The ID is stored
    in a context variable so all loggers inside the request emit it.
    """
    request_id = generate_request_id(dict(request.headers))
    token = request_id_var.set(request_id)
    started = time.perf_counter()
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "request %s %s -> %s (%sms)",
            request.method,
            request.url.path,
            response.status_code,
            int((time.perf_counter() - started) * 1000),
        )
        return response
    except Exception:
        logger.exception(
            "request %s %s failed (request_id=%s)", request.method, request.url.path, request_id
        )
        raise
    finally:
        request_id_var.reset(token)


# --- Global error handler ------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    request_id = request_id_var.get("unknown")
    logger.exception(
        "Unhandled exception on %s %s", request.method, request.url.path,
        extra={"request_id": request_id},
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "code": "INTERNAL_ERROR",
            "request_id": request_id,
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Every HTTP error carries the request ID for correlation by support."""
    content = dict(exc.detail) if isinstance(exc.detail, dict) else {"detail": exc.detail}
    content["request_id"] = request_id_var.get("unknown")
    return JSONResponse(status_code=exc.status_code, content=content, headers=exc.headers)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    content = {
        "detail": jsonable_encoder(exc.errors()),
        "request_id": request_id_var.get("unknown"),
    }
    return JSONResponse(status_code=422, content=content)


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
