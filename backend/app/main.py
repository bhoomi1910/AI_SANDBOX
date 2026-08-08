"""
Aegis Sandbox AI — FastAPI application entrypoint.

Run locally:
    uvicorn app.main:app --reload --port 8000

Interactive API docs:
    http://localhost:8000/docs
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routers import dashboard, investigations, upload

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="AI-Powered Interactive Malware Analysis & Threat Investigation Platform (MSc prototype).",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_PREFIX = "/api"
app.include_router(dashboard.router, prefix=API_PREFIX)
app.include_router(investigations.router, prefix=API_PREFIX)
app.include_router(upload.router, prefix=API_PREFIX)


@app.get("/api/health", tags=["system"])
def health():
    return {
        "status": "operational",
        "app": settings.app_name,
        "environment": settings.environment,
        "useRealLlm": settings.use_real_llm,
        "components": {
            "api": "operational",
            "sandbox_cluster": "operational",
            "ai_engine": "operational",
            "threat_intel_feeds": "operational",
        },
    }


@app.get("/", tags=["system"])
def root():
    return {
        "name": settings.app_name,
        "docs": "/docs",
        "health": "/api/health",
    }
