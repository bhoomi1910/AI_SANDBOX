# Production Readiness

## Overview

This document covers the production readiness measures implemented for the Aegis Sandbox AI platform, including configuration management, reliability improvements, monitoring, and deployment preparation.

## Configuration Management

### Backend (`app/config.py`)
All settings are environment-variable driven with sensible defaults:

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./sandbox.db` | Database connection string |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama LLM endpoint |
| `AI_MODEL` | `llama3.1:latest` | Model to use for analysis |
| `AI_TIMEOUT_SECONDS` | `120` | Timeout for AI inference |
| `AI_PROBE_TIMEOUT_SECONDS` | `30` | Timeout for AI availability check |
| `MAX_UPLOAD_SIZE` | `104857600` (100 MB) | Maximum upload file size |
| `UPLOAD_DIR` | `./uploads` | Upload storage directory |
| `REPORT_DIR` | `./reports` | Generated reports directory |
| `CORS_ORIGINS` | `*` | Allowed CORS origins (comma-separated) |
| `ENVIRONMENT` | `development` | Environment mode (development/production) |

### Frontend (`frontend/.env`)
| Variable | Default | Description |
|---|---|---|
| `VITE_USE_BACKEND` | `true` | Use live backend vs mock data |

## Reliability Improvements

### Dashboard OOM Prevention
The dashboard endpoint (`routers/dashboard.py`) previously loaded all analysis results and MITRE data into memory. Fixed with:
- **SQL aggregation** for malware family statistics (replaces Python-side counting)
- **LIMIT 500** on `AnalysisResult` queries
- **LIMIT 500** on MITRE technique queries
- Prevents out-of-memory crashes on large datasets

### Health Endpoint (`/api/health`)
- Reports status of API, static analysis engine, and AI engine
- AI check uses `is_ai_available()` for quick reachability test
- No longer exposes database URL, file paths, or internal configuration
- Suitable for load balancer health checks

### Error Recovery
- Global exception handler in `main.py` returns sanitized error responses
- React `ErrorBoundary` catches frontend render errors with recovery UI
- AI service gracefully handles Ollama downtime with user-friendly messages

## Deployment

### Docker Compose
```yaml
# docker-compose.yml (development)
services:
  backend:
    build: ./backend
    ports: ["8000:8000"]
    environment:
      DATABASE_URL: postgresql://postgres:aegis@db:5432/aegis
      ENVIRONMENT: development
    depends_on: [db]

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: aegis
      POSTGRES_PASSWORD: aegis
    volumes: [pgdata:/var/lib/postgresql/data]

  frontend:
    build: ./frontend
    ports: ["3000:80"]

volumes:
  pgdata:
```

### Backend Dockerfile
- Based on `python:3.14-slim`
- Runs as non-root `aegis` user (UID 1001)
- Exposes port 8000
- Installs only production dependencies

### Frontend (nginx)
- Serves built static files
- Security headers configured
- Hidden file access blocked (`.env`, `.git`, `.htaccess`)
- API requests proxied to backend

## Monitoring

### Health Check
```bash
curl http://localhost:8000/api/health
```
Response includes:
- `status`: "healthy" or "degraded"
- `components.api`, `components.static_analysis`, `components.ai_engine`: "ok" or "unavailable"
- `ai_available`: boolean
- `timestamp`: ISO timestamp

### Structured Logging
- Python `logging` module used throughout backend
- Log level configurable via `LOG_LEVEL` environment variable
- Request IDs not yet implemented (future enhancement)

## Production Checklist

### Pre-deployment
- [ ] Set `ENVIRONMENT=production` to disable `/docs` and enable HSTS
- [ ] Configure `CORS_ORIGINS` to specific domain(s) instead of `*`
- [ ] Set secure database credentials (not `aegis`)
- [ ] Ensure Ollama is running and accessible at configured `OLLAMA_URL`
- [ ] Set appropriate `MAX_UPLOAD_SIZE` for your use case

### Post-deployment
- [ ] Verify health endpoint returns `"status": "healthy"`
- [ ] Test file upload and analysis pipeline end-to-end
- [ ] Verify CORS headers on responses
- [ ] Check that `/docs` returns 404 in production mode
- [ ] Monitor disk usage for `uploads/` and `reports/` directories

## Test Suite

**128 tests** covering:
- AI service, providers, prompts, validation (26 tests)
- Dashboard endpoint structure and data (20 tests)
- Detection engine and MITRE mapping (10 tests)
- IOC extraction and validation (10 tests)
- Scoring engine (9 tests)
- Report generation and API (14 tests)
- Health endpoint (5 tests)
- Upload pipeline (7 tests)
- Failure isolation (4 tests)
- Adversarial security tests (16 tests)
- API integration tests (7 tests)

Run: `cd backend && python -m pytest tests/ -v`
