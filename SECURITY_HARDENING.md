# Security Hardening

## Overview

This document covers the security measures implemented across the Aegis Sandbox AI platform during the security hardening phase.

## Backend Security

### Input Validation & Sanitization
- **Filename sanitization**: Null bytes stripped, path traversal sequences (`../`, `..\\`) removed, control characters filtered, filenames truncated to 120 characters (`services/storage.py`)
- **AI prompt injection defense**: `_sanitize_for_prompt()` in `services/ai/prompt.py` strips control characters and newlines from filenames before embedding in AI prompts
- **PATCH endpoint limits**: `closureNotes` max 2000 chars, `assignedTo` max 64, `malwareFamily` max 64, `classification` max 128 (`routers/investigations.py`)
- **Upload size enforcement**: Configurable via `MAX_UPLOAD_SIZE` (default 100 MB), enforced during streaming (`services/storage.py`)

### HTTP Security Headers
Middleware in `main.py` adds on every response:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `X-XSS-Protection: 0`
- `Strict-Transport-Security` (production only)

### Error Handling
- **Global exception handler** in `main.py` catches unhandled exceptions and returns sanitized JSON (`{"error": "Internal server error", "detail": "..."}`) — no stack traces leaked
- **AI service errors** (`services/ai/service.py`) return generic messages without raw exception details
- **CORS hardened**: Wildcard origins (`*`) disable `allow_credentials`; allowed methods restricted to `GET, POST, PATCH, DELETE`

### API Security
- **`/docs` and `/redoc` disabled** when `environment != "development"` (production)
- **Health endpoint** (`/api/health`) no longer exposes `database_url` or internal config
- **AI availability check**: `is_ai_available()` in `services/ai/providers.py` performs quick reachability test without exposing connection details

### Case Closure
- `InvestigationUpdate` Pydantic model validates all PATCH fields
- Status transitions enforced: only valid state changes accepted
- Closure fields tracked: `resolution`, `closure_notes`, `closed_by`, `closed_at`

## Frontend Security

### Error Boundary
- `ErrorBoundary.tsx` wraps the entire React app in `main.tsx`
- Catches render errors and displays a recovery UI instead of white screen
- Includes error details and refresh button

### Threat Intelligence Hardening
- Domain/IP/hash inputs filtered, searched, and sorted
- Copy-to-clipboard button for IOC values
- Empty state handling for missing data

## Infrastructure Security

### Docker
- **Backend Dockerfile**: Runs as non-root `aegis` user (UID 1001)
- **nginx.conf**: Security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy`, `Permissions-Policy`), hidden file blocking (`.env`, `.git`, `.htaccess`)

### Environment Configuration
- `.env.example` files created for both backend and frontend with documented variables
- `.dockerignore` expanded to exclude tests, docs, IDE files from Docker builds
- Sensitive values (database passwords, API keys) never committed

### Known Risks
- `docker-compose.yml` has hardcoded `POSTGRES_PASSWORD: aegis` — acceptable for dev only; production should use secrets management
- SQLite used for development; production should use PostgreSQL

## Test Coverage

16 adversarial security tests in `tests/test_security.py`:
- Empty/malformed file uploads (3 tests)
- Filename edge cases: null bytes, path traversal, long names, unicode, dots-only (5 tests)
- API security: health endpoint info leakage, invalid IDs, invalid verdicts/severities, headers, input limits (7 tests)
- Duplicate SHA handling (1 test)
- Corrupt analysis result handling (1 test)

**Total test suite: 128 tests — all passing.**
