# Production Readiness

> Last updated: **2026-09-06** · Applies to the current `main` branch (commits
> `60ff096`, `16d2aaf` + today's uncommitted backlog). Every item is marked
> **VERIFIED** (exercised on this machine) or **NOT VERIFIED** (configured/documented
> only — do not claim as tested).

## 1. Configuration Management

### Backend (`backend/app/config.py`)
All settings are environment-variable driven with safe defaults:

| Variable | Default | Description |
|---|---|---|
| `ENVIRONMENT` | `development` | `development` / `test` / `production` (production disables `/docs`, enables HSTS) |
| `LOG_LEVEL` | `INFO` | Root log level for the structured formatter |
| `DATABASE_URL` | `sqlite:///<backend>/aegis.db` | SQLite default; `postgresql+psycopg2://` supported |
| `OLLAMA_URL` | `http://localhost:11434` | Local Ollama only — no cloud inference |
| `AI_MODEL` | `` (empty) | Auto-discover first installed free model |
| `AI_TIMEOUT_SECONDS` | `120` | AI inference timeout |
| `AI_PROBE_TIMEOUT_SECONDS` | `3` | AI availability probe timeout |
| `MAX_UPLOAD_SIZE` | `104857600` (100 MiB) | Enforced while streaming (413) |
| `UPLOAD_DIR` | `<root>/uploads` | Stored under random UUID names |
| `REPORT_DIR` | `<root>/reports` | Generated PDF reports |
| `UPLOAD_RATE_LIMIT` | `30` | Uploads allowed per window per IP |
| `UPLOAD_RATE_WINDOW_SECONDS` | `60` | Rate-limit window |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated allowed origins |

**VERIFIED:** every setting is exercised by dev runs and/or tests.
**NOT VERIFIED:** a non-development `ENVIRONMENT`, and non-SQLite `DATABASE_URL`.

### Frontend (`frontend/.env`)
| Variable | Default | Description |
|---|---|---|
| `VITE_USE_BACKEND` | `true` | Live backend via `/api` proxy vs built-in mock fallback |
| `VITE_API_BASE_URL` | `/api` | API base path |

**VERIFIED:** both live values run in development.

## 2. Structured Logging & Request Correlation

Implemented in `backend/app/logging_config.py` + middleware in `app/main.py`:

- Every response carries `X-Request-ID` (client-supplied only if ≤ 64 chars of
  `[alnum . _ -]`, otherwise a fresh `uuid4().hex`).
- Access log: `request METHOD path -> status (ms)`; analysis logs include
  `investigation_id` / `analyzer`; all lines are `key=value` via `SafeFormatter`.
- Error responses (500 / HTTP errors / 422) include `request_id` for support
  correlation while preserving the `detail` payload shape.
- No secrets, query strings, storage paths or file contents are ever logged.

**VERIFIED:** unit tests, endpoint tests, and live curl checks (auto-generated ID,
honored client ID, 404/422 bodies, access-log capture). **NOT VERIFIED:** nothing
(fully covered).

## 3. Upload Rate Limiting

`backend/app/services/ratelimit.py`: thread-safe fixed-window `InMemoryRateLimiter`,
keyed by client IP on `POST /api/samples/upload` (default 30/min/IP), `429` with
`Retry-After` header, **fail-safe** (a limiter fault allows the request and logs).

- **VERIFIED:** limiter unit tests (window rollover, per-key isolation) + endpoint
  test (2 allowed → 429 with `Retry-After` and correlated `request_id`).
- **NOT VERIFIED / single-instance scope:** in-memory — a horizontally scaled
  deployment must replace it with a shared store (Redis etc.).

## 4. Database Compatibility

- SQLite default (zero-config) — **VERIFIED** by full test suite + live runs.
- PostgreSQL supported via `psycopg2-binary` in `backend/requirements.txt`;
  `pool_pre_ping=True` on the SQLAlchemy engine; compose mounts
  `database/init.sql`. **NOT VERIFIED live**: no Postgres server / `psql` on this
  machine — URL/driver path is configuration-tested only.
- Schema migration (Alembic) intentionally deferred. Dev note: a stale SQLite file
  predating new columns must be deleted to recreate the table (see README).

## 5. Docker & Deployment Scaffold

- `backend/Dockerfile`: `python:3.12-slim`, non-root `aegis` (UID 1001), prod-only
  deps. `frontend/Dockerfile` + `nginx.conf`: security headers, hidden-file
  blocking, `/api` proxied to `backend:8000`.
- `docker-compose.yml`: PostgreSQL (no host port binding, `pg_isready` healthcheck,
  volume `aegis-pgdata`), backend, frontend. Credentials come from a root `.env`
  (`POSTGRES_PASSWORD=${POSTGRES_PASSWORD:?...}` — **no hardcoded password**).
  Unused Redis service and stale `USE_REAL_LLM` flag removed.
- **NOT VERIFIED live:** Docker is not installed on this machine. Status —
  "Docker verification pending because Docker is unavailable on the development
  machine." The images/compose are hardened and lint-checked, but a real build/run
  has not been executed here.

## 6. Monitoring & Health

- `GET /api/health` returns operational status + component states
  (`api`, `static_analysis`, `ai_engine`); exposes **no** internals.
  **VERIFIED** live (`status: operational`, `ai_engine: unavailable` without Ollama).

## 7. Production Checklist — Final Verification

### Pre-deployment
- [x] `ENVIRONMENT=production` disables `/docs` + `/redoc` and enables HSTS — **VERIFIED in code; HSTS NOT observed live (dev env)**
- [x] `CORS_ORIGINS` restricted to specific origins (wildcard never enabled with credentials) — **VERIFIED**
- [x] Security headers on every response (`nosniff`, `DENY`, `Referrer-Policy`, `X-XSS-Protection`) — **VERIFIED live**
- [x] Upload rate limiting active (429 + `Retry-After`) — **VERIFIED by tests; default 30/min/IP**
- [x] No hardcoded credentials in compose; `.env` files documented — **VERIFIED (compose now `${POSTGRES_PASSWORD}`)**
- [x] Global + HTTP + validation error handlers return `request_id`, no internals — **VERIFIED live**
- [ ] Set a real Postgres password and run against PostgreSQL — **NOT VERIFIED (no Postgres available)**
- [ ] Build and run the Docker stack — **NOT VERIFIED (Docker unavailable)**
- [ ] Run with Ollama installed and a free model pulled — **NOT VERIFIED (Ollama unavailable; graceful fallback verified)**

### Post-deployment (as verified on this machine)
- [x] `GET /api/health` → `200 status=operational` — **VERIFIED live**
- [x] Upload → analysis pipeline completes (147-test suite) — **VERIFIED**
- [x] CORS + security headers present on live responses — **VERIFIED live**
- [x] `/docs` reachable in development only — **VERIFIED (200 in dev; disabled by `ENVIRONMENT=production`)**
- [x] ESLint (`--max-warnings 0`), `tsc --noEmit`, `vite build` all green — **VERIFIED**
- [x] Frontend live through the Vite `/api` proxy — **VERIFIED live**

## 8. Test Suite

**147 tests, all passing** (`cd backend && python -m pytest -q`):

- AI service, providers, prompts, validation (26)
- Dashboard endpoint structure and data (20)
- Detection engine and MITRE mapping (10)
- IOC extraction and validation (10)
- Scoring engine (9)
- Report generation and API (14)
- Health endpoint (5)
- Upload pipeline (7)
- Failure isolation (4)
- Adversarial security tests (16)
- API integration tests (7)
- Request-ID / structured logging (11)
- Rate limiting (8)

**Frontend:** `npm run lint` · `npm run build` (includes `tsc --noEmit`) — clean.

## 9. Known Environment Gaps

| Capability | Status |
|---|---|
| PostgreSQL | NOT VERIFIED (no server/`psql` on dev machine) |
| Docker / Docker Compose | NOT VERIFIED (Docker unavailable) |
| Ollama / AI inference | NOT VERIFIED (unavailable; deterministic fallback + clear UI state verified) |
| Horizontal scaling / distributed rate limiting | Out of scope (in-memory limiter, single instance) |