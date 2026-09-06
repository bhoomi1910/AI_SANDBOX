# AI-Powered Intelligent Sandbox — Project Summary (for ChatGPT review)

> **Purpose of this file:** a self-contained summary of the project and everything
> completed up to **2026-09-06**, so anyone (e.g. ChatGPT) can explain the project.
> Status of the code: local branch `main` is pushed to GitHub and in sync.

---

## 1. What the project is

A **B.E. Major Project**: a safe **static malware-analysis platform** with an
AI-assisted interpretation layer. An analyst uploads a suspicious file and gets a
scored, evidence-backed threat analysis, MITRE ATT&CK mappings, an optional local-AI
explanation, and a downloadable PDF report.

The most important design rule: **the sample is NEVER executed.** Analysis is
deterministic and fully local. The AI (a local Ollama model) can only *explain* the
deterministic findings — it can never invent detections, IOCs, scores or techniques.

---

## 2. Tech stack

| Layer | Technology |
|---|---|
| Frontend | React 18 + TypeScript, Vite 5, TailwindCSS, TanStack Query, Recharts, Framer Motion |
| Backend | Python 3.11+ (tested on 3.14), FastAPI, SQLAlchemy 2, SQLite (PostgreSQL-ready via `psycopg2`) |
| Reporting | ReportLab (server-generated PDF) |
| AI (optional) | Local Ollama only — free models auto-discovered via `/api/tags`, no cloud/paid inference |
| Quality gates | ESLint flat config (`typescript-eslint` + `react-hooks` + `react-refresh`, zero warnings), `tsc`, `vite build` |

---

## 3. Architecture

```
frontend/  React SPA (Dashboard, Queue, Upload, analysis deep-dive pages)
backend/   FastAPI service
  app/
    main.py                 entrypoint, CORS, security headers, request-ID/access-log middleware,
                            global + HTTP + validation error handlers
    config.py               env-driven settings (pydantic-settings)
    database.py             SQLAlchemy engine/session, pool_pre_ping (Postgres-ready), init_db
    models.py               Investigation + AnalysisResult models
    logging_config.py       structured "key=value" logging + per-request request IDs
    routers/                dashboard · investigations · upload
    services/
      storage.py            secure streaming upload + SHA-256/MD5/SHA-1 hashing
      analysis/             static analyzers (PE/Office/PDF/Image/scripts/strings/entropy/YARA-lite/score)
      detection/            evidence · IOC · 11 correlation rules · MITRE ATT&CK · provenance graph
      ai/                   Ollama provider · deterministic prompt · strict anti-hallucination validation
      reports/              ReportLab PDF (context builder + render)
      ratelimit.py          in-memory fixed-window upload rate limiter
    tests/                  147 pytest tests (isolated temp DB)
docker-compose.yml          PostgreSQL + backend + frontend (nginx); no hardcoded secrets
PRODUCTION_READINESS.md     VERIFIED / NOT VERIFIED production checklist
```

### Backend request flow

```
POST /api/samples/upload
  → rate limit check (30/min/IP) → streaming size limit (100 MiB, 413 if over)
  → empty file rejected (422) → filename sanitized, stored under random UUID name
  → SHA-256 / MD5 / SHA-1 computed at write time
  → Investigation row created  → queued for analysis
```

### Analysis pipeline & status lifecycle

```
queued → running → analysing → ai-processing → completed | failed → closed
```

Static analysis → normalized evidence → IOC extraction → correlation rules →
evidence-backed MITRE mappings → deterministic threat score → verdict
(`malicious` / `suspicious` / `clean`) with severity. A searchable provenance graph
ties file → evidence → IOC/finding → technique.

---

## 4. What has been built — phase history

| Phase | Date | Commit | What landed |
|---|---|---|---|
| P1 Stabilization | 2026-08-09 | — | Real SQLite layer, secure upload, Dashboard/Queue/Upload wired to live data |
| P2 Static analysis | 2026-08-09 | — | Analyzers (PE/Office/PDF/Image/scripts), strings, entropy, YARA-lite, deterministic scoring |
| P3 Detection & evidence | 2026-08-09 | — | Evidence engine, IOC extraction, 11 correlation rules, MITRE ATT&CK, provenance graph |
| P4 AI/Ollama engine | 2026-08-10 | — | `AIProvider` abstraction, deterministic prompt, strict JSON validation, graceful unavailable state |
| P7 Report | 2026-08-11 | — | ReportLab PDF endpoint + UI report page |
| Dashboard analytics | 2026-08-18 | — | Live aggregations (KPIs, charts, IOC/YARA/MITRE stats) replacing mock numbers |
| Case closure + Threat-Intel UI | 2026-08-20 | `78f3b45` | PATCH endpoint, closure fields, Threat Intel filtering/search/copy |
| **Security hardening** | 2026-08-20 | `16d2aaf` | CORS, security headers, sanitized errors, `/docs` disabled outside dev, dashboard OOM fix, non-root Docker, nginx hardening, 16 adversarial tests |
| **ESLint quality gate** | 2026-08-31 | `60ff096` | ESLint flat config; 17 findings fixed incl. a real conditional-hooks bug; zero-warnings lint |
| **Production hardening** | 2026-09-06 | `3cab917` | Structured logging + request IDs, upload rate limiting, PostgreSQL readiness, Docker/env hardening, 19 new tests |
| Repo hygiene | 2026-09-06 | `3fe1ec7` | `.gitignore` covers DB backups |

> Note: an unrelated GitHub Copilot PR (a "dynamic sandbox scaffold") existed on the
> remote; it was removed from `main` because it contradicted the project's core scope
> (samples are never executed). Its content still exists on `origin/copilot/*` branches.

---

## 5. Recent updates in detail (the "new" work)

### A. Structured logging + request IDs (commit `3cab917`)
- New module `backend/app/logging_config.py`:
  - `request_id_var` (context variable) + `RequestIdFilter` — every log line inside a
    request emits `request_id=<id>`.
  - `SafeFormatter` — stable `key=value` lines (`asctime`, `level`, `logger`,
    `request_id`, `investigation_id`, `analyzer`, `event`); missing fields default
    to `-` so any logger call is safe.
  - `generate_request_id()` — honors a client-supplied `X-Request-ID` only if ≤ 64
    chars of safe characters (`[A-Za-z0-9._-]`); otherwise generates a UUID.
- Middleware in `main.py`: assigns/echoes `X-Request-ID` on **every** response and
  logs `request METHOD path -> status (ms)`.
- All error responses (500 global handler, HTTP errors, 422 validation) now include
  the correlated `request_id` while keeping the standard `detail` payload shape.
- Upload/analysis log calls now attach `investigation_id` / `analyzer` fields.

### B. Upload rate limiting
- New module `backend/app/services/ratelimit.py`: thread-safe in-memory fixed-window
  limiter (`InMemoryRateLimiter`).
- `POST /api/samples/upload` is protected (default **30 uploads/min per client IP**,
  configurable via `UPLOAD_RATE_LIMIT` / `UPLOAD_RATE_WINDOW_SECONDS`).
- On breach: `429` + `Retry-After` header + `request_id` in the body.
- **Fail-safe:** if the limiter itself throws, the request is allowed and the fault is
  logged (an upload is never blocked by a limiter bug).
- Scope note: in-memory ⇒ per single backend instance. A horizontally scaled
  deployment must swap it for a shared store (e.g. Redis).

### C. PostgreSQL support & database compatibility
- `psycopg2-binary` added to `backend/requirements.txt`.
- SQLAlchemy engine uses `pool_pre_ping=True` (stale pooled connections auto-recovered).
- `DATABASE_URL` accepts `postgresql+psycopg2://user:pass@host:5432/db`.
- `docker-compose.yml` mounts `database/init.sql` into a `postgres:16-alpine` service.
- Schema migrations (Alembic) intentionally deferred; dev SQLite files can be recreated.

### D. Docker / Compose hardening
- Compose rewritten:
  - Credentials via a root `.env` — `POSTGRES_PASSWORD=${POSTGRES_PASSWORD:?...}`
    (**no hardcoded password** anywhere).
  - Removed the unused Redis service and stale `USE_REAL_LLM` flag.
  - Backend: `LOG_LEVEL`, rate-limit env passthrough; nginx frontend proxies `/api` →
    `backend:8000`; healthcheck `pg_isready`.
- Backend Dockerfile: `python:3.12-slim`, runs as non-root `aegis` (UID 1001).
- Frontend `.dockerignore` excludes `node_modules`, `dist`, `.env`, `.env.local`.

### E. Environment configuration
- `backend/.env.example` rewritten to list every real variable with defaults and
  descriptions (incl. `LOG_LEVEL`, `UPLOAD_RATE_*`, Postgres URL example). No secrets
  in any `.env.example`.

### F. New tests (19) — total 147
- `tests/test_logging.py` (11): formatter/filter/generator units; response carries
  generated or client-provided `X-Request-ID`; unsafe headers replaced; error bodies
  match the header; access-log capture.
- `tests/test_rate_limit.py` (8): limiter windowing/per-key rollover; live `429` via
  limiter swap with `Retry-After` + `request_id`.

---

## 6. Public API overview (all under `/api`)

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Service + component status (no internals) |
| GET | `/dashboard/stats` | Aggregated dashboard statistics |
| POST | `/samples/upload` | Secure upload → hashing → analysis (rate-limited, 100 MiB cap) |
| GET | `/investigations` | List (optional `?status=` filter) |
| GET | `/investigations/{id}` | Single investigation |
| PATCH | `/investigations/{id}` | Update verdict/severity/closure fields, close case |
| GET | `/investigations/{id}/static` | Persisted static-analysis payload |
| GET | `/investigations/{id}/findings` | Detection findings |
| GET | `/investigations/{id}/iocs` | Deduplicated indicators of compromise |
| GET | `/investigations/{id}/mitre` | Evidence-backed MITRE ATT&CK mappings |
| GET | `/investigations/{id}/graph` | Provenance graph |
| GET | `/investigations/{id}/threat-intel` | Stored IOCs (external feeds pending) |
| GET | `/investigations/{id}/ai` | AI interpretation (`completed`/`unavailable`/`error`) |
| GET | `/investigations/{id}/report/pdf` | Downloadable PDF report |

Response headers: security headers on every response; `X-Request-ID` on every response.

---

## 7. Tests & quality

- **Backend: 147/147 pytest tests pass** (breakdown):
  - AI service/providers/prompts/validation 26 · dashboard 20 · detection/MITRE 10 ·
    IOC 10 · scoring 9 · reports 14 · health 5 · upload 7 · failure isolation 4 ·
    adversarial security 16 · API integration 7 · request-ID/logging 11 · rate-limit 8.
  - Tests run against an isolated temp DB; no real Ollama needed (mock transport /
    injected provider).
- **Frontend:** `npm run lint` (zero warnings) · `npm run build` (= `tsc --noEmit` +
  `vite build`) — both green.

---

## 8. How to run locally

```bash
# Backend (http://localhost:8000, docs at /docs)
cd backend
pip install -r requirements.txt
copy .env.example .env        # adjust if needed
python -m uvicorn app.main:app --reload --port 8000

# Frontend (http://localhost:5173)
cd frontend
npm install
copy .env.example .env        # VITE_USE_BACKEND=true, VITE_API_BASE_URL=/api
npm run dev
```

- Ollama optional: install Ollama + `ollama pull qwen3:4b`; leave `AI_MODEL=` empty to
  auto-discover. Without it, AI sections show a clear "unavailable" state and all
  deterministic analysis still works.

---

## 9. Verification status & known gaps (be honest with these)

| Item | Status |
|---|---|
| Security headers + request IDs live | VERIFIED (curl checks) |
| Backend tests 147/147, frontend lint/tsc/build | VERIFIED |
| SQLite path | VERIFIED (tests + live runs) |
| PostgreSQL path | **NOT VERIFIED** — no Postgres server on this machine (config-tested only) |
| Docker / Compose stack | **NOT VERIFIED** — Docker not installed; status = "pending because Docker is unavailable" |
| Ollama / AI inference | NOT VERIFIED — not installed; graceful `unavailable` fallback verified |
| Distributed (multi-instance) rate limiting | Out of scope — in-memory limiter is single-instance |
| Real authentication/RBAC | Demo gate only — any credentials pass |
| External threat-intel feeds | Pending (endpoints return stored IOCs) |
| TLS/HTTPS, security-hardened reverse proxy | Not deployed (out of current scope) |

---

## 10. Suggested ChatGPT prompts

- "Explain the project in 10 minutes for a B.E. defense, including architecture,
  security model, and demo flow."
- "Review the production-hardening updates (section 5) and list any risks or gaps."
- "Generate a project-report / marks-rubric writeup using sections 1, 3, 4, 6, 7."