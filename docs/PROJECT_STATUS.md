# PROJECT_STATUS.md

**Project:** AI-Powered Intelligent Sandbox for Secure File Analysis using Artificial Intelligence
**Audit date:** 09 August 2026
**Target completion:** 30 November 2026

---

## 0. Current Status (Phase 1 — Stabilization) — updated 09 Aug 2026

**Decision (user):** the project root is `Desktop\AI Sandbox` (the former "Aegis Sandbox AI"
prototype). The prototype's UI is kept; its backend has been rebuilt on a real SQLite layer.

**Working now (verified end-to-end):**
- Backend boots (`uvicorn app.main:app`) with `init_db` startup. All endpoints return 200.
- `POST /api/samples/upload` streams the file to `uploads/`, enforces the 100 MiB limit,
  rejects empty files, sanitises filenames, computes SHA-256/MD5/SHA-1, and creates an
  `INV-YYYY-NNNN` investigation row.
- `GET /api/investigations` (with `?status=` filter), `GET /api/investigations/{id}`,
  `GET /api/dashboard/stats` serve live DB data.
- 12 pytest tests pass against an isolated temp DB (`python -m pytest` in `backend/`).
- Frontend Dashboard, Queue and Upload pages are wired to the backend with a demo-data
  fallback (`VITE_USE_BACKEND`, `VITE_API_BASE_URL`). `npm run build` passes.

**Run it:** terminal A — `cd backend && ../venv/Scripts/python -m uvicorn app.main:app --reload`;
terminal B — `cd frontend && npm run dev`. Open http://localhost:5173.

**Still to do (by phase):** static analysis engine (P2), threat detection/YARA/MITRE (P3),
AI/Ollama verdict (P4), reporting/history (P5). Deep-dive pages still render mock content;
backend returns structured "pending" payloads for those endpoints until their modules land.

**Known issues:** `npm run lint` broken (eslint not installed); Docker not installed; Ollama
not installed (`ai_model=qwen3` is a default, not verified).

---

## 0.1 Current Status (Phase 3 — Detection & Evidence Engine) — updated 09 Aug 2026

The sections below record the pre-rebuild audit. Since then, Phase 1 (DB + secure upload),
Phase 2 (static analysis engine) and Phase 3 (detection & evidence engine) have landed and
are verified end-to-end:

**Working now (verified end-to-end):**
- `POST /api/samples/upload` streams to `uploads/`, enforces 100 MiB, rejects empty files,
  computes hashes, creates `INV-YYYY-NNNN`.
- Analysis pipeline (`backend/app/services/analysis/`): file-type detection, metadata,
  strings, entropy, PE/Office/PDF/Image analyzers with per-analyzer failure isolation,
  YARA-lite matching, and a deterministic threat score.
- Detection layer (`backend/app/services/detection/`): normalized evidence model, IOC
  extraction (URL/domain/IP/email/hash/registry/path/command/mutex) with FP controls,
  11 correlation rules, evidence-backed MITRE ATT&CK mappings, provenance graph.
- Endpoints: `/findings`, `/iocs`, `/mitre`, `/graph`, `/static`, `/threat-intel`.
- Frontend Static Analysis and MITRE pages render live detection data with mock fallback.
- **47 pytest tests pass** (`..\venv\Scripts\python.exe -m pytest -q` from `backend/`).
- `npx tsc --noEmit` passes.

**Still to do (by phase):** AI/Ollama verdict (P4, explains — never invents — detections),
reporting/history (P5). AI and report pages still render mock content.

**Known issues:** `npm run lint` broken (eslint not installed); Docker not installed; Ollama
not installed (`ai_model=qwen3` is a default, not verified).

## 1. Executive Summary

The repository currently contains **design documentation only**. The working directory
(`Desktop\docs`) holds 11 documentation files describing the intended BE Major Project.

A **separate prototype codebase** exists on the same machine at
`Desktop\AI Sandbox` ("Aegis Sandbox AI"). It is a self-contained React/FastAPI demo that
ships **high-fidelity simulated data** (a fake SOC console with mock malware analysis).
It does **not** match the documented architecture in several important ways (see
ARCHITECTURE_AUDIT.md). A third, unrelated-but-related project ("AegisFlow", the
`AI-Powered Security Investigation Orchestrator`) also exists on the Desktop.

**Bottom line:** almost none of the documented BE-project features are implemented in
working code. The frontend UI is reusable; the backend must effectively be rebuilt around
the documented architecture.

---

## 2. Repository Layout (as found)

| Path | What it is |
|------|------------|
| `Desktop\docs` (current working dir) | 11 design docs for the BE project. No code. |
| `Desktop\AI Sandbox` | "Aegis Sandbox AI" — React+TS+FastAPI demo prototype (mock data). The only existing code. |
| `Desktop\AI-Powered Security Investigation Orchestrator` | "AegisFlow" — separate, larger reference project (Temporal, Neo4j, RAG). Not part of this project's scope. |
| Git | Repo initialized at the **home directory** (`C:\Users\Bhoomi Bhanushali`), **zero commits**, tracks the whole home folder. Not usable as a project repo. |

---

## 3. What Actually Exists

### Documentation (complete, but aspirational)
- 11 docs in `Desktop\docs` (README, ARCHITECTURE, PROJECT_WORKFLOW, FEATURES,
  FUTURE_ROADMAP, API_DOCUMENTATION, DATABASE, AI_ENGINE, SECURITY_MODULES, DEPLOYMENT,
  CHANGELOG). Identical copy inside `AI Sandbox\docs\docs`.
- Docs describe features as "Completed" that are **not implemented in code** (see §5).

### Frontend prototype (`AI Sandbox\frontend`) — REUSABLE
- React 18 + TypeScript + Vite 5 + Tailwind CSS + Framer Motion + Recharts.
- Pages: Login, Dashboard, Upload, Queue, analysis/{StaticAnalysis, DynamicAnalysis,
  NetworkAnalysis, ThreatIntel, Mitre, AiInvestigation, Report}.
- **Verified:** `npm run build` succeeds (tsc --noEmit + vite build, ~90 s).
- Runs entirely on a **local mock-data layer**; there are **no API calls** in `src/`
  (no axios/fetch/`/api` references). `VITE_USE_BACKEND` is documented but **not implemented**.

### Backend prototype (`AI Sandbox\backend`) — NOT RUNNABLE
- `app/main.py` (FastAPI): routers for dashboard, investigations, samples.
- `app/routers/*.py`: serve **mock data** only (`app/data/mock_data.py`).
- `app/ai/engine.py`: hardcoded deterministic "verdict" for one demo case; the real-LLM
  path is `NotImplementedError`.
- `app/routers/upload.py`: computes SHA-256/MD5 in memory, returns a hardcoded queued
  case ID; **nothing is stored**.
- **Verified broken:** `app.main` fails to import — `pydantic_settings` is not installed.
- Stale/duplicate entrypoints exist: `backend/main.py` + `backend/routes/upload.py`
  (a different, older app).

### Database
- **No database code.** SQLAlchemy is installed but unused (no models, no session).
- `database/init.sql` is PostgreSQL DDL only, not wired to the app.
- Backend config defaults to `sqlite:///./aegis.db` but nothing creates or uses it.

### AI
- No Ollama integration. No provider abstraction. No prompt builder. Deterministic
  simulator only. No models installed on the machine.

### Docker
- `docker-compose.yml` (db=postgres, redis, backend, frontend) + Dockerfiles + nginx.conf
  exist, but the stack will not start (see §4).

### Environment
- Python 3.14.6 (system, **no pip module**), Node 24.17, npm 11.13, git 2.55.
- **Docker: not installed. Ollama: not installed. uv: not installed.**
- venv at `AI Sandbox\venv` (72 packages) matches root `requirements.txt` but is missing
  `pydantic_settings`.

---

## 4. Known Bugs / Broken Things

1. **Backend will not start** — `ModuleNotFoundError: pydantic_settings`
   (`backend\app\config.py:3`).
2. **Docker backend will not start** — compose sets `DATABASE_URL=postgresql+psycopg2://...`
   but `psycopg2-binary` is commented out in `backend\requirements.txt`.
3. **Frontend `npm run lint` is broken** — `package.json` declares an `eslint` script but
   `eslint` is not in `devDependencies`.
4. **Root `requirements.txt` is UTF-16 encoded** — `pip install -r requirements.txt` fails
   on modern pip.
5. **Duplicate backend entrypoints** — `backend\main.py` and `backend\app\main.py` are
   unrelated apps; `backend\routes\` vs `backend\app\routers\` both exist.
6. **Git repo is misconfigured** — initialized in the home directory with no commits.
7. **Frontend never calls the backend** — the documented `VITE_USE_BACKEND=true` path does
   not exist in code.
8. **System Python 3.14 has no pip** — cannot install dependencies until pip/bootstrap is
   fixed (recommend Python 3.12 + venv per `steps.txt`).

---

## 5. Feature Implementation Status vs Documentation

| Feature (per docs) | Documented | Actual |
|--------------------|-----------|--------|
| React dashboard UI | ✅ | ✅ UI exists (mock data) |
| File upload | ✅ | ⚠️ computes hashes only, nothing stored |
| Backend REST APIs | ✅ | ⚠️ mock-data endpoints only |
| SQLite database | ✅ | ❌ no DB code |
| Docker support | ✅ | ⚠️ files exist, stack broken |
| File validation | ❌ planned | ❌ missing |
| Secure file storage | ❌ planned | ❌ missing (one stray route writes to `../uploads`) |
| File type detection | ❌ planned | ❌ missing |
| Metadata extraction | ❌ planned | ❌ missing |
| SHA-256 (persisted) | ❌ planned | ⚠️ computed in upload response only |
| Static analysis (PE/PDF/Office/Image/Script) | ❌ planned | ❌ missing (simulated values) |
| String / entropy analysis | ❌ planned | ❌ missing |
| YARA matching | ❌ planned | ❌ missing |
| IOC extraction | ❌ planned | ❌ missing |
| Threat scoring | ❌ planned | ❌ missing (mock `riskScore` values) |
| MITRE ATT&CK mapping | ❌ planned | ❌ missing (mock technique list) |
| AI / Ollama engine | 🔄 prototype | ❌ missing (deterministic simulator) |
| Investigation history | ❌ planned | ❌ missing (mock list only) |
| Investigation flow graph | ❌ planned | ❌ missing |
| PDF report generation | ❌ planned | ❌ missing (browser-print only) |
| Dashboard analytics (real data) | ❌ planned | ❌ missing (static mock stats) |
| Tests (unit/integration/security) | — | ❌ none exist |
| `.env.example` | ✅ | ⚠️ backend has one; no root/frontend live wiring |

---

## 6. Technical Debt / Risks

- **Vision conflict:** existing prototype is a *simulated detonation SOC product* (MSc
  branding); the BE-project docs mandate *safe static analysis, never execute*. Deciding
  which one is the final product is the #1 risk (see ARCHITECTURE_AUDIT.md).
- **Mock-data dependency:** frontend has zero API integration; re-wiring is non-trivial.
- **No tests and no CI:** zero regression safety net.
- **Python 3.14 / no pip / no Docker / no Ollama** on this machine blocks most verification.
- **Naming:** "Aegis" branding must be replaced with the project title for the BE
  demonstration.

---

## 7. Completed / Partial / Missing Summary

- **Completed:** design documentation; a buildable demo frontend UI (mock); basic FastAPI
  skeleton; docker-compose scaffold.
- **Partial:** upload endpoint (hashing only), AI module (simulator only).
- **Missing (i.e., to build):** real backend analysis engine, database layer, AI/Ollama,
  threat scoring, YARA, IOC, MITRE, reporting, history, dashboard-from-real-data, tests,
  working Docker, git history, deployment config.
