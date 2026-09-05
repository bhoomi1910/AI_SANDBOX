<div align="center">

# 🛡️ AI-Powered Intelligent Sandbox

### Deterministic Static Malware Analysis Platform with AI-Assisted Interpretation

*A B.E. Major Project — a working SOC-analyst workflow: upload a suspicious file, receive
a scored, evidence-backed threat analysis, MITRE ATT&CK mapping, an AI interpretation, and a
downloadable PDF investigation report.*

`React` · `TypeScript` · `Vite` · `TailwindCSS` · `FastAPI` · `SQLAlchemy` · `SQLite` · `ReportLab` · `Ollama (optional)`

</div>

---

## What is this?

A **safe static analysis sandbox** — the sample is **never executed**. The analyst uploads a
file and the pipeline produces:

- **Hashing** — SHA-256 / MD5 / SHA-1 computed at upload time.
- **Static analysis** — file-type detection, metadata, strings, entropy, PE / Office / PDF /
  Image analyzers with per-analyzer failure isolation, YARA-lite matching.
- **Detection layer** — normalized evidence, IOC extraction (URLs, domains, IPs, emails,
  hashes, registry keys, paths, commands, mutexes) with false-positive controls, 11
  correlation rules, and **evidence-backed MITRE ATT&CK mappings** (no hardcoded lists).
- **Deterministic threat score** — per-category deduplicated weighting → `malicious` /
  `suspicious` / `clean` verdict with severity.
- **AI interpretation (optional)** — a local Ollama model explains *what the deterministic
  findings mean*. The AI can never add detections, invent IOCs/MITRE techniques, or change
  the score.
- **PDF report** — a professional ReportLab report built from the persisted analysis,
  downloadable from the UI.

> The AI is **interpretation only**. Everything the report claims is grounded in the
> deterministic analysis; when Ollama is unavailable the platform degrades gracefully and
> shows a clearly labelled deterministic summary instead of a fake verdict.

---

## The Workflow

```
  Login ──▶ Dashboard ──▶ Upload Sample ──▶ Investigation Queue
                                                   │
                                                   ▼
  Static Analysis ──▶ IOCs & Findings ──▶ MITRE ATT&CK ──▶ AI Investigation ──▶ 📄 Report (PDF)
```

Deep-dive pages: `Static Analysis`, `Mitre`, `AI Investigation` and `Report` are wired to the
live backend. `Dynamic`, `Network` and `Threat Intel` still render the mock prototype dataset
(out of scope — this platform intentionally never executes samples).

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Frontend | React 18 + TypeScript, Vite, TailwindCSS, TanStack Query, Recharts, Framer Motion |
| Backend | Python 3.11+ (tested on 3.14), FastAPI, SQLAlchemy 2, SQLite (PostgreSQL-ready via psycopg2) |
| Reporting | ReportLab (PDF) |
| AI (optional) | Local Ollama only — free models auto-discovered via `/api/tags`, no cloud/paid inference |

---

## Quick Start

**Prerequisites:** Node.js 20+, Python 3.11+.

### 1. Backend (FastAPI)

```bash
cd backend
python -m venv .venv

# Windows
.\.venv\Scripts\Activate.ps1
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env      # Windows (or: cp .env.example .env)
uvicorn app.main:app --reload --port 8000
```

- Interactive API docs → http://localhost:8000/docs
- Health check → http://localhost:8000/api/health

### 2. Frontend (React + Vite)

```bash
cd frontend
npm install
copy .env.example .env      # Windows (or: cp .env.example .env)
npm run dev
```

Open http://localhost:5173 → click **Access console**.

`VITE_USE_BACKEND=true` (the default in `.env.example`) points the frontend at the running
backend through the Vite `/api` proxy. Set `VITE_USE_BACKEND=false` to run the frontend fully
on its built-in mock dataset — no backend required.

### 3. Optional — local AI (Ollama)

1. Install [Ollama](https://ollama.com) and pull a free model, e.g. `ollama pull qwen3:4b`.
2. Leave `AI_MODEL=` empty in `backend/.env` to auto-discover the first installed model, or set
   it explicitly.
3. Restart the backend. Without Ollama, the AI sections render a clear "unavailable" state and
   everything else keeps working.

---

## Tests

```bash
# Backend — 147 tests (unit + integration + end-to-end API), no real Ollama needed
cd backend
..\venv\Scripts\python.exe -m pytest -q        # Windows
../venv/bin/python -m pytest -q                # Linux/macOS

# Frontend — type-check + lint + production build
cd frontend
npm run lint
npm run build
```

---

## API Overview

All routes are prefixed with `/api`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service health + component status |
| `GET` | `/dashboard/stats` | Live dashboard statistics |
| `POST` | `/samples/upload` | Secure upload → hashing → analysis (100 MiB limit, empty rejected, rate-limited 30/min/IP) |
| `GET` | `/investigations` | List investigations (optional `?status=` filter) |
| `GET` | `/investigations/{id}` | Single investigation |
| `GET` | `/investigations/{id}/static` | Full persisted analysis payload |
| `GET` | `/investigations/{id}/findings` | Detection findings (analyzer + rule-correlated) |
| `GET` | `/investigations/{id}/iocs` | Deduplicated indicators of compromise |
| `GET` | `/investigations/{id}/mitre` | Evidence-backed MITRE ATT&CK mappings |
| `GET` | `/investigations/{id}/graph` | Provenance graph (file → evidence → IOC/finding → technique) |
| `GET` | `/investigations/{id}/threat-intel` | Stored IOCs (external feeds pending) |
| `GET` | `/investigations/{id}/ai` | AI interpretation (`completed` / `unavailable` / `error`) |
| `GET` | `/investigations/{id}/report/pdf` | Downloadable PDF investigation report |

---

## Project Structure

```
AI SANDBOX/
├── frontend/                  # React + TypeScript + Vite SPA
│   ├── src/
│   │   ├── components/        # ui (shadcn-style) · layout · shared widgets
│   │   ├── pages/             # Login, Dashboard, Upload, Queue, analysis/*
│   │   ├── data/              # Types + demo (mock) fallback dataset
│   │   ├── lib/               # api client (VITE_USE_BACKEND switch), utils
│   │   └── index.css          # design system / theme tokens
│   ├── .env.example           # VITE_USE_BACKEND=true, /api base URL
│   └── package.json
├── backend/                   # FastAPI service
│   ├── app/
│   │   ├── main.py            # app entrypoint + CORS + health
│   │   ├── config.py          # env-driven settings (SQLite default)
│   │   ├── database.py        # SQLAlchemy session + init
│   │   ├── models.py          # Investigation / AnalysisResult
│   │   ├── routers/           # dashboard · investigations · upload
│   │   └── services/
│   │       ├── storage.py     # secure streaming upload + hashing
│   │       ├── analysis/      # static analyzers (PE/Office/PDF/Image/scripts/strings/entropy/yara/score)
│   │       ├── detection/     # evidence · IOC · rules · MITRE · graph
│   │       ├── ai/            # Ollama provider · prompt · strict validation
│   │       └── reports/       # ReportLab PDF report (context builder + render)
│   ├── tests/                 # 147 pytest tests (isolated temp DB)
│   ├── .env.example
│   └── requirements.txt       # pinned dependencies
├── docs/                      # design + status docs (ARCHITECTURE, API, DATABASE, CHANGELOG…)
├── docker-compose.yml         # optional full-stack scaffold
└── README.md
```

---

## Known Limitations

- **Dynamic / Network / Threat-Intel deep-dive pages** still render the mock prototype dataset;
  this platform is static-analysis-only and never executes samples.
- **Threat-intel feeds** (`/threat-intel`) return stored IOCs; external enrichment is pending.
- **Authentication** is a demo gate — any credentials pass; there is no real identity provider.
- **AI** requires a local Ollama; without it the AI sections show a labelled "unavailable" state.
- The upload accepts any file type, but analysis depth depends on the installed analyzers
  (PE / Office / PDF / Image / script text).
- The upload rate limiter is in-memory and therefore **per single backend instance**; a
  horizontally scaled deployment must swap it for a shared store (e.g. Redis).

---

## Build History

Phase-completed log in [`docs/CHANGELOG.md`](./docs/CHANGELOG.md) and live status in
[`docs/PROJECT_STATUS.md`](./docs/PROJECT_STATUS.md).

1. **Phase 1** — real DB layer, secure upload, live Dashboard/Queue/Upload.
2. **Phase 2** — static analysis engine (analyzers, strings, entropy, YARA-lite, scoring).
3. **Phase 3** — detection & evidence engine (IOCs, correlation rules, MITRE, graph).
4. **Phase 4** — AI/Ollama interpretation engine (interpretation only, strict validation).
5. **Phase 7** — investigation PDF report (server-generated, frontend Report page).
6. **Phase 8 (2026-08-20)** — security hardening: CORS, security headers, sanitized error
   responses, adversarial test suite, non-root Docker images, nginx hardening.
7. **Phase 9 (2026-08-31)** — quality gate: ESLint (typescript-eslint, react-hooks,
   react-refresh) in flat config, 17 findings fixed, zero-warnings lint.
8. **Phase 10 (2026-09-06)** — production hardening: structured logging with per-request
   IDs, upload rate limiting, PostgreSQL driver + Docker env substitution, regression +
   security regression, verified production-readiness checklist.

---

> **Scope note:** a prototype for a B.E. demonstration, not a production security product.
> For setup details see [`steps.txt`](./steps.txt).
