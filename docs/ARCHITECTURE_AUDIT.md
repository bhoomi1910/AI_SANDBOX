# ARCHITECTURE_AUDIT.md

## 1. Purpose

Compare the *documented* architecture (docs/) with the *actual* codebase (`Desktop\AI Sandbox`)
and list the minimal changes needed to make the code match the documented BE Major Project:
**AI-Powered Intelligent Sandbox for Secure File Analysis using Artificial Intelligence**.

## 2. Documented Architecture (docs/)

- **Frontend:** React + Vite + Tailwind + React Router + Axios + Recharts. Pages for
  Dashboard, Upload, Investigations, Reports.
- **Backend:** FastAPI + SQLAlchemy + Pydantic + Uvicorn. Modular services: metadata,
  hashing, static analysis, YARA, AI, reports, threat scoring.
- **Database:** SQLite now; PostgreSQL later. Tables for investigations, files, metadata,
  hashes, static analysis, yara_matches, ioc_results, ai_analysis, mitre_mapping, reports.
- **Security engine:** file validation → type detection (magic bytes) → metadata → hashing →
  static analysis (PE/PDF/Office/Image/Script) → strings → entropy → YARA → IOC → threat score.
- **AI engine:** interpretation layer over structured evidence via **Ollama** (local LLM),
  provider/model-configurable, graceful fallback when Ollama is down.
- **Principles:** safe static analysis only — **uploaded files are never executed**;
  deterministic evidence first, AI second; module failures must not crash an investigation.
- **Infrastructure:** Docker Compose; SQLite volume; health checks; `.env.example`.
- **Reporting:** ReportLab PDFs containing deterministic findings + clearly-separated
  AI interpretation.

## 3. Actual Architecture (`Desktop\AI Sandbox`)

- **Frontend:** React 18 + TS + Vite + Tailwind + Framer Motion + Recharts. Pages: Login,
  Dashboard, Upload, Queue, Static/Dynamic/Network/ThreatIntel/Mitre/AiInvestigation/Report.
  **Fully self-contained on mock data — zero backend API calls.** "Dynamic" and "Network"
  analysis are simulated detonation/C2 visualizations.
- **Backend:** FastAPI serving **mock_data.py** through routers. AI engine is a hardcoded
  deterministic simulator for one Emotet case; the real-LLM path is `NotImplementedError`
  (OpenAI/Anthropic references, no Ollama).
- **Database:** none in code. PostgreSQL DDL only in `database/init.sql`; SQLAlchemy unused.
- **Docker:** compose defines postgres + redis + backend + frontend; backend container is
  broken (psycopg2 missing).
- **Upload:** computes SHA-256/MD5 in memory, returns a hardcoded "queued" case, stores nothing.

## 4. Differences (Documented vs Actual)

| Area | Documented | Actual | Impact |
|------|-----------|--------|--------|
| Product name | "AI-Powered Intelligent Sandbox" (BE project) | "Aegis Sandbox AI" (MSc demo) | Must rebrand |
| Analysis model | Safe **static only**, never execute | **Simulated dynamic detonation** + C2 maps | Direct conflict with core security principle |
| Data source | Real analysis engine + SQLite | Mock JSON only | Everything must be rebuilt |
| AI | Ollama, local LLM, evidence-based | Deterministic simulator, OpenAI/Claude placeholders | Rebuild to Ollama provider abstraction |
| Threat score | Weighted, explainable, evidence-driven | Static `riskScore` in mock data | Rebuild |
| MITRE | Mapped from detected evidence | Hardcoded technique list | Rebuild |
| Reports | ReportLab PDF | Browser print-to-PDF | Rebuild |
| Database | SQLite models + migrations | No models | Rebuild |
| Frontend↔Backend | REST via Axios | None (mock layer) | Wire real API layer |
| Docker | Working stack | Broken backend container | Fix |

## 5. What Is Actually Reusable

- **Frontend UI, pages, components, styling** — strong, professional, dark-theme SOC
  console. Rebrand ("Aegis" → project name), then keep the visual design and information
  architecture (Dashboard, Upload, Investigation detail, Static, AI, Report, Mitre).
  Remove/simply the "Dynamic Analysis" and "Network Analysis" pages or explicitly label
  them as *future/out-of-scope* since the BE project is static-only (decision required).
- **FastAPI skeleton** (`app/main.py`, CORS, health endpoint).
- **docker-compose / Dockerfiles / nginx** as a base — must be fixed.
- **Design docs** — the source of truth for the target architecture.

## 6. Architectural Risks

1. **Core-principle conflict (highest risk):** the existing prototype presents *simulated
   detonation results*. The BE project mandates *no execution and real static analysis*.
   If not resolved explicitly, reviewers could think the project "fakes" results or that the
   demo claims dynamic behavior never observed. → Resolve by scoping the project to
   **real static analysis** and removing/re-labelling simulated-detonation content.
2. **Mock-data debt:** frontend is coupled to local TS mock files; replacing with API calls
   touches every page.
3. **No tests/CI:** any rebuild is unverifiable.
4. **Local toolchain gaps:** Python 3.14 without pip, no Docker, no Ollama — verification
   of Docker and AI work is blocked until installed.
5. **Git:** repo root is the home directory; project has no history.

## 7. Recommended Minimal Changes (no redesign)

Keep the documented architecture. Do **not** change stack (React/Vite stays; FastAPI stays;
SQLite stays; Docker stays). Minimal changes:

1. **Establish the real project root** (decide: consolidate into one folder, e.g.
   `Desktop\AI Sandbox`, and move the docs in) and **initialize proper git** there.
2. **Rebrand** frontend strings/logos/package names to the BE project name.
3. **Fix stabilization blockers:** install backend venv deps (add `pydantic-settings`,
   `psycopg2-binary` for compose), fix root `requirements.txt` encoding, add `eslint` dep
   or drop the lint script, remove stale `backend/main.py` + `backend/routes/`.
4. **Build the real backend** around the documented modules (BaseAnalyzer pattern, evidence
   dicts, per-module failure isolation), replacing mock-data serving.
5. **Add the SQLite layer** (SQLAlchemy models + migrations) implementing the documented tables.
6. **Wire the frontend** to the API (Axios service layer), keeping the mock data as a
   dev-only fallback.
7. **Replace the AI simulator** with an Ollama provider abstraction + evidence-based prompts
   + fallback, per AI_ENGINE.md.
8. **Implement threat scoring, YARA, IOC, MITRE mapping, PDF reports** deterministically.
9. Fix Docker, add `.env.example` at root, and create the deployment checklist.

## 8. What Should NOT Be Changed

- React + Vite + Tailwind frontend stack.
- FastAPI + SQLAlchemy + Pydantic backend stack.
- SQLite as the current database.
- Docker Compose deployment approach.
- The safe-static-analysis security principle (no execution of uploaded files).
- The modular, evidence-first architecture described in the docs.

## 9. Open Decisions (owner must confirm before Phase 1)

1. Project root/consolidation (current `Desktop\docs` is docs-only; code is in `Desktop\AI Sandbox`).
2. Fate of the "Dynamic Analysis" / "Network Analysis" simulated pages.
3. Whether the existing Aegis frontend UI is kept as the base (recommended: yes).
