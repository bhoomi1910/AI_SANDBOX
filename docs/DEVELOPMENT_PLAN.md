# DEVELOPMENT_PLAN.md

**Project:** AI-Powered Intelligent Sandbox for Secure File Analysis using Artificial Intelligence
**Target completion:** 30 November 2026
**Plan created:** 09 August 2026 (after repository audit)

---

## 1. Ground Truth (from audit)

- Docs exist; **code is at prototype level** (`Desktop\AI Sandbox`, "Aegis Sandbox AI").
- Frontend UI builds but is mock-only. Backend does not start. No database, no real
  analysis engine, no AI/Ollama, no tests, broken Docker, no git history.
- Machine: Python 3.14 (no pip), Node 24, no Docker, no Ollama.

This plan is **realistic**, not aspirational: it starts by fixing the foundation, then
builds the documented features in dependency order.

---

## 2. Foundational Decisions (blocking — resolve first)

1. **Project root:** consolidate code + docs into one folder (recommended: make
   `Desktop\AI Sandbox` the project root, move the 11 docs + 4 audit docs in, or create a
   fresh root). The current working directory is docs-only.
2. **Git:** initialize a proper repo in the project root (current repo sits in the home
   directory with no commits). Commit in logical milestones only.
3. **Scope:** static-analysis only (per docs). Decide fate of the simulated
   "Dynamic Analysis"/"Network Analysis" pages (remove or label out-of-scope).
4. **Toolchain:** use Python 3.12 for the backend (per `steps.txt`; 3.14 lacks pip and some
   libs). Confirm installs for Docker and Ollama when they become needed.

---

## 3. Development Phases

### PHASE 1 — Stabilization (August)
Goal: everything runs locally and the UI talks to a real API.

- [ ] Consolidate project root; init git; initial commit of docs.
- [ ] Fix backend environment: `python3.12 -m venv`, install pinned deps
  (`pydantic-settings`, `python-multipart`, etc.), fix UTF-16 `requirements.txt`.
- [ ] Make `app.main` import and serve `/api/health`, `/api/dashboard/stats`, etc.
- [ ] Remove stale duplicate backend entrypoints (`backend/main.py`, `backend/routes/`).
- [ ] Frontend: fix/remove broken `lint` script; add Axios service layer; wire Dashboard +
  Upload + Investigations to real endpoints (keep mock layer as dev fallback only).
- [ ] Implement upload → validate (size, empty, extension) → secure storage (sanitized,
  UUID names, uploads dir, path-traversal-safe) → create investigation row.
- [ ] Add `.env.example` at root; document setup in README/DEPLOYMENT.

**Exit criteria:** backend boots; upload stores a file and creates an investigation;
frontend displays it; `npm run build` passes.

### PHASE 2 — Core File Analysis (August–September)
- [ ] SHA-256 (+ MD5/SHA-1) persisted; duplicate detection by hash.
- [ ] File type detection by magic bytes (independent of extension).
- [ ] Metadata extraction (basic OS metadata; then per-type).
- [ ] `BaseAnalyzer` interface + analyzers: PE, PDF, Office (docx/xlsx/pptx), Image, Script,
  Archive. Each returns structured evidence; each fails independently.
- [ ] Strings extraction + entropy analysis.

### PHASE 3 — Detection Engine (September)
- [ ] YARA integration (`yara-python`) with a rules directory + bundled starter rules.
- [ ] IOC extraction (IP, URL, domain, email, registry key, file path, hash).
- [ ] Suspicious indicator detection (suspicious imports, packed/entropy heuristics).
- [ ] Explainable threat score (weighted, documented methodology) + risk levels.
- [ ] Digital signature info where practical (best-effort).

### PHASE 4 — AI Engine / Ollama (October)
- [ ] `AIProvider` abstraction → `OllamaProvider`; model via config, not hardcoded.
- [ ] Structured evidence → prompt builder → JSON-ish response → validation.
- [ ] Executive summary, technical summary, threat explanation, confidence, recommendations.
- [ ] **Graceful fallback:** if Ollama is down, investigation completes with AI marked
  "unavailable"; never blocks analysis.

### PHASE 5 — MITRE ATT&CK Mapping (October)
- [ ] Deterministic mapping rules from evidence → technique {id, name, tactic, evidence,
  confidence, source module}. No hallucinated mappings.

### PHASE 6 — Investigation Flow Graph (October)
- [ ] Evidence-based flow visualization (file → type → findings → IOC → YARA → MITRE →
  score → AI). Clearly label observed vs inferred vs AI interpretation.

### PHASE 7 — Reporting (October)
- [ ] ReportLab PDF: investigation ID, file info, hashes, metadata, static analysis, YARA,
  IOCs, score, MITRE, AI summary (clearly labelled), recommendations, timestamps, modules run.

### PHASE 8 — Dashboard Analytics (October–November)
- [ ] Real stats from DB: totals, threat distribution, file types, IOCs, YARA hits, high-risk
  files, timeline, status. Professional, demonstration-ready.

### PHASE 9 — Testing & Hardening (November)
- [ ] Unit tests (hashing, validation, detection, analyzers, IOC, scoring, AI parsing).
- [ ] Integration tests (upload→analysis→DB→report).
- [ ] Security tests (oversized, malformed, path traversal, bad MIME, duplicate uploads,
  unavailable Ollama, analyzer failures — fail safe).
- [ ] Structured logging; config via env; no secrets committed.

### PHASE 10 — Docker & Deployment (November)
- [ ] Fix compose (psycopg2/SQLite path), health checks, persistent storage.
- [ ] Create `DEPLOYMENT_CHECKLIST.md`; verify Docker on this machine (install Docker).
- [ ] Final documentation sync; demonstration prep; final release.

---

## 4. Milestones & Dates

| Milestone | Target | Notes |
|-----------|--------|-------|
| Audit + 4 docs delivered | 09 Aug 2026 | ✅ done |
| Stabilized stack runs locally | 20 Aug 2026 | Phase 1 |
| Core analysis engine (hashes, type, metadata, PE/PDF/Office) | 15 Sep 2026 | Phase 2 |
| Detection engine (YARA, IOC, scoring) | 30 Sep 2026 | Phase 3 |
| Ollama AI + MITRE + graph + reporting | 25 Oct 2026 | Phases 4–7 |
| Dashboard analytics | 10 Nov 2026 | Phase 8 |
| Tests + hardening + Docker + deployment | 25 Nov 2026 | Phases 9–10 |
| Final demo prep + release | 30 Nov 2026 | — |

Dates are targets; the plan is re-baselined after Phase 1 stabilization.

---

## 5. Testing Strategy

- pytest (unit + integration + security) for the backend.
- Frontend: `tsc --noEmit` on every build; add Vitest for critical components/utils later.
- Manual verification checklist per milestone (upload, analyze, report, history).
- Every module must fail independently (module status recorded, investigation continues).

## 6. Deployment Strategy

- Primary: Docker Compose (frontend nginx + backend uvicorn + SQLite volume).
- Local dev: two terminals (`npm run dev`, `uvicorn app.main:app --reload`).
- Ollama: host service, `OLLAMA_URL`/`OLLAMA_MODEL` env config; backend tolerant of absence.
- Final: `DEPLOYMENT_CHECKLIST.md` + documented prerequisites.

## 7. Dependency Order (why this sequence)

Backend must boot before UI wiring; hashing/type/metadata before analyzers; analyzers before
detection; evidence before AI/MITRE/scoring/reports; DB first so anything can persist.
AI is deliberately built **after** the deterministic engine so the app never depends on AI.
