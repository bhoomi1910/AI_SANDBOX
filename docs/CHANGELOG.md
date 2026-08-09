# Changelog

All notable changes to the **AI-Powered Intelligent Sandbox for Secure File Analysis using Artificial Intelligence** will be documented in this file.

The project follows a version-based development approach, where each release introduces new functionality while maintaining compatibility with the existing architecture.

---

# Development Log (real history)

## 2026-08-09 — Phase 1: Stabilization (project root = `Desktop\AI Sandbox`)

### Added
- SQLite persistence layer: `backend/app/database.py`, `backend/app/models.py`
  (`Investigation` record matching the frontend `Investigation` type), `init_db`
  startup lifecycle.
- Secure sample upload: streaming size limit (100 MiB, 413 if exceeded), empty
  upload rejection (422), filename sanitisation + UUID storage names, SHA-256 /
  MD5 / SHA-1 computed at write time (`backend/app/services/storage.py`).
- DB-backed routers: `GET /api/investigations` (status filter), `GET
  /api/investigations/{id}`, `GET /api/dashboard/stats`, `POST /api/samples/upload`.
- 12 pytest tests (`backend/tests/`) running against an isolated temp database.
- Frontend API client `frontend/src/lib/api.ts` with `VITE_USE_BACKEND` /
  `VITE_API_BASE_URL` switches; Dashboard, Queue and Upload pages wired to live
  data with an automatic demo-data fallback.
- `backend/pytest.ini`, canonical pinned `backend/requirements.txt`.

### Changed
- Backend rebranded to "AI-Powered Intelligent Sandbox"; config moved to
  `BACKEND_DIR/aegis.db`, added Ollama/upload/report settings.
- Case IDs are generated `INV-YYYY-NNNN`.
- Upload page replaces the simulated progress + hardcoded case ID with a real
  upload; "detonation" copy replaced with static-analysis copy.

### Removed
- `backend/app/data/mock_data.py`, `backend/app/ai/engine.py`, stale duplicate
  `backend/main.py` and `backend/routes/upload.py`, UTF-16 root `requirements.txt`.

### Fixed
- Backend boot failure (`pydantic_settings` missing) — backend now runs and all
  endpoints respond 200.
- Git repo initialized correctly at the project root with a clean baseline.
- Docs consolidated into `AI Sandbox\docs\`.

### Known issues (not yet fixed)
- `npm run lint` still broken (`eslint` not in devDependencies).
- AI analysis (Ollama) and report generation remain Phase 4+.

---

## 2026-08-09 — Phase 2: Static Analysis Engine

### Added
- Analyzer pipeline in `backend/app/services/analysis/`: `analysis_types.py`
  (enums + capability flags), `static_analyzer.py` (per-type dispatch with
  per-analyzer failure isolation), `strings.py` (offset-annotated ASCII/UTF-16
  extraction, configurable limits), `entropy.py`, `pe.py` (headers, sections,
  imports, exports, resources, compilation time, suspicious API heuristics),
  `office.py`, `pdf.py`, `image.py`, `yara_lite.py`, `score.py`.
- PE analysis features: AnomalyScore, ImportScore, SuspiciousImports,
  XOR/SIP spam heuristics, entropy-per-section, SHA256 fingerprint.
- Office analysis: embedded objects, external links, VBA detection, DDE.
- PDF analysis: document metadata + page count, action/stream heuristics.
- File-type detection (`file_type.py`) wired into the analysis pipeline.
- Frontend: `StaticAnalysis.tsx` and `Mitre.tsx` connected to the backend.
- 29 additional pytest tests covering analyzers and the API.

### Changed
- Analysis now runs synchronously during the upload request lifecycle.
- Static analysis results persisted to the investigation record.

---

## 2026-08-09 — Phase 3: Detection & Evidence Engine

### Added
- Deterministic detection layer `backend/app/services/detection/`:
  - `evidence.py` — normalized, deduplicated evidence model (observed vs
    derived vs inferred, never conflated), with type metadata and limits.
  - `ioc.py` — IOC extraction (URL, domain, IP v4/v6, email, hash, registry,
    Windows path, command, mutex) with false-positive controls, defang
    normalization, and provenance-preserving dedup.
  - `rules.py` — 11 detection rules (PowerShell, command shell, downloader,
    network, persistence, obfuscation, sandbox evasion, credential access,
    remote access, masquerading) with confidence and MITRE mapping.
  - `mitre.py` — evidence-backed MITRE ATT&CK aggregation (22 techniques)
    with confidence, severity and provenance; no hardcoded technique lists.
  - `graph.py` — provenance graph (file → evidence → IOC/finding → technique).
  - `__init__.py` — `run_detection(ctx)` orchestration.
- Scoring rewritten in `analysis/score.py`: per-category deduplication, fixed
  weights, entropy bonus, deterministic severity and verdict (malicious /
  suspicious / clean).
- YARA-lite hardening: per-rule/per-file failure isolation, strict hex and
  condition parsing, `any of (...)` / `all of (...)` expansion, and a fix for
  `$`-identifier condition matching.
- New API endpoints: `/findings`, `/iocs`, `/mitre`, `/graph`;
  `/threat-intel` now returns stored IOCs.
- Frontend: `api.ts` clients for the new endpoints; `StaticAnalysis.tsx` and
  `Mitre.tsx` render live detection data with mock fallback.
- 18 additional pytest tests (IOC, detection, scoring, MITRE, failure
  isolation, end-to-end detection API) — 47 tests total.

### Changed
- Orchestrator (`analysis/__init__.py`) now runs detection after static/YARA
  findings, persists `evidence`/`iocs`/`mitre`/`graph`, and computes the score
  from detection findings.
- Docs: `SECURITY_MODULES.md`, `API_DOCUMENTATION.md`, `FEATURES.md`,
  `AI_ENGINE.md`, `PROJECT_WORKFLOW.md`, `CHANGELOG.md` updated for Phase 3.

### Security
- Detection is deterministic and fully local; the sample is never executed.
- Failure isolation: a crashing analyzer or rule never fails the investigation.

### Known issues (not yet fixed)
- `npm run lint` still broken (`eslint` not in devDependencies).
- Report generation remains Phase 7.

---

## 2026-08-10 — Phase 4: AI/Ollama Engine (interpretation only)

### Added
- AI package `backend/app/services/ai/`:
  - `providers.py` — `AIProvider` abstraction + `OllamaProvider` (local Ollama
    REST only, no cloud/paid inference), timeouts, `AIUnavailable` mapping.
  - `prompt.py` — deterministic prompt builder over the Phase 3 output
    (findings, IOCs, MITRE mappings, score) with hard anti-invention rules.
  - `validation.py` — strict JSON schema validation; anti-hallucination guard
    drops any MITRE technique id not present in the deterministic mappings;
    types coerced, sizes bounded, confidence clamped 0–100.
  - `service.py` — `run_ai_analysis(context)` with three stable outcomes:
    `completed` / `unavailable` (Ollama down) / `error` (response rejected).
  - `errors.py` — `AIUnavailable`, `AIValidationError`.
- Config: `ai_model` no longer hard-coded; empty string auto-discovers the
  first installed free model via `GET /api/tags`. Added
  `ai_timeout_seconds` / `ai_probe_timeout_seconds`.
- `/api/investigations/{id}/ai` endpoint: builds the deterministic context,
  runs the AI, caches `completed` results on the stored payload (repeat
  requests instant), never caches unavailable/error so a later-installed
  Ollama is picked up automatically.
- Frontend: `api.ts` `getAiAnalysis`; `AiInvestigation.tsx` renders live
  structured AI output (executive/technical/threat summaries, key findings,
  risk factors, MITRE explanations joined with the deterministic mapping,
  recommendations, confidence, limitations, deterministic score/verdict) with
  mock fallback and a clear "AI analysis unavailable" state.
- 31 additional pytest tests (prompt, validation, provider with mock
  transport, service outcomes, end-to-end `/ai` API with injected provider) —
  **78 tests total**, all passing with no real Ollama installed.

### Changed
- The AI page no longer shows fabricated malware verdicts — it always reflects
  the deterministic analysis and marks AI content as interpretation.
- Docs: `AI_ENGINE.md`, `API_DOCUMENTATION.md` updated for Phase 4.

### Security
- The AI can never: execute the sample, determine the raw score, invent IOCs,
  invent MITRE techniques, claim unobserved runtime behaviour, or override a
  deterministic finding.
- Failure isolation extends to the AI layer: a provider outage, hang, or
  invalid response never blocks or corrupts the investigation.

### Known issues (not yet fixed)
- `npm run lint` still broken (`eslint` not in devDependencies).
- Report generation remains Phase 7.

---

# Versioning Strategy

The project follows **Semantic Versioning (SemVer)**.

```
MAJOR.MINOR.PATCH
```

Example

```
1.0.0
```

Meaning

- **MAJOR** – Breaking architectural changes
- **MINOR** – New features and enhancements
- **PATCH** – Bug fixes and performance improvements

---

# Version 1.0.0 – Prototype Release

**Status:** Current Prototype

## Release Date

To Be Announced

---

## Overview

Version 1.0.0 establishes the foundation of the AI-Powered Intelligent Sandbox. It includes the initial project architecture, frontend dashboard, backend APIs, database integration, and modular design required for future cybersecurity analysis features.

---

## Added

### Frontend

- React application
- Vite project setup
- Tailwind CSS integration
- Responsive dashboard
- Sidebar navigation
- Upload interface
- Investigation page
- Modern UI components

---

### Backend

- FastAPI server
- REST API architecture
- Modular backend structure
- File upload endpoint
- Investigation endpoints
- Database initialization
- API documentation using Swagger

---

### Database

- SQLite integration
- Investigation storage
- Database initialization scripts

---

### Infrastructure

- Docker support
- Docker Compose configuration
- Modular folder structure
- Environment configuration

---

### Documentation

Added comprehensive documentation:

- README.md
- ARCHITECTURE.md
- PROJECT_WORKFLOW.md
- FEATURES.md
- FUTURE_ROADMAP.md
- API_DOCUMENTATION.md
- DATABASE.md
- AI_ENGINE.md
- SECURITY_MODULES.md
- DEPLOYMENT.md
- CHANGELOG.md

---

## Security

Current implementation provides:

- Secure file upload foundation
- Modular security engine architecture
- Preparation for static analysis modules

---

## AI

Current implementation includes:

- AI module architecture
- Planned Ollama integration
- Local AI design
- Explainable AI workflow

---

## Known Limitations

The prototype currently does not include:

- Metadata extraction
- SHA-256 hashing
- Static analysis
- YARA scanning
- IOC extraction
- Threat scoring
- PDF report generation
- Search functionality
- User authentication

These features are planned for future releases.

---

# Version 1.1.0 – Core Security Analysis

**Status:** Planned

## Planned Additions

### Security Analysis

- Metadata extraction
- SHA-256 hash generation
- File type detection
- String extraction
- Entropy analysis

---

### Static Analysis

Support for:

- PE Executables
- PDF files
- Office documents
- Images

---

### Dashboard

- Investigation statistics
- File information cards
- Improved visualizations

---

### Database

Additional tables:

- Metadata
- Hashes
- Static analysis results

---

# Version 1.2.0 – Threat Detection

**Status:** Planned

## Planned Features

- YARA rule matching
- IOC extraction
- Threat score engine
- Digital signature verification
- MITRE ATT&CK mapping

---

## Dashboard

New widgets:

- Threat distribution
- High-risk investigations
- IOC statistics

---

# Version 1.3.0 – AI Integration

**Status:** Planned

## AI Enhancements

- Ollama integration
- Local LLM support
- Executive summaries
- Technical summaries
- Threat explanations
- Analyst recommendations

---

## Supported Models

- Qwen
- DeepSeek
- Llama
- Mistral
- CodeLlama

---

# Version 1.4.0 – Reporting

**Status:** Planned

## Planned Features

- PDF report generation
- Report downloads
- Investigation export
- Executive report templates

---

# Version 1.5.0 – Investigation History

**Status:** Planned

## Planned Features

- Search investigations
- Filter investigations
- Investigation history
- Investigation comparison
- Tagging system

---

# Version 1.6.0 – Threat Intelligence

**Status:** Planned

## Integrations

- VirusTotal
- MalwareBazaar
- AlienVault OTX
- AbuseIPDB

---

# Version 1.7.0 – Advanced Analysis

**Status:** Planned

## New Modules

- APK analysis
- ELF analysis
- Mach-O analysis
- Advanced PDF analysis
- Office macro analysis
- Image metadata analysis

---

# Version 1.8.0 – Collaboration

**Status:** Planned

## Features

- User authentication
- Role-Based Access Control (RBAC)
- Multi-user investigations
- Investigation notes
- Case management

---

# Version 1.9.0 – AI Assistant

**Status:** Planned

## Planned Features

- AI investigation chatbot
- Explainable AI reasoning
- AI-assisted threat hunting
- AI-generated investigation summaries
- AI report writing

---

# Version 2.0.0 – Intelligent Investigation Platform

**Status:** Long-Term Vision

## Major Enhancements

### AI

- Retrieval-Augmented Generation (RAG)
- Local vector database
- Malware family prediction
- AI-generated YARA rules
- AI-assisted Sigma rule generation

---

### Security

- IOC relationship graph
- Threat timeline reconstruction
- Advanced threat scoring
- Threat actor attribution assistance

---

### Enterprise Features

- PostgreSQL support
- Background processing
- Audit logging
- Notifications
- Multi-tenant architecture
- HTTPS deployment
- API authentication

---

# Bug Fix Log

Future bug fixes will be recorded in the following format.

| Version | Issue | Resolution |
|----------|-------|------------|
| 1.0.1 | Example issue | Example fix |

---

# Performance Improvements

Future optimizations may include:

- Faster file uploads
- Optimized database queries
- AI response caching
- Parallel analysis modules
- Improved dashboard rendering
- Reduced memory consumption

---

# Documentation Updates

Documentation will be updated whenever:

- New modules are added
- APIs change
- Database schema changes
- Deployment process changes
- AI models are updated

---

# Upgrade Path

Future releases are designed to maintain compatibility with the existing architecture.

Upgrade order:

```
1.0.0
    │
    ▼
1.1.0
    │
    ▼
1.2.0
    │
    ▼
1.3.0
    │
    ▼
1.4.0
    │
    ▼
2.0.0
```

---

# Contribution Guidelines

When contributing to the project:

- Follow the existing folder structure.
- Maintain modular architecture.
- Document all new features.
- Update API documentation.
- Update database documentation if schemas change.
- Record changes in this changelog.
- Ensure backward compatibility whenever possible.

---

# Project Milestones

| Milestone | Status |
|------------|--------|
| Project Planning | ✅ Completed |
| Prototype Development | ✅ Completed |
| Documentation | ✅ Completed |
| Static Analysis Engine | ✅ Completed |
| Threat Detection Modules | ✅ Completed |
| AI Integration (Ollama) | ✅ Completed |
| Report Generation | 🚧 Planned |
| Dashboard Analytics | 🚧 Planned |
| Threat Intelligence Integration | 📅 Future |
| AI Investigation Assistant | 📅 Future |
| Version 2.0 Release | 🎯 Long-Term Goal |

---

# Summary

The AI-Powered Intelligent Sandbox is being developed through a structured, version-based roadmap that emphasizes modularity, security, and maintainability. Each release introduces focused improvements while preserving compatibility with the existing architecture. This changelog serves as the project's historical record, allowing developers, researchers, and evaluators to track progress, understand feature evolution, and plan future development effectively.