<div align="center">

# 🛡️ Aegis Sandbox AI

### AI-Powered Interactive Malware Analysis & Threat Investigation Platform

*An MSc Cyber Security demonstration prototype — a high-fidelity working model of a modern SOC malware-analysis product.*

`React` · `TypeScript` · `Vite` · `TailwindCSS` · `FastAPI` · `PostgreSQL` · `Docker` · `LangChain / RAG`

</div>

---

## 📌 What is this?

**Aegis Sandbox AI** lets a SOC analyst upload a suspicious file, detonate it in an isolated
sandbox, and receive a complete, AI-reasoned threat investigation — static analysis, dynamic
behaviour, network activity, threat-intel enrichment, MITRE ATT&CK mapping, an explainable AI
verdict, and an exportable investigation report.

It is designed to demonstrate the **complete analyst workflow** end-to-end. Real malware
detonation is optional; where a live sandbox/API is unavailable the platform serves
**high-fidelity simulated data** so the entire journey is fully demonstrable offline.

> **Scope note:** This is a *prototype for demonstration*, not a production security product.
> It intentionally ships believable simulated results so a mentor can see exactly what the
> production system becomes.

---

## 🎯 The Workflow

```
  Login ──▶ Dashboard ──▶ Upload Sample ──▶ Investigation Queue
                                                    │
        ┌───────────────────────────────────────────┘
        ▼
  Static Analysis ──▶ Dynamic Analysis ──▶ Network Analysis
        │
        ▼
  Threat Intelligence ──▶ MITRE ATT&CK ──▶ 🤖 AI Investigation ──▶ 📄 Report (PDF)
```

---

## ✨ Features

| Module | Highlights |
|--------|-----------|
| **Dashboard** | KPI tiles with sparklines, 30-day detection trend, malware-family donut, severity distribution, live threat feed, system health, AI engine card |
| **Upload** | Drag-and-drop with animated scan effect, real hashing, simulated analysis pipeline, supports `.exe .dll .pdf .docx .zip .iso` |
| **Investigation Queue** | Live status (queued → running → analysing → AI-processing → completed), filters, search, progress bars |
| **Static Analysis** | SHA-256/MD5, entropy gauge, compiler/packer, PE sections, imports, searchable strings, YARA hits, VirusTotal lookup |
| **Dynamic Analysis** | Simulated sandbox VM screen, behaviour timeline, process tree, registry, filesystem, mutexes, persistence, API calls |
| **Network Analysis** | Animated C2 world map, DNS/HTTP(S) tables, geolocated connections, packet timeline |
| **Threat Intelligence** | VirusTotal, AlienVault OTX, AbuseIPDB, MITRE, CVE, Hybrid Analysis enrichment + IOC table |
| **MITRE ATT&CK** | Kill-chain flow + interactive technique matrix with evidence drawer |
| **AI Investigation** ⭐ | Typewriter verdict, confidence gauges, what-it-does / why-dangerous, reconstructed attack chain, business impact, explainable reasoning trace, recommended actions |
| **Report** | Formatted investigation report with Executive Summary, timeline, risk score, IOCs, MITRE, recommendations, **Export PDF** (print) |

Dark theme · Framer Motion animations · responsive · loading & skeleton states · accessible focus states.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              FRONTEND (SPA)                                │
│   React + TypeScript + Vite + Tailwind + shadcn-style UI                   │
│   React Router · TanStack Query · Recharts · Framer Motion · Lucide        │
│   Runs fully on a local mock-data layer (no backend required for demo)     │
└───────────────────────────────┬──────────────────────────────────────────┘
                                 │  REST /api  (optional)
┌───────────────────────────────▼──────────────────────────────────────────┐
│                         BACKEND — FastAPI (Python)                         │
│   Routers: dashboard · investigations · samples · health                   │
│   SQLAlchemy models · Pydantic schemas                                     │
│   AI engine (deterministic simulator ⇄ LangChain + FAISS + LLM)            │
└─────────┬───────────────────────┬───────────────────────┬────────────────┘
          │                       │                       │
    ┌─────▼─────┐          ┌──────▼──────┐         ┌───────▼────────┐
    │PostgreSQL │          │    Redis    │         │  Sandbox layer │
    │ (schema)  │          │Celery broker│         │ CAPE / Cuckoo  │
    └───────────┘          └─────────────┘         │  (simulated)   │
                                                    └────────────────┘
```

**AI pipeline (production):** static + dynamic + network signals → RAG retrieval over a
FAISS vector index of historical malware behaviours → LangChain prompt → OpenAI/Claude-compatible
LLM → structured, explainable verdict. The prototype ships a **deterministic simulator** so it
runs with **zero API keys**.

---

## 📁 Project Structure

```
AI SANDBOX/
├── frontend/                 # React + TypeScript + Vite SPA
│   ├── src/
│   │   ├── components/       # ui/ (shadcn-style) · layout/ · shared/
│   │   ├── pages/            # Login, Dashboard, Upload, Queue, analysis/*
│   │   ├── data/             # Mock data layer (types, investigations, deep-dive)
│   │   ├── lib/              # utils, nav config
│   │   └── index.css         # Design system / theme tokens
│   ├── tailwind.config.js
│   ├── Dockerfile · nginx.conf
│   └── package.json
├── backend/                  # FastAPI service
│   ├── app/
│   │   ├── main.py           # App entrypoint + routers
│   │   ├── config.py         # Settings (env-driven)
│   │   ├── routers/          # dashboard · investigations · upload
│   │   ├── data/mock_data.py # Simulated SOC dataset
│   │   └── ai/engine.py      # AI verdict engine (simulator ⇄ LLM)
│   ├── requirements.txt
│   └── Dockerfile
├── database/
│   └── init.sql              # PostgreSQL schema + seed
├── scripts/                  # Convenience run scripts (Windows + Linux)
├── docker-compose.yml        # Full-stack topology
├── steps.txt                 # Beginner-friendly setup & run guide
└── README.md
```

---

## 🚀 Quick Start

The fastest path — **frontend only** (self-contained, mock data, no backend needed):

```bash
cd frontend
npm install
npm run dev
# open http://localhost:5173  → click "Access console"
```

Full stack with Docker:

```bash
docker compose up --build
# frontend → http://localhost:8080
# backend  → http://localhost:8000/docs
```

➡️ **See [`steps.txt`](./steps.txt) for the complete, beginner-friendly setup guide**
(software versions, Windows + Linux, environment variables, troubleshooting).

---

## 🖼️ Screenshots

> _Add screenshots / a screen recording here for your presentation._

| | |
|---|---|
| `docs/screenshots/dashboard.png` — SOC Dashboard | `docs/screenshots/ai.png` — AI Investigation |
| `docs/screenshots/dynamic.png` — Dynamic Analysis | `docs/screenshots/network.png` — C2 Map |
| `docs/screenshots/mitre.png` — ATT&CK Matrix | `docs/screenshots/report.png` — Report |

---

## 🔭 Future Scope

- **Real sandbox integration** — wire CAPE/Cuckoo for live detonation and PCAP capture.
- **Live threat-intel connectors** — VirusTotal, OTX, AbuseIPDB, MISP with API keys.
- **Production LLM pipeline** — enable LangChain + FAISS RAG over a real behaviour corpus.
- **Automated IR playbooks** — SOAR-style containment actions and ticketing (Jira/ServiceNow).
- **Multi-tenant RBAC & SSO** — SAML/OIDC, per-role dashboards for the five user personas.
- **YARA/Sigma rule authoring** — in-app rule editor with backtesting.
- **Historical hunting & clustering** — sample similarity graph, campaign attribution.
- **Real-time collaboration** — shared case notes, analyst hand-off, audit trail.

---

## ⚠️ Known Limitations

- Analysis data for the deep-dive pages is **simulated** for the featured case (`AGS-2026-0412`);
  it demonstrates fidelity, not live detonation.
- Authentication is a **demo gate** (no real identity provider) — any credentials pass.
- The AI verdict uses a **deterministic simulator** by default (no LLM call).
- Threat-intel figures are representative mock values unless real API keys are supplied.
- Frontend and backend both carry their own copy of the mock dataset so each runs standalone;
  in production this is a single source of truth in PostgreSQL.

---

## 🧑‍🎓 About

Built as an **MSc Cyber Security** project prototype to demonstrate the complete design and
user experience of an AI-assisted malware-analysis SOC platform.

**Primary user:** SOC Analyst · **Secondary:** Malware Analyst, Threat Hunter, Incident Response, SOC Manager.

<div align="center">
<sub>Aegis Sandbox AI — demonstration prototype. Not for production security use.</sub>
</div>
