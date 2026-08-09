# AI-Powered Intelligent Sandbox for Secure File Analysis using Artificial Intelligence

> An AI-assisted cybersecurity investigation platform for secure, offline file analysis using static analysis techniques, YARA rules, local Large Language Models (LLMs), and intelligent reporting.

---

# Project Overview

The AI-Powered Intelligent Sandbox is an educational cybersecurity investigation platform designed to help users safely analyze suspicious files without executing them.

Unlike traditional malware sandboxes that execute malicious software inside isolated virtual machines, this project focuses on **safe static analysis** combined with **Artificial Intelligence** to assist analysts in understanding potentially malicious files.

The platform extracts metadata, calculates cryptographic hashes, performs static analysis, scans files using YARA rules, leverages a locally hosted AI model through Ollama to generate human-readable explanations, assigns a threat score, and generates professional investigation reports.

This project is being developed as a **Bachelor of Engineering (BE) Major Project** and is intended for educational, research, and cybersecurity learning purposes.

---

# Problem Statement

Security analysts frequently encounter suspicious files received through email attachments, downloads, USB devices, or other sources. Traditional antivirus software often provides only a binary verdict (malicious or safe), offering little insight into why a file is considered dangerous.

Enterprise malware sandboxes such as CAPE, Cuckoo Sandbox, or Any.Run provide detailed analysis but require significant infrastructure, virtualization, and advanced configuration, making them unsuitable for educational environments.

There is a need for a lightweight, AI-assisted platform that enables users to understand suspicious files through static analysis, explainable AI, and cybersecurity techniques without executing potentially harmful code.

---

# Project Objectives

- Develop a secure platform for analyzing suspicious files.
- Perform static file analysis without executing uploaded files.
- Generate cryptographic hashes for file identification.
- Extract metadata from multiple file formats.
- Detect known threats using YARA rules.
- Use a locally hosted AI model for intelligent threat explanation.
- Generate understandable investigation reports.
- Maintain investigation history.
- Visualize analysis results through an interactive dashboard.
- Provide an extensible architecture for future cybersecurity research.

---

# Key Features

### Current Prototype

- Modern React Dashboard
- Secure File Upload
- Investigation Management
- FastAPI Backend
- SQLite Database
- REST APIs
- Docker Support
- AI Module Foundation

### Planned Features

- Metadata Extraction
- SHA-256 Hash Generation
- Static File Analysis
- YARA Rule Matching
- AI Threat Explanation
- Threat Scoring
- IOC Extraction
- MITRE ATT&CK Mapping
- PDF Report Generation
- Investigation History
- Dashboard Analytics
- Search & Filtering
- Local LLM Integration using Ollama

---

# Technology Stack

## Frontend

- React
- Vite
- Tailwind CSS
- React Router
- Axios
- Recharts

## Backend

- Python
- FastAPI
- SQLAlchemy
- Pydantic
- Uvicorn

## Database

- SQLite (Current)
- PostgreSQL (Future)

## Artificial Intelligence

- Ollama
- Local Open-Source LLMs
- Prompt Engineering

Supported models include:

- Qwen
- DeepSeek
- Llama
- Mistral
- CodeLlama

## Cybersecurity Libraries

- hashlib
- python-magic
- pefile
- yara-python
- oletools
- pdfid
- pdf-parser
- ssdeep
- ExifTool
- LIEF

## Reporting

- ReportLab

## Deployment

- Docker
- Docker Compose

---

# System Architecture

```
                User

                  │

                  ▼

        React Frontend (Vite)

                  │

                  ▼

        FastAPI Backend APIs

                  │

      ┌───────────┼───────────┐
      │           │           │

      ▼           ▼           ▼

 Metadata    Static Scan   AI Engine

      │           │           │

      └──────┬────┴─────┬─────┘
             │          │

             ▼          ▼

       SQLite Database

             │

             ▼

      Dashboard & Reports
```

---

# Investigation Workflow

```
Upload File

↓

Metadata Extraction

↓

SHA-256 Generation

↓

Static Analysis

↓

YARA Rule Matching

↓

AI Threat Analysis

↓

Threat Score Calculation

↓

Generate Report

↓

Store Investigation

↓

Dashboard Visualization
```

---

# Repository Structure

```
README.md

docs/
│── ARCHITECTURE.md
│── PROJECT_WORKFLOW.md
│── FEATURES.md
│── FUTURE_ROADMAP.md
│── API_DOCUMENTATION.md
│── DATABASE.md
│── AI_ENGINE.md
│── SECURITY_MODULES.md
│── DEPLOYMENT.md
│── CHANGELOG.md

frontend/

backend/

database/

docker/

reports/

uploads/

yara_rules/
```

---

# Documentation

Detailed documentation is available inside the **docs** directory.

| Document | Description |
|----------|-------------|
| ARCHITECTURE.md | Overall system architecture |
| PROJECT_WORKFLOW.md | Complete investigation workflow |
| FEATURES.md | Current and planned features |
| FUTURE_ROADMAP.md | Development roadmap |
| API_DOCUMENTATION.md | Backend API reference |
| DATABASE.md | Database schema |
| AI_ENGINE.md | Local AI engine architecture |
| SECURITY_MODULES.md | Security analysis modules |
| DEPLOYMENT.md | Installation and deployment |
| CHANGELOG.md | Development history |

---

# Current Development Status

| Module | Status |
|---------|--------|
| Frontend Dashboard | Completed |
| Backend APIs | Completed |
| Database | Completed |
| File Upload | Completed |
| Investigation Page | Completed |
| AI Module | Completed (Ollama, local-only, interpretation only) |
| Metadata Extraction | Planned |
| Hash Generation | Planned |
| Static Analysis | Planned |
| YARA Integration | Planned |
| AI Threat Explanation | Planned |
| PDF Reports | Planned |
| Dashboard Analytics | Planned |

---

# Future Vision

The project aims to evolve into a comprehensive AI-assisted cybersecurity investigation platform capable of analyzing multiple file types, correlating indicators of compromise, generating explainable AI reports, integrating threat intelligence, and supporting collaborative investigations while maintaining an educational and research-focused design.

---

# Disclaimer

This project is intended for educational, research, and cybersecurity learning purposes only. It does not execute uploaded files or attempt to replace enterprise malware sandbox solutions. Users should analyze potentially malicious files only in secure and controlled environments.

---

# License

This project is developed as part of a Bachelor of Engineering (BE) Major Project.

Future licensing will be determined upon public release.