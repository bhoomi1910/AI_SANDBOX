# System Architecture

## Overview

The AI-Powered Intelligent Sandbox is designed using a modular client-server architecture. Each major component has a dedicated responsibility, allowing the system to be scalable, maintainable, and easy to extend with future cybersecurity capabilities.

The architecture separates the user interface, business logic, security analysis, artificial intelligence, and data storage into independent modules that communicate through REST APIs.

---

# Architecture Goals

The architecture is designed with the following objectives:

- Modular and maintainable codebase
- Secure file handling
- AI-assisted investigation workflow
- Easy integration of new cybersecurity modules
- Separation of concerns
- Scalable backend services
- Extensible AI framework
- Offline-first design using local AI models

---

# High-Level Architecture

```
                    +----------------------+
                    |       User           |
                    +----------+-----------+
                               |
                               |
                     Web Browser (React)
                               |
                               |
                    +----------v-----------+
                    |  React + Vite Frontend|
                    +----------+-----------+
                               |
                      REST API Requests
                               |
                               |
                    +----------v-----------+
                    |   FastAPI Backend    |
                    +----------+-----------+
                               |
          +--------------------+--------------------+
          |                    |                    |
          |                    |                    |
+---------v--------+  +--------v---------+  +-------v--------+
| Security Engine  |  |    AI Engine     |  | Database Layer |
+---------+--------+  +--------+---------+  +-------+--------+
          |                    |                    |
          |                    |                    |
          |              Ollama LLM                SQLite
          |                    |
          +--------------------+
                    |
                    |
            Analysis Results
                    |
                    |
           Dashboard & Reports
```

---

# System Components

The system is divided into five primary layers:

1. Frontend Layer
2. Backend Layer
3. Security Analysis Layer
4. Artificial Intelligence Layer
5. Data Storage Layer

Each layer has a clearly defined responsibility.

---

# Frontend Layer

## Purpose

The frontend provides a user-friendly interface for interacting with the sandbox.

It allows users to upload files, view investigation results, generate reports, and monitor analysis history.

---

## Technologies

- React
- Vite
- Tailwind CSS
- React Router
- Axios
- Recharts

---

## Responsibilities

- User Interface
- File Upload
- Dashboard
- Investigation History
- Report Download
- API Communication
- Data Visualization

---

# Backend Layer

## Purpose

The backend coordinates the complete investigation workflow.

It receives uploaded files, invokes the required security modules, stores results, and returns analysis to the frontend.

---

## Technologies

- Python
- FastAPI
- SQLAlchemy
- Pydantic
- Uvicorn

---

## Responsibilities

- REST API
- File Management
- Investigation Management
- Database Operations
- AI Integration
- Report Generation
- Security Module Coordination

---

# Security Analysis Layer

## Purpose

This layer performs all technical analysis on uploaded files.

No uploaded file is executed.

Instead, the file is inspected using static analysis techniques.

---

## Responsibilities

- Metadata Extraction
- SHA-256 Hash Generation
- File Type Detection
- PE Analysis
- Office Document Analysis
- PDF Analysis
- String Extraction
- Entropy Analysis
- Digital Signature Verification
- YARA Rule Matching
- IOC Extraction

---

# Artificial Intelligence Layer

## Purpose

The AI Engine assists analysts by explaining technical findings in human-readable language.

Instead of making security decisions automatically, the AI provides contextual explanations and recommendations based on the analysis results.

---

## AI Framework

The project uses:

- Ollama
- Local Open-Source LLMs

Supported models include:

- Qwen
- DeepSeek
- Llama
- Mistral
- CodeLlama

---

## AI Responsibilities

- Threat Explanation
- Executive Summary
- Technical Summary
- Risk Assessment
- Analyst Recommendations
- Report Enhancement
- MITRE ATT&CK Suggestions
- IOC Interpretation

---

# Database Layer

## Purpose

The database stores all investigations and generated analysis.

The current prototype uses SQLite for simplicity and portability.

Future versions may support PostgreSQL.

---

## Stored Information

- Investigation Records
- Uploaded File Metadata
- Cryptographic Hashes
- Threat Scores
- AI Analysis
- YARA Matches
- Generated Reports
- Investigation History

---

# Internal Module Architecture

```
Frontend

│

├── Dashboard

├── Upload

├── Investigations

├── Reports

└── Settings



Backend

│

├── API

├── Database

├── Models

├── Schemas

├── Services

│      ├── Metadata

│      ├── Hashing

│      ├── Static Analysis

│      ├── YARA

│      ├── AI Engine

│      ├── Reports

│      └── Threat Scoring

└── Utilities
```

---

# Request Flow

```
User Uploads File

↓

React Upload Component

↓

FastAPI Upload Endpoint

↓

Store Uploaded File

↓

Metadata Extraction

↓

Generate Hash

↓

Static Analysis

↓

YARA Scan

↓

AI Analysis (Ollama)

↓

Threat Score

↓

Save Investigation

↓

Return Results

↓

Frontend Dashboard
```

---

# Data Flow

```
Upload File

↓

File Storage

↓

Security Modules

↓

AI Engine

↓

Database

↓

REST API

↓

Dashboard

↓

PDF Report
```

---

# Design Principles

The project follows several software engineering principles to ensure long-term maintainability.

## Separation of Concerns

Each module has a single responsibility.

Examples:

- Upload module handles file uploads only.
- AI module performs AI processing only.
- Security module performs technical analysis only.

---

## Modular Design

Every feature is implemented as an independent service.

This allows future modules to be added without affecting existing functionality.

---

## Scalability

Although the prototype uses SQLite, the architecture supports migration to PostgreSQL or other relational databases with minimal code changes.

---

## Extensibility

Future cybersecurity modules such as VirusTotal integration, memory analysis, APK analysis, and PCAP analysis can be added without redesigning the system.

---

## Security

The platform is designed with security in mind.

Key principles include:

- No execution of uploaded files
- Secure file storage
- Hash verification
- Local AI processing
- Offline analysis
- Modular validation

---

# Architectural Advantages

The chosen architecture provides several benefits:

- Lightweight
- Easy to understand
- Educational
- Research-friendly
- Modular
- AI-assisted
- Scalable
- Secure
- Docker-compatible
- Cross-platform

---

# Current Architecture Status

| Component | Status |
|----------|--------|
| React Frontend | ✅ Implemented |
| FastAPI Backend | ✅ Implemented |
| REST APIs | ✅ Implemented |
| SQLite Database | ✅ Implemented |
| Docker Support | ✅ Implemented |
| Upload Module | ✅ Implemented |
| Dashboard | ✅ Implemented |
| AI Module | 🔄 Prototype |
| Security Modules | 🚧 Under Development |

---

# Future Architecture Enhancements

The architecture is intentionally designed to support future enhancements without requiring major restructuring.

Planned architectural improvements include:

- PostgreSQL support
- Multi-user authentication
- Role-Based Access Control (RBAC)
- Threat Intelligence Integration
- AI Chat Assistant
- Investigation Collaboration
- Distributed Analysis Workers
- Background Task Queue (Celery/RQ)
- Elasticsearch-based Search
- Vector Database for AI Knowledge
- Plugin System for Security Modules
- Containerized Analysis Workers
- Kubernetes Deployment
- Cloud Storage Support
- WebSocket-based Live Analysis Updates

---

# Summary

The AI-Powered Intelligent Sandbox adopts a modular, layered architecture that separates presentation, business logic, security analysis, artificial intelligence, and persistence into independent components. This design simplifies development, supports future expansion, and provides a solid foundation for building an educational AI-assisted cybersecurity investigation platform while remaining suitable for real-world software engineering practices.