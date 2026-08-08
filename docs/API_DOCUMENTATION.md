# API Documentation

## Overview

The AI-Powered Intelligent Sandbox follows a RESTful API architecture that enables seamless communication between the React frontend and the FastAPI backend. Every user action—such as uploading a file, viewing an investigation, or generating a report—is performed through secure HTTP requests.

The API layer acts as the bridge between the presentation layer and the backend services, ensuring that business logic, security analysis, and data persistence remain independent from the user interface.

---

# API Architecture

```
React Frontend
        │
        │ HTTP/HTTPS
        ▼
+----------------------+
|    FastAPI Server    |
+----------------------+
        │
        ├───────────────┐
        │               │
        ▼               ▼
 Security Engine     AI Engine
        │               │
        └──────┬────────┘
               │
               ▼
          SQLite Database
```

---

# API Design Principles

The backend APIs follow several design principles:

- RESTful architecture
- JSON request and response format
- Stateless communication
- Modular endpoints
- Version-ready structure
- Consistent error responses
- Easy integration with future mobile or desktop clients

---

# Base URL

Development

```
http://localhost:8000
```

Future Production

```
https://sandbox.company.com/api/v1
```

---

# API Versioning

Current Version

```
v1
```

Future versions will follow:

```
/api/v1/
/api/v2/
/api/v3/
```

This prevents breaking existing frontend applications.

---

# Authentication

## Current Prototype

No authentication.

Suitable for local development and academic demonstration.

---

## Future

JWT Authentication

OAuth2

Role-Based Access Control

API Keys

Refresh Tokens

Session Management

---

# Request Format

Example

```http
POST /upload
Content-Type: multipart/form-data
```

---

# Response Format

Every successful response follows a standard structure.

```json
{
    "success": true,
    "message": "Operation completed successfully.",
    "data": {}
}
```

---

# Error Response

```json
{
    "success": false,
    "error": "Invalid file type.",
    "status": 400
}
```

---

# API Modules

The API is divided into independent modules.

```
Upload API

Investigation API

Analysis API

AI API

Report API

History API

Dashboard API

Authentication API (Future)

Settings API (Future)
```

---

# Upload API

## Upload File

### Endpoint

```
POST /upload
```

---

### Purpose

Uploads a suspicious file for investigation.

---

### Request

Multipart Form Data

```
file
```

---

### Response

```json
{
    "investigation_id": 101,
    "filename": "sample.exe",
    "status": "Uploaded"
}
```

---

### Possible Responses

| Code | Description |
|-------|-------------|
|200|Upload Successful|
|400|Invalid File|
|413|File Too Large|
|500|Server Error|

---

# Investigation API

## Get All Investigations

### Endpoint

```
GET /api/investigations
```

Returns every investigation.

---

### Example Response

```json
[
    {
        "id":1,
        "filename":"invoice.exe",
        "score":82,
        "status":"Completed"
    }
]
```

---

## Investigation Details

### Endpoint

```
GET /api/investigations/{id}
```

Returns complete investigation information.

---

## Static Analysis

### Endpoint

```
GET /api/investigations/{id}/static
```

Returns the stored analysis payload: file type, `static` (strings, YARA,
sections, imports, capabilities, metadata), `findings`, `score`, `evidence`,
`iocs`, `mitre`, `graph`, `classification`, `tags`, `modules` and the module
health map.

---

## Findings (Phase 3)

### Endpoint

```
GET /api/investigations/{id}/findings
```

Returns derived findings: analyzer findings enriched with `confidence`,
`mitre` and `evidence_ids`, plus rule-correlated detections, de-duplicated for
display.

```json
{
  "status": "completed",
  "investigation": "INV-2026-0001",
  "findings": [
    {
      "severity": "high",
      "category": "powershell",
      "title": "PowerShell execution with obfuscation/execution primitives",
      "confidence": 0.85,
      "mitre": "T1059.001",
      "mitre_techniques": ["T1059.001"],
      "evidence_ids": ["ev-0002", "ev-0003"],
      "module": "detection:powershell"
    }
  ]
}
```

---

## IOCs (Phase 3)

### Endpoint

```
GET /api/investigations/{id}/iocs
```

Returns de-duplicated indicators with source provenance.

```json
{
  "status": "completed",
  "investigation": "INV-2026-0001",
  "iocs": [
    {
      "id": "ioc-0001",
      "type": "url",
      "value": "http://evil.example/payload.bin",
      "severity": "medium",
      "confidence": 0.83,
      "sources": [
        {"module": "strings", "evidence_id": "ev-0002", "context": "http://evil.example/payload.bin"}
      ],
      "count": 2,
      "mitre_techniques": ["T1071"]
    }
  ]
}
```

---

## MITRE ATT&CK (Phase 3)

### Endpoint

```
GET /api/investigations/{id}/mitre
```

Returns evidence-backed technique mappings.

```json
{
  "status": "completed",
  "investigation": "INV-2026-0001",
  "techniques": [
    {
      "technique_id": "T1055",
      "technique": "Process Injection",
      "tactic": "Defense Evasion",
      "confidence": 0.9,
      "severity": "high",
      "source_modules": ["pe"],
      "findings": ["Process injection APIs imported"],
      "evidence": ["VirtualAllocEx + WriteProcessMemory"],
      "provenance": {"finding_count": 1, "source_modules": ["pe"], "evidence_observed": []}
    }
  ]
}
```

---

## Investigation Graph (Phase 3)

### Endpoint

```
GET /api/investigations/{id}/graph
```

Returns the provenance graph: `nodes` (file / evidence / ioc / finding /
technique) and typed `edges` (`contains`, `indicates`, `yields`,
`supported_by`, `maps_to`).

```json
{
  "status": "completed",
  "graph": {
    "nodes": [{"id": "file:abc…", "kind": "file", "label": "update.ps1", "severity": "info"}],
    "edges": [{"source": "file:abc…", "target": "ev-0001", "type": "contains"}],
    "stats": {"evidence": 8, "findings": 4, "iocs": 7, "techniques": 4}
  }
}
```

---

## Threat Intel

### Endpoint

```
GET /api/investigations/{id}/threat-intel
```

Phase 3 returns the deterministic IOC list. External threat-intel feeds are
future work.

```
GET /api/investigations/{id}/ai
```

AI deep-dive returns `unavailable` until the Phase 4 engine is configured.

---

## Delete Investigation

Future

```
DELETE /investigations/{id}
```

---

## Search Investigations

Future

```
GET /investigations/search
```

Search by

- Hash
- Filename
- Threat Score
- Date
- File Type

---

# Metadata API

Future Module

---

## Extract Metadata

```
POST /metadata
```

Returns

- Size
- MIME Type
- Extension
- Created Time
- Modified Time
- Permissions

---

# Hash API

Future Module

---

## Generate Hash

```
POST /hash
```

Returns

```json
{
    "sha256":"..."
}
```

Future

- MD5
- SHA1
- SHA512

---

# Static Analysis API

Future Module

---

## Analyze File

```
POST /analysis/static
```

Returns

- PE Information
- Strings
- Entropy
- Suspicious Imports

---

# YARA API

Future Module

---

## Scan File

```
POST /analysis/yara
```

Returns

```json
{
    "matched_rules":[]
}
```

---

# IOC API

Implemented in Phase 3 — see `GET /api/investigations/{id}/iocs` above.

---

# Threat Score API

Implemented — the threat score is computed by the scoring engine and returned
inside `GET /api/investigations/{id}/static` (the `score` object with
`total`, `severity`, `verdict` and `breakdown`).

# AI Analysis API

## AI Investigation

```
POST /analysis/ai
```

Uses

- Ollama
- Local LLM

Returns

- Executive Summary
- Technical Summary
- Threat Explanation
- Recommendations

---

### Example

```json
{
    "summary":"The uploaded executable contains suspicious API imports...",
    "risk":"High",
    "recommendation":"Investigate before execution."
}
```

---

# MITRE Mapping API

Implemented in Phase 3 — see `GET /api/investigations/{id}/mitre` above.

Returns evidence-backed mappings with technique ID, name, tactic, confidence,
severity and provenance.

# Report API

## Generate Report

```
POST /reports/generate
```

---

Returns

PDF location

```json
{
    "report":"reports/report_101.pdf"
}
```

---

## Download Report

```
GET /reports/{id}
```

---

# Dashboard API

## Statistics

```
GET /dashboard/stats
```

Returns

- Total Investigations
- High Risk Files
- Safe Files
- Recent Uploads

---

## Dashboard Charts

Future

```
GET /dashboard/charts
```

Returns chart-ready JSON.

---

# History API

Future

```
GET /history
```

Returns previous investigations.

---

# Search API

Future

```
GET /search
```

Supported

- Filename
- Hash
- IOC
- Threat Score
- Date

---

# Health Check API

```
GET /health
```

Response

```json
{
    "status":"healthy"
}
```

Used by Docker and deployment systems.

---

# Error Codes

| Code | Meaning |
|-------|----------|
|200|Success|
|201|Created|
|400|Bad Request|
|401|Unauthorized|
|403|Forbidden|
|404|Not Found|
|413|Payload Too Large|
|422|Validation Error|
|500|Internal Server Error|

---

# API Workflow Example

```
User Uploads File

↓

POST /upload

↓

File Stored

↓

POST /analysis/static

↓

POST /analysis/yara

↓

POST /analysis/ai

↓

POST /reports/generate

↓

GET /investigations/{id}

↓

Dashboard Updated
```

---

# Security Considerations

The API follows several security practices:

- Input validation
- File size validation
- MIME type verification
- Request validation using Pydantic
- Secure file storage
- No direct execution of uploaded files
- Consistent error handling
- Future JWT authentication
- Future rate limiting
- Future HTTPS enforcement

---

# Future API Enhancements

Planned additions include:

- JWT Authentication
- Role-Based Access Control (RBAC)
- Background analysis jobs
- WebSocket live progress updates
- Batch file upload APIs
- Investigation comparison API
- Threat intelligence APIs
- AI chat endpoint
- Plugin management API
- Audit log API
- Notification API
- Webhook support
- GraphQL gateway (optional)

---

# OpenAPI & Swagger

Since the backend is built with FastAPI, interactive API documentation is automatically generated.

Swagger UI

```
http://localhost:8000/docs
```

ReDoc

```
http://localhost:8000/redoc
```

These interfaces allow developers to explore endpoints, submit test requests, and inspect request and response schemas without additional tooling.

---

# Summary

The REST API is the communication backbone of the AI-Powered Intelligent Sandbox. It provides a modular, scalable, and secure interface between the frontend, security analysis engine, AI services, and database. The API-first design ensures that future clients—including web, desktop, or mobile applications—can integrate with the platform while maintaining a consistent and extensible architecture.