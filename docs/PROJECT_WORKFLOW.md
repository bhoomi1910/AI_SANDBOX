# Project Workflow

## Overview

The AI-Powered Intelligent Sandbox follows a structured investigation workflow designed to safely analyze suspicious files without executing them. Every uploaded file passes through multiple analysis stages, where technical information is collected, security checks are performed, AI generates explanations, and the results are presented through an interactive dashboard.

The workflow is modular, meaning each stage operates independently and can be extended or replaced without affecting the rest of the system.

---

# Investigation Lifecycle

```
User Uploads File
        │
        ▼
File Validation
        │
        ▼
Store File Securely
        │
        ▼
Metadata Extraction
        │
        ▼
Hash Generation
        │
        ▼
File Type Detection
        │
        ▼
Static Analysis
        │
        ▼
YARA Rule Matching
        │
        ▼
Detection & Evidence Engine
(evidence, IOC extraction, correlation, graph)
        │
        ▼
Threat Score Calculation
        │
        ▼
MITRE ATT&CK Mapping
        │
        ▼
AI Analysis (Ollama) — Phase 4
        │
        ▼
Generate Investigation Report
        │
        ▼
Store Investigation
        │
        ▼
Dashboard Visualization
```

---

# Step 1 — File Upload

## Purpose

The investigation begins when a user uploads a suspicious file through the web interface.

The upload module securely transfers the file to the backend for processing.

---

## Supported File Types

Examples include:

- EXE
- DLL
- PDF
- DOCX
- XLSX
- PPTX
- ZIP
- RAR
- APK
- ELF
- Images
- Scripts
- Text Files

Future versions will support additional file formats.

---

## Upload Validation

Before accepting the file, the system validates:

- File size
- File extension
- MIME type
- Empty files
- Duplicate uploads (future)
- Corrupted files

---

# Step 2 — Secure File Storage

## Purpose

After validation, the uploaded file is stored inside a secure upload directory.

The original file remains unchanged throughout the investigation.

No code is executed.

---

## Benefits

- Preserves evidence
- Prevents accidental execution
- Allows repeat analysis
- Enables report regeneration

---

# Step 3 — Metadata Extraction

## Purpose

Metadata provides valuable information about the uploaded file without inspecting its internal code.

Examples include:

- Filename
- File size
- Extension
- MIME type
- Creation date
- Modification date
- Owner
- Permissions

Future versions may extract:

- Digital signatures
- EXIF metadata
- PDF properties
- Office document metadata

---

# Step 4 — Cryptographic Hash Generation

## Purpose

A cryptographic hash uniquely identifies a file.

The hash remains constant unless the file changes.

---

## Generated Hashes

Current

- SHA-256

Future

- MD5
- SHA-1
- SHA-512
- SSDEEP (Similarity Hash)

---

## Why Hashes Matter

They help analysts:

- Identify duplicate files
- Compare malware samples
- Search threat intelligence databases
- Verify file integrity

---

# Step 5 — File Type Detection

## Purpose

The system determines the actual file type instead of relying solely on the file extension.

Example:

```
invoice.pdf.exe

↓

Executable
```

This prevents attackers from disguising malicious files.

---

# Step 6 — Static Analysis

## Purpose

Static analysis inspects the file without executing it.

The analysis depends on the detected file type.

---

## Executables

Possible analysis includes:

- PE Header
- Sections
- Imports
- Exports
- Resources
- Compilation Time
- Suspicious APIs

---

## Office Documents

Possible analysis:

- VBA Macros
- Auto Execution
- Embedded Objects
- External Links

---

## PDF Files

Possible analysis:

- JavaScript
- Embedded Files
- OpenAction
- Encryption
- Launch Actions

---

## Images

Possible analysis:

- EXIF Metadata
- Camera Information
- GPS Data

Future

- Steganography Detection

---

# Step 7 — YARA Rule Matching

## Purpose

The uploaded file is scanned using YARA rules.

YARA helps identify known malware patterns.

---

## Workflow

```
Uploaded File

↓

YARA Rules

↓

Matched Rules

↓

Possible Malware Family

↓

Threat Indicators
```

---

## Benefits

- Signature-based detection
- Fast scanning
- Community-maintained rules
- Easy rule updates

---

# Step 8 — IOC Extraction

## Purpose

Indicators of Compromise (IOCs) are extracted from the file (Phase 3).

## Implemented Types

- URLs
- Domains
- IP Addresses (IPv4 and IPv6)
- Emails
- Registry Keys
- Windows File Paths
- Hashes (MD5, SHA-1, SHA-256)
- Commands
- Mutexes

## Implementation Notes

- Extraction scans normalized evidence **and** the raw string pool (the
  strings classifier alone cannot emit email/hash types).
- False-positive controls: extension-like "TLDs" are rejected (e.g.
  `update.exe`, `kernel32.dll`), IPv4 rejects leading zeros and octets > 255,
  and defanged URLs (`[.]`, `[dot]`) are normalized and restored.
- Deduplication is provenance-preserving: each IOC carries its `sources`,
  a confidence boost per YARA source, and a match `count`.

---

# Step 8.5 — Detection & Evidence Engine (Phase 3)

## Purpose

A deterministic engine between the static analyzers and the AI layer.

## What It Produces

- Normalized evidence (observed vs derived vs inferred, never conflated)
- Correlated, enriched findings with confidence scores
- Evidence-backed MITRE ATT&CK mappings with provenance
- A provenance graph (file → evidence → IOC/finding → technique)

## Design

- Rules fire only when the supporting evidence exists (e.g. a downloader
  needs both a URL and a download primitive).
- Detection results are deterministic and reproducible — no model in the loop.

---

# Step 9 — Threat Score Calculation

## Purpose

The platform assigns a numerical threat score and a verdict based on the
detection engine's findings (Phase 3).

## Scoring Method (deterministic)

- Findings are deduplicated per category: repeated findings in the same
  category count at the category's weight, not once per finding (10 medium
  findings in one category ≠ 70 points).
- Weights: critical 25 / high 15 / medium 7 / low 2 / info 0.
- Entropy bonus: +5 at ≥ 7.5, +3 at ≥ 7.0.
- Severity = worst indicator across the investigation.

## Verdict Rules

| Verdict | Condition |
|---------|-----------|
| Malicious | Total ≥ 60, OR worst indicator is critical |
| Suspicious | Total ≥ 25, OR (worst is high AND total ≥ 15) |
| Clean | Otherwise |

**Example:** three distinct high-severity categories (45 points) → Suspicious,
not Malicious.

---

# Step 10 — AI Analysis

## Purpose

The technical analysis results are provided to a locally hosted AI model through Ollama.

The AI does not directly inspect the file. Instead, it interprets the collected analysis data and generates a human-readable explanation.

---

## AI Responsibilities

- Explain findings
- Summarize investigation
- Identify suspicious behavior
- Recommend analyst actions
- Estimate overall risk
- Generate executive summary

---

## Advantages

- Offline operation
- Privacy-focused
- No cloud dependency
- Fast local inference

---

# Step 11 — MITRE ATT&CK Mapping

## Purpose

The platform maps suspicious behaviors to the MITRE ATT&CK framework
(implemented in Phase 3, evidence-backed).

## How It Works

- Techniques are aggregated from the detection engine's findings, evidence and
  IOCs — never from a hardcoded static list.
- Each technique carries a confidence, the worst observed severity, and
  provenance (which findings/evidence mapped to it).
- Only techniques backed by real evidence are emitted.

Example mappings:

- Initial Access
- Execution
- Persistence
- Credential Access
- Discovery
- Defense Evasion

This helps analysts understand the tactics and techniques associated with the file.

---

## AI Role (Phase 4)

Phase 4's AI layer will only explain these existing mappings. It must not
invent techniques that the deterministic engine did not observe.

---

# Step 12 — Report Generation

## Purpose

The platform generates a professional investigation report summarizing all analysis results.

---

## Report Contents

- Investigation Information
- Metadata
- Hash Values
- Static Analysis
- YARA Matches
- IOC List
- Threat Score
- AI Explanation
- MITRE Mapping
- Recommendations

---

## Export Formats

Current

- PDF

Future

- HTML
- JSON
- CSV
- STIX
- OpenIOC

---

# Step 13 — Store Investigation

## Purpose

The completed investigation is saved to the database.

Stored information includes:

- File Information
- Metadata
- Hashes
- AI Results
- Threat Score
- Report Location
- Investigation Date

---

# Step 14 — Dashboard Visualization

## Purpose

The dashboard presents investigation results in an easy-to-understand format.

---

## Dashboard Components

- Total Investigations
- Recent Uploads
- Threat Score Distribution
- High Risk Files
- File Type Statistics
- Investigation Timeline
- Recent Reports

Future versions may include:

- Heatmaps
- Threat Trends
- MITRE Coverage
- IOC Graphs
- Analyst Activity

---

# Complete Sequence Diagram

```
User
 │
 │ Upload File
 ▼
Frontend
 │
 ▼
FastAPI Backend
 │
 ├── Validate File
 │
 ├── Store File
 │
 ├── Extract Metadata
 │
 ├── Generate SHA-256
 │
 ├── Detect File Type
 │
 ├── Static Analysis
 │
 ├── YARA Scan
 │
 ├── Extract IOCs
 │
 ├── Calculate Threat Score
 │
 ├── Send Results to Ollama
 │
 ├── Generate AI Explanation
 │
 ├── Generate Report
 │
 ├── Store Database Record
 │
 ▼
Frontend Dashboard
 │
 ▼
User Views Investigation
```

---

# Error Handling

The workflow is designed to handle errors gracefully.

Examples include:

- Invalid file format
- Unsupported file type
- Corrupted uploads
- Failed YARA scan
- AI response timeout
- Database errors
- Report generation failure

Each error is logged and returned with an appropriate message without interrupting the entire application.

---

# Future Workflow Enhancements

The investigation pipeline is designed to support future enhancements without requiring major architectural changes.

Planned additions include:

- Batch file analysis
- ZIP archive extraction
- Password-protected archive support
- VirusTotal enrichment
- MalwareBazaar integration
- Sigma rule matching
- AI-generated YARA rules
- PCAP analysis
- Memory dump analysis
- APK analysis
- ELF analysis
- Mach-O analysis
- Investigation collaboration
- AI chatbot for investigation queries
- Scheduled analysis jobs
- Background task processing
- Real-time progress updates
- Multi-user case management

---

# Summary

The investigation workflow combines traditional static analysis techniques with AI-assisted interpretation to create a safe, explainable, and extensible cybersecurity investigation platform. By avoiding dynamic execution and focusing on offline analysis, the platform remains suitable for educational environments while providing valuable insights into suspicious files. Its modular design ensures that additional analysis modules and future integrations can be incorporated with minimal changes to the existing workflow.