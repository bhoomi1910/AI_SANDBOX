# Security Modules

## Overview

The Security Engine is the core component of the AI-Powered Intelligent Sandbox. It is responsible for performing all cybersecurity-related analysis on uploaded files before the results are interpreted by the AI Engine.

Unlike traditional malware sandboxes that execute suspicious files inside virtual machines, this platform performs **safe static analysis**, ensuring that potentially malicious files are never executed during the investigation process.

The Security Engine consists of multiple independent modules that work together to identify suspicious characteristics, extract useful information, and generate evidence for AI-assisted analysis.

---

# Security Engine Architecture

```
                    Uploaded File
                          │
                          ▼
                File Validation Module
                          │
                          ▼
               File Type Detection Module
                          │
                          ▼
                  Metadata Extraction
                          │
                          ▼
                Cryptographic Hashing
                          │
                          ▼
                  Static Analysis
                          │
                          ▼
                  String Extraction
                          │
                          ▼
                    YARA Scanner
                          │
                          ▼
                 IOC Extraction Module
                          │
                          ▼
               Threat Score Calculation
                          │
                          ▼
                     AI Engine
```

---

# Module Overview

| Module | Purpose |
|---------|---------|
| File Validation | Validate uploaded files |
| File Type Detection | Identify actual file type |
| Metadata Extraction | Collect file information |
| Cryptographic Hashing | Generate unique file hashes |
| Static Analysis | Inspect internal structure |
| String Extraction | Extract readable strings |
| Entropy Analysis | Detect packed or encrypted files |
| Digital Signature Verification | Validate certificates |
| YARA Rule Matching | Detect known malware patterns |
| IOC Extraction | Identify Indicators of Compromise |
| Threat Scoring | Calculate overall risk |

---

# File Validation Module

## Purpose

The File Validation module ensures that uploaded files are suitable for analysis before they enter the investigation pipeline.

---

## Validation Checks

- Empty file detection
- Maximum file size
- Supported file formats
- MIME type verification
- Corrupted file detection
- Duplicate file detection (Future)

---

## Benefits

- Prevents invalid uploads
- Protects backend services
- Improves investigation reliability

---

# File Type Detection

## Purpose

Attackers frequently disguise malicious files by changing their extensions.

Example:

```
invoice.pdf.exe
```

Instead of trusting the filename, the platform determines the real file type using file signatures (magic bytes).

---

## Supported File Types

Current

- Executables
- Documents
- PDFs
- Images
- Archives
- Scripts

Future

- APK
- ELF
- Mach-O
- ISO
- Memory Dumps

---

# Metadata Extraction

## Purpose

Collect metadata without executing the file.

---

## Information Collected

- File Name
- Extension
- MIME Type
- File Size
- Created Time
- Modified Time
- Access Time
- Permissions

Future

- Digital Signature
- EXIF Metadata
- Office Metadata
- PDF Metadata

---

## Why Metadata Matters

Metadata provides useful forensic information such as:

- File origin
- Timeline reconstruction
- File ownership
- Evidence preservation

---

# Cryptographic Hashing

## Purpose

Generate unique fingerprints for every uploaded file.

---

## Current

- SHA-256

---

## Future

- MD5
- SHA-1
- SHA-512
- SSDEEP (Similarity Hash)

---

## Applications

- Duplicate detection
- Integrity verification
- Malware lookup
- Threat intelligence searches

---

# Static Analysis

## Purpose

Analyze the internal structure of files without executing them.

Static analysis is completely safe because the uploaded file is never run.

---

## Executable Analysis

Potential analysis includes:

- PE Header
- Imports
- Exports
- Sections
- Resources
- Compilation Time
- Entry Point

---

## Office Documents

Detect:

- VBA Macros
- AutoOpen
- Embedded Objects
- PowerShell Commands

---

## PDF Analysis

Inspect:

- JavaScript
- Embedded Files
- Launch Actions
- OpenAction
- Encryption

---

## Image Analysis

Extract:

- EXIF Metadata
- Camera Information
- GPS Coordinates

Future

- Steganography Detection

---

# String Extraction

## Purpose

Many malicious files contain readable strings that reveal attacker activity.

---

## Detect

- URLs
- Domains
- Emails
- IP Addresses
- Registry Keys
- File Paths
- API Keys
- Cryptocurrency Wallets

---

## Benefits

String analysis often reveals:

- Command-and-Control servers
- Download URLs
- Hardcoded credentials
- Suspicious commands

---

# Entropy Analysis

## Purpose

Measure randomness inside a file.

High entropy often indicates:

- Encryption
- Compression
- Packers
- Obfuscation

---

## Risk Levels

| Entropy | Interpretation |
|----------|----------------|
| 0–5 | Low |
| 5–7 | Normal |
| >7 | Suspicious |

---

# Digital Signature Verification

## Purpose

Verify whether an executable has been digitally signed.

---

## Checks

- Signature Present
- Trusted Publisher
- Certificate Validity
- Certificate Expiration
- Certificate Chain

---

## Benefits

- Detect unsigned executables
- Validate publishers
- Increase investigation confidence

---

# YARA Rule Matching

## Purpose

Identify malware using pattern-based detection.

YARA rules describe known malware characteristics and signatures.

---

## Workflow

```
Uploaded File

↓

YARA Engine

↓

Matched Rules

↓

Threat Indicators
```

---

## Benefits

- Fast detection
- Signature matching
- Community rule support
- Custom rule support

---

## Future

- Rule Categories
- AI-generated Rules
- Rule Marketplace
- Automatic Rule Updates

---

# IOC Extraction

## Purpose

Extract Indicators of Compromise (IOCs) from uploaded files.

---

## Supported IOCs (implemented — Phase 3)

- IP Addresses (IPv4 + IPv6, validated octet-by-octet)
- Domains (with file-extension false-positive filtering)
- URLs (including defanged `evil[.]example` restoration)
- Email Addresses
- Registry Keys
- Windows File Paths
- Cryptographic Hashes (MD5 / SHA-1 / SHA-256)
- Commands (cmd / PowerShell / LOLBins)
- Mutexes

### False-positive controls

- Version-like numbers are never treated as IPs (`1.999.999.999` is rejected).
- Domains ending in a common file extension are rejected (`update.exe`, `kernel32.dll`).
- Private/loopback IPs keep a reduced confidence.

### Deduplication & provenance

The same IOC observed by several modules (strings, YARA, analyzers) is stored
once. Every IOC carries `sources` (module + evidence id + context), a `count`,
and a confidence that rises slightly with corroboration.

---

## IOC Applications

- Threat Intelligence
- Incident Response
- Threat Hunting
- Detection Engineering

---

# Threat Score Engine

## Purpose

Calculate an overall risk score based on multiple security indicators.

---

## Inputs

- File Type
- Entropy
- YARA Matches
- Suspicious APIs
- IOC Count
- Digital Signature
- AI Assessment

---

## Risk Scale

| Score | Level |
|---------|--------|
| 0–20 | Safe |
| 21–40 | Low |
| 41–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

---

## Scoring method (implemented — Phase 3, deterministic)

- Each finding carries a fixed weight: critical 25 / high 15 / medium 7 /
  low 2 / info 0.
- **Per-category dedup:** within one category only the strongest finding's
  weight counts. Ten YARA hits are one signal, not ten — cross-category
  signals (injection + downloader + persistence) still stack.
- Whole-file entropy adds a bounded bonus (3 if ≥ 7.0, 5 if ≥ 7.5).
- The reported severity is the worst single indicator.
- Verdict thresholds are frozen:
  - `malicious`: total ≥ 60 OR worst indicator == critical
  - `suspicious`: total ≥ 25 OR (worst indicator == high AND total ≥ 15)
  - `clean`: otherwise (static evidence only — never a guarantee)
- A high indicator therefore never produces a "clean" verdict.

---

# Threat Intelligence (Future)

The platform will support optional integration with external threat intelligence services.

Examples:

- VirusTotal
- MalwareBazaar
- AlienVault OTX
- AbuseIPDB

These integrations will enrich investigation results without being required for core functionality.

---

# MITRE ATT&CK Mapping

## Purpose

Map suspicious findings to the MITRE ATT&CK framework.

---

## Implementation (Phase 3 — evidence-backed)

A built-in catalog covers 22 techniques across the tactics most relevant to
static triage. Every emitted mapping must be supported by deterministic
evidence — no technique is invented because a model "thinks" it is plausible.
Phase 4 AI may only *explain* mappings that already exist.

### How a mapping is produced

1. Analyzer findings are attached to a technique via `mitre` metadata or the
   category→technique table (e.g. `process-injection` → T1055,
   `registry-persistence` → T1547.001, `pdf-javascript` → T1059.007).
2. Detection rules correlate evidence and emit capability findings with a
   technique (PowerShell T1059.001, downloader T1105, network T1071, …).
3. `build_mitre` aggregates findings per technique with:
   - `confidence` = strongest contributing finding,
   - `severity` = worst indicator,
   - `provenance` = finding count, source modules and observed evidence,
   - `evidence` snippets the analyst can inspect.

### Confidence semantics

| Range | Meaning |
|-------|---------|
| 0.90 – 1.00 | direct observation (PE import, YARA match, exact string) |
| 0.70 – 0.85 | strong derived correlation (rule over multiple evidence) |
| 0.50 – 0.65 | moderate inference (generic network strings) |
| < 0.50 | speculative — avoided |

---

# Phase 3 — Detection & Evidence Engine

The deterministic layer between raw static output and the AI engine. It turns
analyzer output into an explainable assessment:

```
static/raw analysis
  -> normalized EVIDENCE (observed)
  -> IOCs (deduplicated, provenance-preserving)
  -> findings enriched + correlated (derived)
  -> MITRE mappings (evidence-backed, inferred)
  -> investigation GRAPH (why the verdict is what it is)
```

## Evidence model

Three distinct concepts are never conflated:

| Kind | Meaning | Example |
|------|---------|---------|
| OBSERVED evidence | directly extracted, normalized | string, URL, PE import, YARA hit |
| DERIVED findings | rules over evidence | "PowerShell with obfuscation" |
| INFERRED technique | MITRE mapping backed by findings | T1055 via injection APIs |

Evidence entries carry `id`, `category`, `type`, `value`, `source_module`,
`severity`, `confidence`, `description`, `evidence`, `mitre_techniques` and
`metadata`. The list is capped (250) to keep payloads bounded.

## Detection rules

Rules fire only on real evidence (never on the mere fact a file is
executable). A rule is skipped when the analyzer already reported its
category, so the finding list stays noise-free. Examples: PowerShell execution
(T1059.001), command shell / LOLBins (T1059.003), downloader (T1105), network
communication (T1071), registry Run-key persistence (T1547.001), service
persistence (T1543.003), obfuscation (T1027), sandbox evasion (T1497),
credential access (T1555), remote access (T1219), masquerading (T1036).

## Investigation graph

A provenance graph connects the file → evidence → IOCs / findings → MITRE
techniques with typed edges (`contains`, `indicates`, `yields`,
`supported_by`, `maps_to`), capped at 160 nodes / 320 edges.

## Failure isolation

- YARA-lite isolates per rule and per file: one malformed rule (bad hex,
  unsupported condition) is logged and skipped; it never aborts the scan.
- Detection tolerates missing or empty analyzer sections.
- Every analysis module fails independently; a module error never aborts the
  pipeline.

---

# Security Module Workflow

```
Upload File

↓

Validation

↓

File Type Detection

↓

Metadata Extraction

↓

SHA-256 Generation

↓

Static Analysis

↓

String Extraction

↓

Entropy Analysis

↓

YARA Matching

↓

IOC Extraction

↓

Threat Score

↓

AI Explanation

↓

Generate Report
```

---

# Security Design Principles

The Security Engine follows several key principles:

- Never execute uploaded files
- Preserve original evidence
- Perform analysis in a controlled environment
- Use modular analysis components
- Produce explainable results
- Support future extensibility

---

# Current Module Status

| Module | Status |
|---------|--------|
| File Upload | ✅ Implemented |
| File Validation | ✅ Implemented |
| File Type Detection | ✅ Implemented |
| Metadata Extraction | ✅ Implemented |
| SHA-256 Hashing | ✅ Implemented |
| Static Analysis | ✅ Implemented |
| String Extraction | ✅ Implemented |
| Entropy Analysis | ✅ Implemented |
| Digital Signature Verification | ✅ Implemented |
| YARA Scanner | ✅ Implemented |
| IOC Extraction | ✅ Implemented (Phase 3) |
| Threat Score Engine | ✅ Implemented (Phase 3, deduplicated) |
| Detection Rules & Evidence | ✅ Implemented (Phase 3) |
| MITRE Mapping | ✅ Implemented (Phase 3, evidence-backed) |
| Investigation Graph | ✅ Implemented (Phase 3) |
| Threat Intelligence | 📅 Future (external feeds) |
| AI Interpretation | 📅 Future (Phase 4) |

---

# Future Enhancements

The Security Engine is designed to accommodate advanced cybersecurity capabilities as the project evolves.

Planned enhancements include:

- APK Static Analysis
- ELF Analysis
- Mach-O Analysis
- PCAP Analysis
- Memory Dump Analysis
- Registry Hive Analysis
- Sigma Rule Matching
- CAPA Integration
- Fuzzy Hashing (SSDEEP)
- Steganography Detection
- Certificate Reputation Checking
- AI-generated YARA Rules
- Threat Actor Attribution
- IOC Relationship Graph
- Automated Threat Hunting

---

# Summary

The Security Engine is the foundation of the AI-Powered Intelligent Sandbox. By combining static analysis, cryptographic hashing, YARA scanning, IOC extraction, and AI-assisted interpretation, it enables users to investigate suspicious files safely without executing them. Its modular architecture ensures that new cybersecurity techniques and analysis modules can be integrated as the platform grows, making it suitable for both academic research and practical cybersecurity learning.