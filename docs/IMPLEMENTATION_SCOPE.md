# AI Malware Analysis Platform — Scope and Success Criteria

## Title Alignment
Develop an Artificial Intelligence (AI) powered malware analysis platform using sandboxing for threat detection and automated investigation reporting.

## Input / Output Contract
- **Input:** multiple file categories (executables, scripts, documents, archives, PDFs, images, and unknown binaries).
- **Output:** investigation report describing observed threats, malware indicators, evidence-backed findings, and recommended actions.

## Scope Baseline
1. Secure ingestion with validation, hashing, quarantine state, and provenance.
2. Static analysis modules with normalized evidence output.
3. Detection/correlation engine producing IOCs, findings, MITRE mappings, and deterministic threat score/verdict.
4. Dynamic sandbox orchestration path with strict isolation controls and explicit availability states.
5. AI interpretation constrained to deterministic outputs with strict validation and safe fallback.
6. Automated PDF reporting with evidence traceability and audit metadata.
7. Frontend analyst workflow for upload, queueing, investigation review, and report download.

## Required Report Sections
- File identity and cryptographic hashes
- Threat verdict and risk score
- Evidence summary and top findings
- Indicators of Compromise (IOCs)
- MITRE ATT&CK mapping
- AI interpretation status/summary (when available)
- Remediation and investigation recommendations
- Traceability/audit identifiers

## Security Boundaries
- No direct host execution of uploaded samples.
- Dynamic execution path must run only in isolated worker/sandbox context.
- Enforced size limits, filename sanitization, and controlled storage locations.
- Request-level audit logging and evidence-trace identifiers for every investigation.
- Deterministic analysis remains the source of truth; AI cannot invent detections.

## Success Criteria
- Uploads for supported categories are accepted, persisted, and traceable.
- Investigation APIs expose static, dynamic, IOC, MITRE, AI, trace, and report outputs.
- Report claims map back to stored evidence and trace identifiers.
- Frontend supports operational filtering by status, severity, and verdict.
- Automated tests validate upload security, analysis endpoints, and reporting behavior.
