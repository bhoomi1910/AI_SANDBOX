# Database Documentation

## Overview

The AI-Powered Intelligent Sandbox uses a relational database to store investigation records, uploaded file information, AI analysis, threat intelligence, reports, and historical data.

The current prototype uses **SQLite** because it is lightweight, portable, and easy to integrate with FastAPI.

The architecture is database-independent, allowing future migration to **PostgreSQL** with minimal code changes.

---

# Database Goals

The database is designed to:

- Store investigation history
- Maintain uploaded file information
- Store security analysis results
- Save AI-generated explanations
- Store generated reports
- Support dashboard analytics
- Enable investigation search
- Preserve forensic evidence
- Support future multi-user environments

---

# Current Database

## Database Engine

```
SQLite
```

Advantages:

- Lightweight
- No installation required
- Easy backup
- Fast development
- Ideal for educational projects

---

# Future Database

The architecture supports migration to:

- PostgreSQL
- MySQL
- MariaDB

without major changes to the application logic.

---

# Entity Relationship Overview

```
                Users (Future)
                     │
                     │
                     ▼
            Investigations
                     │
        ┌────────────┼────────────┐
        │            │            │
        ▼            ▼            ▼
 Uploaded Files  AI Analysis   Reports
        │            │
        │            ▼
        │      Threat Scores
        │
        ▼
Metadata
        │
        ▼
YARA Results
        │
        ▼
IOC Results
```

---

# Main Tables

Current Prototype

- investigations

Future

- uploaded_files
- file_metadata
- hash_values
- static_analysis
- yara_matches
- ioc_results
- ai_analysis
- mitre_mapping
- reports
- users
- audit_logs

---

# Table: investigations

## Purpose

Stores every investigation performed by the system.

---

## Fields

| Column | Type | Description |
|---------|------|-------------|
| id | INTEGER | Primary Key |
| filename | TEXT | Uploaded file name |
| file_type | TEXT | Detected file type |
| upload_date | DATETIME | Upload timestamp |
| status | TEXT | Investigation status |
| threat_score | INTEGER | Risk score |
| risk_level | TEXT | Safe, Low, Medium, High, Critical |
| report_path | TEXT | Generated report location |

---

## Status Values

- Uploaded
- Processing
- Completed
- Failed

---

# Table: uploaded_files (Future)

## Purpose

Stores detailed information about uploaded files.

---

## Fields

| Column | Description |
|---------|-------------|
| id | Primary Key |
| investigation_id | Foreign Key |
| original_name | Original filename |
| stored_name | Internal filename |
| file_size | File size |
| extension | File extension |
| mime_type | MIME type |
| upload_time | Upload timestamp |
| storage_path | File location |

---

# Table: file_metadata

## Purpose

Stores metadata extracted from uploaded files.

---

## Example Fields

- File Size
- MIME Type
- Created Date
- Modified Date
- Owner
- Permissions
- EXIF Metadata
- PDF Properties

---

# Table: hash_values

## Purpose

Stores cryptographic hashes.

---

## Fields

| Hash Type |
|-----------|
| SHA256 |
| MD5 |
| SHA1 |
| SHA512 |
| SSDEEP |

---

## Why Store Multiple Hashes?

Different threat intelligence platforms use different hash algorithms.

---

# Table: static_analysis

## Purpose

Stores results from static file analysis.

---

## Example Data

- File Entropy
- Import Table
- Export Table
- Sections
- Resources
- Suspicious APIs
- Embedded Objects

---

# Table: yara_matches

## Purpose

Stores YARA rule matching results.

---

## Example Fields

| Column | Description |
|---------|-------------|
| Rule Name | Matched Rule |
| Severity | Risk Level |
| Description | Rule Description |
| Rule Category | Malware Family |

---

# Table: ioc_results

## Purpose

Stores extracted Indicators of Compromise.

---

## IOC Types

- IP Address
- Domain
- URL
- Email
- Registry Key
- File Path
- Hash
- Wallet Address

---

# Table: ai_analysis

## Purpose

Stores AI-generated investigation results.

---

## Example Fields

- Executive Summary
- Technical Summary
- Threat Explanation
- Recommendations
- Confidence Score
- AI Model Used
- Analysis Time

---

# Table: mitre_mapping

## Purpose

Maps findings to the MITRE ATT&CK framework.

---

## Stored Data

- Technique ID
- Technique Name
- Tactic
- Confidence

Example

```
T1059

Command and Scripting Interpreter
```

---

# Table: reports

## Purpose

Stores generated reports.

---

## Example Fields

- Report ID
- Investigation ID
- Report Type
- File Path
- Generated Date

---

# Table: users (Future)

## Purpose

Supports authentication.

---

## Example Fields

- Username
- Email
- Password Hash
- Role
- Last Login

---

## Roles

- Administrator
- Security Analyst
- Viewer

---

# Table: audit_logs (Future)

## Purpose

Records user activity.

---

## Example Events

- Login
- Upload
- Report Download
- Investigation Delete
- Settings Update

---

# Database Relationships

```
Investigation

│

├── Uploaded File

├── Metadata

├── Hashes

├── Static Analysis

├── YARA Matches

├── IOC Results

├── AI Analysis

├── Report

└── MITRE Mapping
```

---

# Database Workflow

```
User Upload

↓

Create Investigation

↓

Store File

↓

Extract Metadata

↓

Generate Hash

↓

Store Metadata

↓

Static Analysis

↓

Store Results

↓

AI Analysis

↓

Store AI Results

↓

Generate Report

↓

Save Report

↓

Dashboard
```

---

# Indexing Strategy

Future indexes will improve search performance.

Examples:

- SHA256
- Filename
- Upload Date
- Threat Score
- File Type
- Investigation Status

---

# Search Capabilities

Users will be able to search using:

- Filename
- Hash
- Threat Score
- Upload Date
- IOC
- YARA Rule
- Risk Level

---

# Data Retention

Current

- Store all investigations

Future

- Automatic cleanup policies
- Investigation archiving
- Report retention settings

---

# Backup Strategy

Recommended backups:

- Daily SQLite backup
- Weekly compressed archive
- Future PostgreSQL scheduled backups

---

# Security Considerations

The database follows several security principles:

- Parameterized SQL queries
- SQLAlchemy ORM
- Input validation
- No direct SQL execution
- Secure file path storage
- Future encryption for sensitive fields
- Role-based database access
- Audit logging

---

# Future Enhancements

Planned database improvements include:

- PostgreSQL migration
- Investigation versioning
- Full-text search
- Elasticsearch integration
- Vector database for AI knowledge retrieval
- Multi-user support
- Investigation collaboration
- Data encryption at rest
- Automatic backups
- High availability

---

# Summary

The database is the foundation of the AI-Powered Intelligent Sandbox, ensuring that every investigation, analysis result, AI explanation, and generated report is stored securely and can be retrieved efficiently. The current SQLite implementation provides a lightweight solution for development, while the modular schema allows seamless migration to enterprise-grade database systems as the project evolves.