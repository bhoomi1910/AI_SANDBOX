# Deployment Guide

## Overview

This document explains how to set up, configure, and run the **AI-Powered Intelligent Sandbox** in a local development environment. It also provides guidance for future production deployment.

The project follows a modular architecture consisting of:

- React Frontend
- FastAPI Backend
- SQLite Database
- Ollama AI Engine
- Docker Infrastructure

The application is designed to run entirely on a local machine without requiring internet access for AI analysis.

---

# System Architecture

```
                   User

                     │

                     ▼

             React Frontend

                     │

              REST API Calls

                     ▼

             FastAPI Backend

     ┌──────────┼───────────┐
     │          │           │
     ▼          ▼           ▼

SQLite DB  Security Engine  Ollama

     │          │           │
     └──────────┴───────────┘

               Investigation
                  Results
```

---

# System Requirements

## Operating System

Supported:

- Windows 10
- Windows 11
- Ubuntu 22.04+
- Debian
- Fedora
- macOS (Apple Silicon & Intel)

---

## Hardware Requirements

### Minimum

| Component | Requirement |
|-----------|-------------|
| CPU | 4 Cores |
| RAM | 8 GB |
| Storage | 20 GB Free |
| GPU | Optional |

---

### Recommended

| Component | Requirement |
|-----------|-------------|
| CPU | 8+ Cores |
| RAM | 16 GB |
| Storage | SSD (50 GB+) |
| GPU | NVIDIA GPU (Optional) |

---

# Software Requirements

Install the following software before running the project.

| Software | Purpose |
|----------|----------|
| Python 3.11+ | Backend |
| Node.js 20+ | Frontend |
| npm | Package Manager |
| Git | Version Control |
| Docker | Containerization |
| Docker Compose | Multi-container Management |
| Ollama | Local AI Models |

---

# Project Structure

```
AI-Powered-Intelligent-Sandbox/

│

├── backend/

├── frontend/

├── database/

├── docker/

├── reports/

├── uploads/

├── docs/

├── docker-compose.yml

├── README.md

└── .env
```

---

# Clone Repository

```bash
git clone <repository-url>

cd AI-Powered-Intelligent-Sandbox
```

---

# Backend Setup

Navigate to the backend directory.

```bash
cd backend
```

---

## Create Virtual Environment

Windows

```powershell
python -m venv venv
```

Linux/macOS

```bash
python3 -m venv venv
```

---

## Activate Virtual Environment

Windows

```powershell
venv\Scripts\activate
```

Linux/macOS

```bash
source venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Verify Installation

```bash
python --version

pip --version
```

---

# Frontend Setup

Navigate to frontend.

```bash
cd frontend
```

---

## Install Packages

```bash
npm install
```

---

## Start Development Server

```bash
npm run dev
```

Default

```
http://localhost:5173
```

---

# Backend Server

Run FastAPI.

```bash
uvicorn app.main:app --reload
```

Default

```
http://localhost:8000
```

Swagger

```
http://localhost:8000/docs
```

ReDoc

```
http://localhost:8000/redoc
```

---

# SQLite Database

No installation is required.

The database file is automatically created during initialization.

Example

```
database.db
```

---

# Ollama Installation

The AI Engine requires Ollama.

Download and install Ollama from the official website:

https://ollama.com

---

## Verify Installation

```bash
ollama --version
```

---

# Download AI Models

Example

```bash
ollama pull qwen3
```

Other supported models

```bash
ollama pull llama3

ollama pull mistral

ollama pull deepseek-r1

ollama pull codellama
```

---

# Start Ollama

```bash
ollama serve
```

Default API

```
http://localhost:11434
```

---

# Verify Ollama

```bash
ollama list
```

---

# Docker Deployment

Build project

```bash
docker-compose build
```

---

Run project

```bash
docker-compose up
```

Detached mode

```bash
docker-compose up -d
```

---

Stop containers

```bash
docker-compose down
```

---

Rebuild

```bash
docker-compose up --build
```

---

# Environment Variables

Create

```
.env
```

Example

```text
APP_NAME=AI Sandbox

DEBUG=True

DATABASE_URL=sqlite:///database.db

OLLAMA_URL=http://localhost:11434

OLLAMA_MODEL=qwen3

UPLOAD_DIRECTORY=uploads

REPORT_DIRECTORY=reports

MAX_UPLOAD_SIZE=104857600
```

---

# Folder Structure

The following folders are automatically created if they do not exist.

```
uploads/

reports/

logs/

temp/

database/
```

---

# Upload Directory

Uploaded files are stored in

```
uploads/
```

Original files are never modified.

---

# Reports

Generated investigation reports

```
reports/
```

Current

- PDF

Future

- HTML
- JSON
- CSV

---

# Logs

System logs

```
logs/
```

Examples

- API Errors
- AI Errors
- Upload Errors
- Database Errors

---

# Running the Complete Project

Step 1

Start Ollama

```bash
ollama serve
```

---

Step 2

Run Backend

```bash
uvicorn app.main:app --reload
```

---

Step 3

Run Frontend

```bash
npm run dev
```

---

Step 4

Open Browser

```
http://localhost:5173
```

---

# Verification Checklist

Ensure:

✅ Frontend loads successfully

✅ Backend is running

✅ Swagger UI opens

✅ Ollama is active

✅ SQLite database is created

✅ File upload works

✅ Investigation is stored

---

# Common Issues

## Python Not Found

Solution

Install Python and add it to the system PATH.

---

## npm Not Found

Solution

Install Node.js.

Verify

```bash
node -v

npm -v
```

---

## Virtual Environment Not Activating

Windows

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then activate

```powershell
venv\Scripts\activate
```

---

## Port Already in Use

Backend

Change port

```bash
uvicorn app.main:app --reload --port 8001
```

Frontend

Modify Vite configuration.

---

## Ollama Connection Failed

Check

```bash
ollama serve
```

Verify

```
http://localhost:11434
```

---

## Docker Issues

Verify installation

```bash
docker --version

docker-compose --version
```

---

# Security Recommendations

The deployment follows several security practices:

- Uploaded files are never executed.
- AI models run locally.
- Input validation is applied before processing.
- Reports are generated from analysis data only.
- Sensitive information remains on the local system.

---

# Future Production Deployment

Future production deployments may include:

- PostgreSQL database
- Nginx reverse proxy
- HTTPS with TLS
- User authentication
- Role-Based Access Control (RBAC)
- Background task processing
- Redis caching
- Automated backups
- Container orchestration (Kubernetes)

---

# Continuous Integration & Continuous Deployment (Future)

Planned CI/CD pipeline:

- GitHub Actions
- Automated testing
- Docker image builds
- Security scanning
- Automated deployment to staging and production

---

# Deployment Workflow

```
Clone Repository

↓

Install Dependencies

↓

Configure Environment

↓

Start Ollama

↓

Initialize Database

↓

Run Backend

↓

Run Frontend

↓

Upload File

↓

Perform Analysis

↓

Generate Report

↓

View Dashboard
```

---

# Deployment Status

| Component | Status |
|-----------|--------|
| React Frontend | ✅ Supported |
| FastAPI Backend | ✅ Supported |
| SQLite Database | ✅ Supported |
| Docker | ✅ Supported |
| Docker Compose | ✅ Supported |
| Ollama Integration | 🚧 In Progress |
| PDF Reports | 🚧 Planned |
| PostgreSQL | 📅 Future |
| HTTPS Deployment | 📅 Future |
| Kubernetes | 📅 Future |

---

# Summary

The AI-Powered Intelligent Sandbox is designed for simple deployment while maintaining a modular architecture. Developers can run the complete application locally using React, FastAPI, SQLite, Docker, and Ollama without relying on external cloud services. The deployment process supports rapid development today while providing a clear path toward scalable and secure production environments in the future.