#!/usr/bin/env bash
# Start the Aegis Sandbox AI frontend + backend together (Linux/macOS)
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Backend
cd "$ROOT/backend"
[ -d .venv ] || python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt
[ -f .env ] || cp .env.example .env
uvicorn app.main:app --reload --port 8000 &
BACK_PID=$!

# Frontend
cd "$ROOT/frontend"
[ -d node_modules ] || npm install
npm run dev

kill $BACK_PID 2>/dev/null || true
