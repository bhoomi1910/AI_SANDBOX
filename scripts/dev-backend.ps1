# Start the Aegis Sandbox AI backend (Windows PowerShell)
Push-Location "$PSScriptRoot\..\backend"
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Cyan
    python -m venv .venv
}
& ".\.venv\Scripts\Activate.ps1"
pip install -q -r requirements.txt
if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env" }
Write-Host "Starting backend on http://localhost:8000/docs ..." -ForegroundColor Green
uvicorn app.main:app --reload --port 8000
Pop-Location
