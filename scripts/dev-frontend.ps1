# Start the Aegis Sandbox AI frontend (Windows PowerShell)
Push-Location "$PSScriptRoot\..\frontend"
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing frontend dependencies..." -ForegroundColor Cyan
    npm install
}
Write-Host "Starting frontend on http://localhost:5173 ..." -ForegroundColor Green
npm run dev
Pop-Location
