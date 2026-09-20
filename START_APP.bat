@echo off
title ForensicChain Launcher
echo ============================================================
echo   Starting ForensicChain Digital Evidence Management System
echo ============================================================
echo.

cd /d "%~dp0"

echo [1/3] Checking blockchain node (Ganache on port 7545)...
powershell -NoProfile -Command "if (!(Get-NetTCPConnection -LocalPort 7545 -ErrorAction SilentlyContinue)) { Write-Host 'Starting Ganache in background...'; Start-Process cmd -ArgumentList '/k npx ganache --port 7545 --wallet.deterministic' -WindowStyle Minimized; Start-Sleep -Seconds 4 } else { Write-Host 'Ganache is already running on port 7545.' }"

echo [2/3] Launching web application in Chrome...
powershell -NoProfile -Command "Start-Process 'http://localhost:5000'"

echo [3/3] Starting Python Backend API on http://localhost:5000...
echo.
echo ============================================================
echo   System is LIVE! Keep this terminal window open.
echo   Press Ctrl + C to stop the server when done.
echo ============================================================
echo.
python backend/app.py
pause
