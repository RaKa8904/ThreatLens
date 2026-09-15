@echo off
title ThreatLens Shutdown
echo ===================================================
echo           ThreatLens SOC Enclave Shutdown
echo ===================================================
echo.

echo [*] Stopping Docker infrastructure containers...
docker compose down

echo [*] Closing FastAPI Backend and Frontend dev servers...
REM Window-title matching fails when consoles run as Windows Terminal tabs,
REM so kill by listening port (backend 8000, frontend 5173); title match kept
REM as a fallback for classic console windows.
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do taskkill /PID %%p /F >nul 2>&1
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":5173" ^| findstr "LISTENING"') do taskkill /PID %%p /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq ThreatLens Backend API*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq ThreatLens Dashboard UI*" /F >nul 2>&1

echo.
echo [OK] ThreatLens shut down successfully.
ping 127.0.0.1 -n 4 >nul
