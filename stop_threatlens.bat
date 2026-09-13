@echo off
title ThreatLens Shutdown
echo ===================================================
echo           ThreatLens SOC Enclave Shutdown          
echo ===================================================
echo.

echo [*] Stopping Docker infrastructure containers...
docker compose down

echo [*] Closing FastAPI Backend and Frontend dev servers...
taskkill /FI "WINDOWTITLE eq ThreatLens Backend API*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq ThreatLens Dashboard UI*" /F >nul 2>&1

echo.
echo [✓] ThreatLens shut down successfully.
ping 127.0.0.1 -n 4 >nul
