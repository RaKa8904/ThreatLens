@echo off
title ThreatLens SOC Enclave
color 0B
cd /d "%~dp0"

echo.
echo ===================================================================
echo   THREATLENS PASSIVE SOC ENCLAVE ^| REAL-TIME THREAT DETECTOR
echo ===================================================================
echo.

REM 1. Ensure .env file exists
if not exist .env (
    echo [*] Initializing configuration [.env]...
    copy .env.example .env >nul
)

REM 2. Ensure ThreatLens.ico and Desktop shortcut exist
if not exist ThreatLens.ico (
    echo [*] Generating ThreatLens application icon...
    .\.venv\Scripts\python.exe scripts/generate_ico.py >nul
)
if not exist ThreatLens.lnk (
    echo [*] Registering Desktop shortcut...
    powershell -ExecutionPolicy Bypass -File create_shortcut.ps1 >nul
)

REM 3. Check if Docker Desktop is running, launch if not
tasklist /FI "IMAGENAME eq Docker Desktop.exe" 2>NUL | find /I /N "Docker Desktop.exe">NUL
if "%ERRORLEVEL%"=="1" (
    echo [*] Launching Docker Desktop engine...
    if exist "C:\Users\%USERNAME%\AppData\Local\Programs\DockerDesktop\Docker Desktop.exe" (
        start "" "C:\Users\%USERNAME%\AppData\Local\Programs\DockerDesktop\Docker Desktop.exe"
    ) else (
        if exist "C:\Program Files\Docker\Docker\Docker Desktop.exe" (
            start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
        )
    )
    echo [*] Waiting for Docker daemon initialization...
    ping 127.0.0.1 -n 11 >nul
)

REM 4. Launch Docker Compose containers (Redpanda, Redis, ClickHouse, Zeek)
echo [*] Spinning up SOC Infrastructure (Redpanda, Redis, ClickHouse, Zeek)...
docker compose up -d
if %ERRORLEVEL% NEQ 0 (
    echo [!] Docker compose failed. Please ensure Docker Desktop is fully initialized and try again.
    pause
    exit /b %ERRORLEVEL%
)

REM 5. Launch FastAPI Backend in a dedicated enclave window
echo [*] Starting ThreatLens Backend API ^& Streaming Gateway (Port 8000)...
start "ThreatLens Backend API" cmd /k "title ThreatLens Backend Service && cd /d "%~dp0" && set INGEST_SOURCE=kafka&& .\.venv\Scripts\uvicorn backend.app.main:app --port 8000 --reload"

echo [*] Initializing Kafka Consumers and Neural Pipeline...
ping 127.0.0.1 -n 5 >nul

REM 6. Ship initial Zeek PCAP logs to Redpanda/Kafka
echo [*] Shipping packet metadata ^& PCAP traces to Redpanda Streaming Hub...
.\.venv\Scripts\python.exe ingest/producers/zeek_kafka_shipper.py --mode batch

REM 7. Launch React Frontend in a dedicated window
echo [*] Launching SOC Enclave Web Interface (Port 5173)...
start "ThreatLens Dashboard UI" cmd /k "title ThreatLens Frontend Console && cd /d "%~dp0frontend" && npm run dev"

REM 8. Launch Browser to Frontend Dashboard
echo [*] Opening ThreatLens SOC Console in default browser...
ping 127.0.0.1 -n 3 >nul
start http://localhost:5173

echo.
echo ===================================================================
echo   [OK] ThreatLens SOC Enclave application started successfully!
echo        - SOC Console Dashboard : http://localhost:5173
echo        - Backend REST API      : http://localhost:8000/docs
echo ===================================================================
echo.
pause
