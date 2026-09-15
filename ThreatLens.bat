@echo off
setlocal
title ThreatLens SOC Enclave
color 0B

REM ===================================================================
REM   Resolve repository root from this script's own location so the
REM   launcher works no matter which working directory it is called from.
REM ===================================================================
set "ROOT_DIR=%~dp0"
cd /d "%ROOT_DIR%"

echo.
echo ===================================================================
echo   THREATLENS PASSIVE SOC ENCLAVE ^| REAL-TIME THREAT DETECTOR
echo ===================================================================
echo.

REM 1. Verify backend virtual environment exists
if not exist ".venv\Scripts\python.exe" (
    echo [X] Virtual environment missing. Create it first:
    echo     python -m venv .venv
    echo     .venv\Scripts\pip install -r backend\requirements.txt
    pause
    exit /b 1
)
set "PY=%ROOT_DIR%.venv\Scripts\python.exe"

REM 2. Ensure .env file exists
if not exist .env (
    echo [*] Initializing configuration [.env]...
    copy .env.example .env >nul
)

REM 3. Ensure ThreatLens.ico and Desktop shortcut exist
if not exist ThreatLens.ico (
    echo [*] Generating ThreatLens application icon...
    "%PY%" scripts\generate_ico.py >nul
)
if not exist ThreatLens.lnk (
    echo [*] Registering Desktop shortcut...
    powershell -ExecutionPolicy Bypass -File create_shortcut.ps1 >nul
)

REM 4. Docker daemon: launch Docker Desktop if needed, then bounded wait
REM    (findstr, not find: immune to a Unix find.exe shadowing it on PATH)
tasklist /FI "IMAGENAME eq Docker Desktop.exe" 2>NUL | findstr /I /C:"Docker Desktop.exe">NUL
if "%ERRORLEVEL%"=="1" (
    echo [*] Launching Docker Desktop engine...
    start "" "docker-desktop://" 2>NUL
    if exist "%LOCALAPPDATA%\Programs\DockerDesktop\Docker Desktop.exe" (
        start "" "%LOCALAPPDATA%\Programs\DockerDesktop\Docker Desktop.exe"
    ) else if exist "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe" (
        start "" "%LOCALAPPDATA%\Programs\Docker\Docker\Docker Desktop.exe"
    ) else if exist "C:\Program Files\Docker\Docker\Docker Desktop.exe" (
        start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    ) else if exist "%LOCALAPPDATA%\DockerDesktop\Docker Desktop.exe" (
        start "" "%LOCALAPPDATA%\DockerDesktop\Docker Desktop.exe"
    )
)

set /a DOCKER_TRIES=0
:wait_docker
docker info >nul 2>&1
if not errorlevel 1 goto docker_ready
set /a DOCKER_TRIES+=1
if %DOCKER_TRIES% GEQ 60 (
    echo [X] Docker daemon not ready after ~2 minutes. Start Docker Desktop manually and retry.
    pause
    exit /b 1
)
echo [*] Waiting for Docker daemon... attempt %DOCKER_TRIES%/60
ping 127.0.0.1 -n 3 >nul
goto wait_docker
:docker_ready
echo [OK] Docker daemon ready.

REM 5. Build and launch Docker Compose containers (Redpanda, Redis, ClickHouse, Zeek)
echo [*] Compiling Zeek Inspection Engine ^& SOC Infrastructure...
docker compose build zeek >nul 2>&1
echo [*] Spinning up SOC Infrastructure (Redpanda, Redis, ClickHouse, Zeek)...
docker compose up -d
if errorlevel 1 (
    echo [X] Docker compose failed. Ensure Docker Desktop is fully initialized and retry.
    pause
    exit /b 1
)

REM 6. Bounded readiness wait: services must ANSWER, not merely be started
echo [*] Waiting for Redpanda, Redis and ClickHouse readiness...
"%PY%" scripts\wait_for_services.py --stage infra
if errorlevel 1 (
    echo [X] Infrastructure not ready. Backend was NOT started, so it cannot
    echo     silently launch into in-memory fallback storage. Inspect with:
    echo     docker compose ps
    echo     docker compose logs
    pause
    exit /b 1
)

REM 7. Launch FastAPI Backend in a dedicated window.
REM    NO --reload here: the reloader's file watcher scans the bind-mounted
REM    data\clickhouse directory and crashes with WinError 1920.
echo [*] Starting ThreatLens Backend API ^& Streaming Gateway - Port 8000...
start "ThreatLens Backend API" cmd /k "set INGEST_SOURCE=zeek_pcap&& .venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000"

echo [*] Waiting for backend readiness - persistent storage required...
"%PY%" scripts\wait_for_services.py --stage backend --timeout 60
if errorlevel 1 (
    echo [X] Backend did not become ready with ClickHouse + Redis connected.
    echo     Check the ThreatLens Backend API window for errors.
    pause
    exit /b 1
)

REM 8. Ship initial Zeek PCAP logs to Redpanda/Kafka
echo [*] Shipping packet metadata ^& PCAP traces to Redpanda Streaming Hub...
"%PY%" ingest\producers\zeek_kafka_shipper.py --mode batch

REM 9. Launch React Frontend in a dedicated window - deps must already exist
if not exist "frontend\node_modules" (
    echo [X] Frontend dependencies missing. Run once, then relaunch:
    echo     cd frontend
    echo     npm install
    pause
    exit /b 1
)
echo [*] Launching SOC Enclave Web Interface - Port 5173...
start "ThreatLens Dashboard UI" cmd /k "cd frontend && npm run dev"

set "FRONTEND_OK=0"
echo [*] Waiting for frontend dev server...
"%PY%" scripts\wait_for_services.py --stage frontend --timeout 60
if errorlevel 1 (
    echo [!] Frontend did not answer on http://localhost:5173 within 60s.
    echo     Check the ThreatLens Dashboard UI window.
) else (
    set "FRONTEND_OK=1"
    echo [*] Opening ThreatLens SOC Console in default browser...
    start http://localhost:5173
)

echo.
echo ===================================================================
if "%FRONTEND_OK%"=="1" (
    echo   [OK] ThreatLens SOC Enclave started successfully!
    echo        - SOC Console Dashboard : http://localhost:5173
    echo        - Backend REST API      : http://localhost:8000/docs
    echo        - Storage               : ClickHouse + Redis - persistent
) else (
    echo   [!] DEGRADED STARTUP: infrastructure + backend are running,
    echo        but the frontend is NOT reachable at http://localhost:5173
    echo        - Backend REST API      : http://localhost:8000/docs
)
echo        - Stop everything       : stop_threatlens.bat
echo ===================================================================
echo.
pause
