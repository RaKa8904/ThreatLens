"""
ThreatLens Hugging Face Gradio Space Entrypoint
===============================================
Launches background system daemons (Redis), mounts the FastAPI application
and compiled React SOC Dashboard, and serves traffic on Port 7860.
"""

import os
import sys
import subprocess
import time
import logging
from pathlib import Path

# Add repository root to python path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threatlens-space")

# 1. Start Redis Server Daemon in Background
try:
    logger.info("Starting background Redis server...")
    subprocess.Popen(
        ["redis-server", "--protected-mode", "no"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
except Exception as err:
    logger.warning("Could not launch system redis-server (%s). In-memory fallback will activate.", err)

# 2. Set Environment Variables for Space Deployment
os.environ["INGEST_SOURCE"] = os.getenv("INGEST_SOURCE", "kafka")
os.environ["REDIS_HOST"] = "127.0.0.1"
os.environ["REDIS_PORT"] = "6379"
os.environ["CLICKHOUSE_HOST"] = "127.0.0.1"

# 3. Import FastAPI App
from backend.app.main import app
from fastapi.staticfiles import StaticFiles

# 4. Mount Compiled React Frontend Static Build if available
frontend_dist = ROOT_DIR / "frontend" / "dist"
if frontend_dist.exists():
    logger.info("Mounting compiled React SOC Dashboard from %s...", frontend_dist)
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
else:
    logger.warning("frontend/dist directory not found. Please build frontend with `npm run build`.")

# 5. Launch Server on Port 7860 (Hugging Face default exposed port)
if __name__ == "__main__":
    import uvicorn
    logger.info("Launching ThreatLens on Port 7860...")
    uvicorn.run(app, host="0.0.0.0", port=7860)
