"""
ThreatLens Hugging Face Gradio Space Entrypoint
===============================================
Launches background system daemons (Redis), mounts the FastAPI application
and compiled React SOC Dashboard, registers with Gradio/ZeroGPU, and serves traffic on Port 7860.
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

# 1. Top-level ZeroGPU initialization for Hugging Face ZeroGPU runtime
try:
    import spaces
    @spaces.GPU
    def _hf_zerogpu_target():
        return True
    
    # CRITICAL: Execute function on startup so ZeroGPU supervisor validates presence
    _hf_zerogpu_target()
    logger.info("Hugging Face ZeroGPU successfully validated on startup.")
except Exception as exc:
    logger.info("ZeroGPU initialization info: %s", exc)

# 2. Start Redis Server Daemon in Background
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

# 3. Check for Kafka / Redpanda broker on localhost:9092
def check_kafka_broker():
    import socket
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect(("127.0.0.1", 9092))
        s.close()
        logger.info("Kafka / Redpanda broker is active on 127.0.0.1:9092.")
        return True
    except Exception:
        s.close()

    # Try launching system redpanda if present
    import shutil
    if shutil.which("redpanda"):
        try:
            logger.info("Launching system Redpanda service...")
            subprocess.Popen(
                ["redpanda", "start", "--smp", "1", "--memory", "512M", "--reserve-memory", "0M", "--overprovisioned", "--node-id", "0", "--check=false", "--kafka-addr", "PLAINTEXT://127.0.0.1:9092"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2)
            return True
        except Exception:
            pass
    return False

check_kafka_broker()

# 4. Strictly enforce local project workflow: INGEST_SOURCE = kafka
os.environ["INGEST_SOURCE"] = "kafka"
os.environ["KAFKA_BOOTSTRAP_SERVERS"] = "127.0.0.1:9092"
os.environ["REDIS_HOST"] = "127.0.0.1"
os.environ["REDIS_PORT"] = "6379"
os.environ["CLICKHOUSE_HOST"] = "127.0.0.1"

# 5. Launch Zeek Kafka Shipper Pipeline in Background
shipper_script = ROOT_DIR / "ingest" / "producers" / "zeek_kafka_shipper.py"
if shipper_script.exists():
    try:
        logger.info("Launching Zeek Kafka Shipper daemon (%s)...", shipper_script)
        subprocess.Popen(
            [sys.executable, str(shipper_script)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        logger.warning("Could not launch Zeek Kafka Shipper (%s).", exc)

# 6. Import FastAPI Application
from backend.app.main import app
from fastapi.staticfiles import StaticFiles

# 7. Robust Multi-Path Discovery for Compiled React Frontend
candidate_paths = [
    ROOT_DIR / "frontend" / "dist",
    Path.cwd() / "frontend" / "dist",
    Path("/app/frontend/dist"),
    Path("/home/user/app/frontend/dist"),
]
frontend_dist = None
for candidate in candidate_paths:
    if candidate.exists() and (candidate / "index.html").exists():
        frontend_dist = candidate.resolve()
        break

if frontend_dist:
    logger.info("Mounting compiled React SOC Dashboard from: %s", frontend_dist)
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
else:
    logger.warning("frontend/dist directory could not be located in candidates: %s", candidate_paths)

# 8. Mount Gradio interface to satisfy Hugging Face Space Lifecycle Watchdog
try:
    import gradio as gr
    with gr.Blocks(title="ThreatLens SOC Enclave") as demo:
        gr.HTML("<meta http-equiv='refresh' content='0; url=/'>")
    app = gr.mount_gradio_app(app, demo, path="/_gradio")
    logger.info("Gradio lifecycle bridge successfully mounted.")
except Exception as err:
    logger.warning("Gradio mount notice: %s", err)

# 9. Launch Server on Port 7860 (Hugging Face default exposed port)
if __name__ == "__main__":
    import uvicorn
    logger.info("Launching ThreatLens on Port 7860 (INGEST_SOURCE=kafka)...")
    uvicorn.run(app, host="0.0.0.0", port=7860)
