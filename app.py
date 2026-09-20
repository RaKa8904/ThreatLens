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

# Top-level ZeroGPU compatibility decorator for Hugging Face ZeroGPU runtime
try:
    import spaces
    @spaces.GPU
    def _hf_zerogpu_target():
        return True
except Exception:
    pass

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

# 2. Ensure Redpanda / Kafka Broker is running on localhost:9092
def ensure_kafka_broker():
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

    # Check if redpanda binary exists or download static release
    bin_dir = ROOT_DIR / "bin"
    redpanda_bin = bin_dir / "redpanda"
    
    import shutil
    sys_redpanda = shutil.which("redpanda")
    cmd_bin = sys_redpanda or (str(redpanda_bin) if redpanda_bin.exists() else None)

    if not cmd_bin:
        logger.info("Downloading standalone Redpanda Kafka broker binary for Linux...")
        try:
            bin_dir.mkdir(parents=True, exist_ok=True)
            import urllib.request
            import tarfile
            url = "https://github.com/redpanda-data/redpanda/releases/download/v23.3.5/redpanda-23.3.5-linux-amd64.tar.gz"
            tar_path = bin_dir / "redpanda.tar.gz"
            urllib.request.urlretrieve(url, tar_path)
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=bin_dir)
            if tar_path.exists():
                tar_path.unlink()
            for p in bin_dir.rglob("redpanda"):
                if p.is_file():
                    os.chmod(p, 0o755)
                    cmd_bin = str(p)
                    break
        except Exception as exc:
            logger.warning("Redpanda binary download omitted (%s).", exc)

    if cmd_bin:
        try:
            logger.info("Launching Redpanda Kafka broker service (%s)...", cmd_bin)
            subprocess.Popen(
                [cmd_bin, "start", "--smp", "1", "--memory", "512M", "--reserve-memory", "0M", "--overprovisioned", "--node-id", "0", "--check=false", "--kafka-addr", "PLAINTEXT://127.0.0.1:9092"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(3)
            return True
        except Exception as exc:
            logger.warning("Redpanda launcher failed (%s).", exc)

    return False

ensure_kafka_broker()

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

# 6. Import FastAPI App
from backend.app.main import app
from fastapi.staticfiles import StaticFiles

# 7. Mount Compiled React Frontend Static Build if available
frontend_dist = (ROOT_DIR / "frontend" / "dist").resolve()
if frontend_dist.exists():
    logger.info("Mounting compiled React SOC Dashboard from %s...", frontend_dist)
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
else:
    logger.warning("frontend/dist directory not found at %s. Please build frontend with `npm run build`.", frontend_dist)

# 8. Launch Server on Port 7860 (Hugging Face default exposed port)
if __name__ == "__main__":
    import uvicorn
    logger.info("Launching ThreatLens on Port 7860 with INGEST_SOURCE=kafka...")
    uvicorn.run(app, host="0.0.0.0", port=7860)
