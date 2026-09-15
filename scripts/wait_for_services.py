"""
ThreatLens Bounded Readiness Checks
===================================
Used by ThreatLens.bat so services are only declared ready after they
actually answer - "container started" is not "service ready".

Stages:
  infra    - Redpanda accepting TCP on 9092, Redis PING, ClickHouse /ping + SELECT 1
  backend  - http://127.0.0.1:8000/api/health with clickhouse/redis both connected
  frontend - http://127.0.0.1:5173 answering

Each check retries once per second until its timeout, then reports [FAIL]
and exits non-zero. No service is started here; this script only observes.
"""

import argparse
import json
import os
import socket
import sys
import time
import urllib.request

from dotenv import load_dotenv

load_dotenv()


def _http_get(url: str, timeout: float = 2.0) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read()


def check_redpanda() -> None:
    host = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092").split(",")[0]
    host, _, port = host.partition(":")
    with socket.create_connection((host or "localhost", int(port or 9092)), timeout=2.0):
        pass


def check_redis() -> None:
    host = os.getenv("REDIS_HOST", "localhost")
    port = int(os.getenv("REDIS_PORT", "6379"))
    with socket.create_connection((host, port), timeout=2.0) as sock:
        sock.sendall(b"PING\r\n")
        reply = sock.recv(16)
        if b"+PONG" not in reply:
            raise RuntimeError(f"unexpected PING reply: {reply!r}")


def check_clickhouse() -> None:
    host = os.getenv("CLICKHOUSE_HOST", "localhost")
    port = os.getenv("CLICKHOUSE_PORT", "8123")
    base = f"http://{host}:{port}"
    if b"Ok" not in _http_get(f"{base}/ping"):
        raise RuntimeError("ClickHouse /ping did not return Ok")
    if _http_get(f"{base}/?query=SELECT%201").strip() != b"1":
        raise RuntimeError("ClickHouse trivial query did not return 1")


def check_backend() -> None:
    body = json.loads(_http_get("http://127.0.0.1:8000/api/health"))
    if body.get("clickhouse_status") != "connected":
        raise RuntimeError(f"clickhouse_status={body.get('clickhouse_status')}")
    if body.get("redis_status") != "connected":
        raise RuntimeError(f"redis_status={body.get('redis_status')}")


def check_frontend() -> None:
    # Vite binds the literal "localhost" (IPv6 ::1 on Windows), not 127.0.0.1.
    _http_get("http://localhost:5173/")


STAGES = {
    "infra": [("Redpanda", check_redpanda), ("Redis", check_redis), ("ClickHouse", check_clickhouse)],
    "backend": [("Backend API", check_backend)],
    "frontend": [("Frontend", check_frontend)],
}


def wait_for(name: str, check, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    last_error = "unknown error"
    while time.monotonic() < deadline:
        try:
            check()
            print(f"[OK] {name} ready")
            return True
        except Exception as exc:
            last_error = exc
            time.sleep(1.0)
    print(f"[FAIL] {name} not ready after {timeout:.0f}s (last error: {last_error})")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreatLens bounded readiness checks")
    parser.add_argument("--stage", required=True, choices=sorted(STAGES))
    parser.add_argument("--timeout", type=float, default=90.0, help="Seconds to wait per check")
    args = parser.parse_args()

    ready = all(wait_for(name, check, args.timeout) for name, check in STAGES[args.stage])
    return 0 if ready else 1


if __name__ == "__main__":
    sys.exit(main())
