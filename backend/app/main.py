"""
ThreatLens FastAPI Application Gateway & Streaming Hub
======================================================
Provides RESTful historical telemetry endpoints, real-time WebSocket broadcast hub,
and background pipeline execution.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
import os
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.app.schemas import ThreatAlertSchema, ThreatClassEnum
from backend.app.storage import ClickHouseAlertStore
from backend.app.websocket_manager import ConnectionManager
from engine.features.store import SlidingWindowStore
from engine.kafka_consumer import KafkaIngestConsumer
from engine.models.aggregator import AlertAggregator
from engine.pipeline import DetectionPipeline
from ingest.producers.mock_producer import SyntheticFlowGenerator

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Global Component Instances
ws_manager = ConnectionManager()
alert_store = ClickHouseAlertStore(auto_connect=True)
window_store = SlidingWindowStore(use_redis=True)
alert_aggregator = AlertAggregator()
pipeline = DetectionPipeline(store=window_store, aggregator=alert_aggregator)
flow_generator = SyntheticFlowGenerator(seed=int(time.time()))

# Live throughput counters
throughput_state = {
    "total_flows": 0,
    "total_packets": 0,
    "total_bytes": 0,
    "start_time": time.time(),
    "last_ingest_at": None,
    "last_processing_latency_ms": None,
    "last_delivery_latency_ms": None,
}


def record_flow_telemetry(payload: Dict[str, Any]):
    """Safely increments live throughput counters for processed flows."""
    throughput_state["total_flows"] += 1
    throughput_state["total_packets"] += int(payload.get("packets_out") or 1) + int(payload.get("packets_in") or 0)
    throughput_state["total_bytes"] += int(payload.get("bytes_out") or 0) + int(payload.get("bytes_in") or 0)
    throughput_state["last_ingest_at"] = time.time()


def event_timestamp_seconds(payload: Dict[str, Any]) -> Optional[float]:
    timestamp = payload.get("timestamp")
    if isinstance(timestamp, (int, float)):
        return float(timestamp)
    if isinstance(timestamp, str):
        try:
            return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


async def background_stream_worker(interval_seconds: float = 1.5):
    """
    Continuous background task generating synthetic enterprise telemetry,
    feeding the detection pipeline, indexing to ClickHouse, and broadcasting alerts.
    """
    logger.info("ThreatLens background telemetry streaming worker started.")
    try:
        while True:
            # Keep high-volume background traffic separate from sparse threats.
            event = flow_generator.generate_event(
                anomaly_ratio=float(os.getenv("SIMULATION_THREAT_RATIO", "0.005"))
            )

            # Update metrics counters
            record_flow_telemetry(event)

            # Run detection pipeline
            processing_started = time.perf_counter()
            alerts = pipeline.process_flow_event(event)
            processing_latency_ms = (time.perf_counter() - processing_started) * 1000
            throughput_state["last_processing_latency_ms"] = round(processing_latency_ms, 3)

            # Ingest to ClickHouse and broadcast live to WebSocket clients
            simulated_confidence = event.get("simulated_confidence")
            for alert in alerts:
                if simulated_confidence is not None:
                    alert = alert.model_copy(update={"confidence_score": simulated_confidence})
                event_ts = event_timestamp_seconds(event)
                alert = alert.model_copy(update={
                    "ingest_latency_ms": round(max(0.0, time.time() - event_ts) * 1000, 3) if event_ts else None,
                    "processing_latency_ms": round(processing_latency_ms, 3),
                })
                alert_store.insert_alert(alert)
                await ws_manager.broadcast(alert)
                throughput_state["last_delivery_latency_ms"] = round(max(0.0, time.time() - alert.timestamp.timestamp()) * 1000, 3)

            flow_rate = max(float(os.getenv("SIMULATION_FLOWS_PER_SECOND", "10")), 0.1)
            await asyncio.sleep(1.0 / flow_rate)
    except asyncio.CancelledError:
        logger.info("ThreatLens background telemetry streaming worker stopped.")
    except Exception as exc:
        logger.error("Error in telemetry streaming worker: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for application startup and shutdown lifecycle."""
    ingest_source = os.getenv("INGEST_SOURCE", "synthetic").lower()
    logger.info("ThreatLens Ingestion Mode: %s", ingest_source)

    worker_task = None
    stop_event = asyncio.Event()

    if ingest_source == "kafka":
        kafka_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        logger.info("Initializing KafkaIngestConsumer connected to %s...", kafka_servers)
        consumer = KafkaIngestConsumer(
            pipeline=pipeline,
            storage=alert_store,
            ws_manager=ws_manager,
            kafka_bootstrap_servers=kafka_servers,
            on_message=lambda topic, data: record_flow_telemetry(data),
        )
        worker_task = asyncio.create_task(consumer.run_consumer_loop(stop_event=stop_event))
    else:
        # Default: Synthetic event stream generator
        enable_bg = os.getenv("ENABLE_BACKGROUND_GENERATOR", "true").lower() in ("true", "1", "yes")
        if enable_bg:
            worker_task = asyncio.create_task(background_stream_worker(interval_seconds=1.2))

    yield

    stop_event.set()
    if worker_task:
        worker_task.cancel()
        try:
            await worker_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="ThreatLens API & Streaming Gateway",
    version="1.0.0",
    description="Real-Time Passive Network Threat Detection & Forensic Dissemination Pipeline",
    lifespan=lifespan,
)

# Enable CORS for local dev frontends (Vite: 5173, Next.js/CRA: 3000)
cors_origins_env = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000")
origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# REST Endpoints
# =============================================================================

@app.get("/api/health", response_model=Dict[str, Any], tags=["System"])
def get_system_health():
    """
    Returns system health status for Redis, ClickHouse, and the detection pipeline.
    """
    return {
        "status": "healthy",
        "ingest_source": os.getenv("INGEST_SOURCE", "synthetic").lower(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "redis": {
                "connected": window_store.is_redis_connected,
                "mode": "redis-cluster" if window_store.is_redis_connected else "in-memory-fallback",
            },
            "clickhouse": {
                "connected": alert_store.is_connected,
                "mode": "clickhouse-olap" if alert_store.is_connected else "in-memory-ring-fallback",
            },
            "pipeline": {
                "active": True,
                "engines_count": len(pipeline.aggregator.engines),
                "supported_classes": [c.value for c in ThreatClassEnum],
            },
            "passive_ingest": {
                "status": "zero-egress-read-only",
                "zero_egress": True,
                "read_only": True,
                "outbound_return_path": False,
            },
        },
        "websocket": {
            "active_clients": ws_manager.client_count,
        },
        "archive": {
            "total_alerts_recorded": alert_store.get_alert_count(),
        },
        "telemetry": {
            "last_ingest_at": throughput_state["last_ingest_at"],
            "processing_latency_ms": throughput_state["last_processing_latency_ms"],
            "delivery_latency_ms": throughput_state["last_delivery_latency_ms"],
        },
    }


@app.get("/api/alerts", response_model=List[ThreatAlertSchema], tags=["Alerts"])
def get_historical_alerts(
    limit: int = Query(50, ge=1, le=500, description="Max alerts to retrieve"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    threat_class: Optional[str] = Query(None, description="Optional ThreatClassEnum filter"),
):
    """
    Retrieves recent threat alerts from ClickHouse or in-memory fallback archive with filtering.
    """
    alerts = alert_store.get_recent_alerts(limit=limit + offset, threat_class=threat_class)
    return alerts[offset : offset + limit]


@app.get("/api/metrics/throughput", response_model=Dict[str, Any], tags=["Metrics"])
def get_network_throughput():
    """
    Returns real-time network throughput and event rate telemetry.
    """
    elapsed = max(time.time() - throughput_state["start_time"], 1.0)
    flows_per_sec = round(throughput_state["total_flows"] / elapsed, 2)
    packets_per_sec = round(throughput_state["total_packets"] / elapsed, 2)
    bytes_per_sec = round(throughput_state["total_bytes"] / elapsed, 2)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 1),
        "flows_per_sec": flows_per_sec,
        "packets_per_sec": packets_per_sec,
        "bytes_per_sec": bytes_per_sec,
        "megabits_per_sec": round(bytes_per_sec * 8 / 1_000_000, 3),
        "total_flows": throughput_state["total_flows"],
        "total_packets": throughput_state["total_packets"],
        "total_bytes": throughput_state["total_bytes"],
        "total_alerts": alert_store.get_alert_count(),
        "active_websocket_clients": ws_manager.client_count,
        "processing_latency_ms": throughput_state["last_processing_latency_ms"],
        "delivery_latency_ms": throughput_state["last_delivery_latency_ms"],
    }


@app.get("/api/analytics/trends", response_model=Dict[str, Any], tags=["Analytics"])
def get_alert_trends(
    window_minutes: int = Query(60, ge=5, le=1440),
    bucket_minutes: int = Query(5, ge=1, le=60),
):
    """Returns selectable time-bucketed alert counts for all six threat vectors."""
    alerts = alert_store.get_recent_alerts(limit=500)
    now = datetime.now(timezone.utc).timestamp()
    start = now - window_minutes * 60
    classes = [c.value for c in ThreatClassEnum]
    bucket_seconds = bucket_minutes * 60
    buckets: Dict[int, Dict[str, int]] = {}
    for alert in alerts:
        timestamp = alert.timestamp.timestamp()
        if timestamp < start:
            continue
        bucket = int((timestamp - start) // bucket_seconds)
        counts = buckets.setdefault(bucket, {threat_class: 0 for threat_class in classes})
        threat_class = alert.threat_class.value if isinstance(alert.threat_class, ThreatClassEnum) else str(alert.threat_class)
        if threat_class in counts:
            counts[threat_class] += 1

    points = []
    bucket_count = max(1, (window_minutes + bucket_minutes - 1) // bucket_minutes)
    for bucket in range(bucket_count):
        bucket_start = start + bucket * bucket_seconds
        points.append({
            "timestamp": datetime.fromtimestamp(bucket_start, timezone.utc).isoformat(),
            "counts": buckets.get(bucket, {threat_class: 0 for threat_class in classes}),
        })
    return {
        "window_minutes": window_minutes,
        "bucket_minutes": bucket_minutes,
        "threat_classes": classes,
        "points": points,
    }


# =============================================================================
# WebSocket Endpoint
# =============================================================================

@app.websocket("/ws/threats")
async def websocket_threat_feed(websocket: WebSocket):
    """
    Direct low-latency WebSocket feed streaming live threat alerts to connected SOC consoles.
    """
    await ws_manager.connect(websocket)
    try:
        # Avoid replaying the persistent archive as a burst during live simulation.
        replay_history = os.getenv("SIMULATION_REPLAY_HISTORY", "false").lower() in ("true", "1", "yes")
        if os.getenv("INGEST_SOURCE", "synthetic").lower() != "synthetic" or replay_history:
            recent_alerts = alert_store.get_recent_alerts(limit=50)
            for alert in reversed(recent_alerts):
                payload = alert.model_dump() if hasattr(alert, "model_dump") else (alert.dict() if hasattr(alert, "dict") else alert)
                if isinstance(payload.get("timestamp"), datetime):
                    payload["timestamp"] = payload["timestamp"].isoformat()
                await websocket.send_json(payload)

        # Keep connection open and accept optional client heartbeats / filters
        while True:
            data = await websocket.receive_text()
            # Client can ping or request immediate refresh
            if data == "ping":
                await websocket.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.debug("WebSocket exception: %s", exc)
        ws_manager.disconnect(websocket)
