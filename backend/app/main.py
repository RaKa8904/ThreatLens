"""
ThreatLens FastAPI Application Gateway & Streaming Hub
======================================================
Provides RESTful historical telemetry endpoints, real-time WebSocket broadcast hub,
and background pipeline execution.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
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
from engine.kafka_consumer import KafkaAlertConsumer
from engine.models.aggregator import AlertAggregator
from engine.pipeline import DetectionPipeline
from engine.stream_worker import StreamWorker
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

# Live Kafka wiring state (populated during lifespan startup)
kafka_state: Dict[str, Any] = {
    "connected": False,
    "ingest_source": os.getenv("INGEST_SOURCE", "synthetic").lower(),
    "error": None,
}

# Live throughput counters
throughput_state = {
    "total_flows": 0,
    "total_packets": 0,
    "total_bytes": 0,
    "start_time": time.time(),
}


def record_flow_telemetry(payload: Dict[str, Any]):
    """Safely increments live throughput counters for processed flows."""
    throughput_state["total_flows"] += 1
    throughput_state["total_packets"] += int(payload.get("packets_out") or 1) + int(payload.get("packets_in") or 0)
    throughput_state["total_bytes"] += int(payload.get("bytes_out") or 0) + int(payload.get("bytes_in") or 0)


async def background_event_producer(
    producer,
    topic: str,
    stop_event: asyncio.Event,
    interval_seconds: float = 1.2,
):
    """
    Synthetic demo mode: generates flow events and publishes them to the
    canonical Kafka 'network-flows' topic, feeding the same downstream
    StreamWorker -> DetectionPipeline path as real Zeek telemetry.
    """
    logger.info("Synthetic event producer started (topic=%s).", topic)
    try:
        while not stop_event.is_set():
            event = flow_generator.generate_event(anomaly_ratio=0.45)
            record_flow_telemetry(event)
            await asyncio.to_thread(
                producer.send, topic, value=json.dumps(event).encode("utf-8")
            )
            await asyncio.sleep(interval_seconds)
    except asyncio.CancelledError:
        logger.info("Synthetic event producer stopped.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for application startup and shutdown lifecycle."""
    ingest_source = os.getenv("INGEST_SOURCE", "synthetic").lower()
    enable_bg = os.getenv("ENABLE_BACKGROUND_GENERATOR", "true").lower() in ("true", "1", "yes")
    kafka_state["ingest_source"] = ingest_source
    logger.info("ThreatLens Ingestion Mode: %s", ingest_source)

    tasks = []
    stream_worker = None
    alert_consumer = None
    producer = None
    stop_event = asyncio.Event()

    if enable_bg:
        kafka_servers = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
        flow_topic = os.getenv("KAFKA_FLOW_TOPIC", "network-flows")

        try:
            stream_worker = StreamWorker(kafka_servers, pipeline=pipeline)
            kafka_state["connected"] = True
            tasks.append(asyncio.create_task(asyncio.to_thread(stream_worker.run)))
            logger.info("StreamWorker started: %s -> detection -> threat-alerts.", flow_topic)
        except Exception as exc:
            kafka_state["error"] = f"stream worker: {exc}"
            logger.error("Kafka unavailable (%s) — live detection pipeline DISABLED.", exc)

        try:
            alert_consumer = KafkaAlertConsumer(
                storage=alert_store,
                ws_manager=ws_manager,
                bootstrap_servers=kafka_servers,
            )
            tasks.append(asyncio.create_task(alert_consumer.run_consumer_loop(stop_event=stop_event)))
        except Exception as exc:
            kafka_state["error"] = f"{kafka_state['error']}; alert consumer: {exc}" if kafka_state["error"] else f"alert consumer: {exc}"
            logger.error("Kafka alert consumer unavailable (%s) — alert persistence DISABLED.", exc)

        if ingest_source == "synthetic":
            try:
                from kafka import KafkaProducer

                producer = KafkaProducer(bootstrap_servers=kafka_servers)
                tasks.append(
                    asyncio.create_task(
                        background_event_producer(producer, flow_topic, stop_event)
                    )
                )
            except Exception as exc:
                kafka_state["error"] = f"{kafka_state['error']}; synthetic producer: {exc}" if kafka_state["error"] else f"synthetic producer: {exc}"
                logger.error("Kafka producer unavailable (%s) — synthetic demo stream DISABLED.", exc)

    yield

    stop_event.set()
    if stream_worker:
        stream_worker.stop()
    if alert_consumer:
        alert_consumer.stop()
    if producer:
        try:
            producer.close()
        except Exception:
            pass
    for task in tasks:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
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
        },
        "websocket": {
            "active_clients": ws_manager.client_count,
        },
        "kafka": kafka_state,
        "archive": {
            "total_alerts_recorded": alert_store.get_alert_count(),
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
        "total_flows": throughput_state["total_flows"],
        "total_packets": throughput_state["total_packets"],
        "total_bytes": throughput_state["total_bytes"],
        "total_alerts": alert_store.get_alert_count(),
        "active_websocket_clients": ws_manager.client_count,
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
