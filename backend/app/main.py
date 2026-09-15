"""
ThreatLens FastAPI Application Gateway & Streaming Hub
======================================================
Provides RESTful historical telemetry endpoints, real-time WebSocket broadcast hub,
and background pipeline execution.
"""

import asyncio
import csv
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
import subprocess
import tempfile
import logging
import os
import queue
import time
import uuid
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# Load the repository-root .env before any configuration-dependent import below:
# engine.config, backend.app.storage, and engine.runtime_config snapshot
# environment values at import time. Already-set environment variables win
# (load_dotenv does not override), so launch scripts and tests stay authoritative.
load_dotenv()

from fastapi import FastAPI, HTTPException, Query, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from backend.app.routers.replay import router as replay_router
from backend.app.schemas import (
    AnalystNoteCreate,
    AnalystNoteSchema,
    AlertStatusEnum,
    SuppressionRule,
    SuppressionRuleCreate,
    SuppressionRuleUpdate,
    ThreatAlertSchema,
    ThreatClassEnum,
    ThresholdConfigResponse,
    ThresholdResetResponse,
    ThresholdUpdateRequest,
)
from backend.app.storage import ClickHouseAlertStore
from backend.app.websocket_manager import ConnectionManager
from engine.features.store import SlidingWindowStore
from engine.kafka_consumer import KafkaIngestConsumer
from engine.models.aggregator import AlertAggregator
from engine.pipeline import DetectionPipeline
from engine.config import describe_thresholds, get_threshold
from engine.runtime_config import RuntimeConfigStore
from ingest.producers.mock_producer import SyntheticFlowGenerator
from ingest.producers.zeek_kafka_shipper import ZeekLogShipper

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Global Component Instances
ws_manager = ConnectionManager()
alert_store = ClickHouseAlertStore(auto_connect=True)
window_store = SlidingWindowStore(use_redis=True)
alert_aggregator = AlertAggregator()
runtime_config = RuntimeConfigStore()
runtime_config.load()
pipeline = DetectionPipeline(store=window_store, aggregator=alert_aggregator, suppression_provider=runtime_config)
flow_generator = SyntheticFlowGenerator(seed=int(time.time()))
replay_state: Dict[str, Any] = {"status": "idle", "path": None, "processed_alerts": 0, "error": None}

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


def run_replay(pcap_path: str) -> None:
    replay_state.update({"status": "running", "path": pcap_path, "processed_alerts": 0, "error": None})
    try:
        with tempfile.TemporaryDirectory(prefix="threatlens-replay-") as log_dir:
            import shutil
            is_testing = os.getenv("TESTING", "").lower() == "true" or "PYTEST_CURRENT_TEST" in os.environ
            if shutil.which("docker") and not is_testing:
                try:
                    subprocess.run(["docker", "rm", "-f", "threatlens-zeek-replay"], capture_output=True, timeout=5)
                    subprocess.run(
                        ["docker", "compose", "run", "--rm", "--name", "threatlens-zeek-replay", "-e", "MODE=replay", "-e", "PCAP_DIR=/replay", "-e", "LOG_DIR=/replay-logs", "-v", f"{Path(pcap_path).parent.resolve()}:/replay:ro", "-v", f"{Path(log_dir).resolve()}:/replay-logs", "zeek"],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                except Exception as exc:
                    logger.debug("Legacy replay docker execution omitted: %s", exc)
            replay_pipeline = DetectionPipeline(store=SlidingWindowStore(use_redis=False), aggregator=AlertAggregator())
            shipper = ZeekLogShipper(log_dir=log_dir, event_queue=queue.Queue())
            for log_name in ["dns", "ssl", "conn"]:
                for event in shipper.process_log_file(log_name, str(Path(log_dir) / f"{log_name}.log")):
                    event["source"] = "replay"
                    for alert in replay_pipeline.process_flow_event(event):
                        alert_store.insert_alert(alert)
                        replay_state["processed_alerts"] += 1
        replay_state["status"] = "completed"
    except Exception as exc:
        replay_state.update({"status": "failed", "error": str(exc)})


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
            for alert in alerts:
                event_ts = event_timestamp_seconds(event)
                alert = alert.model_copy(update={
                    "ingest_latency_ms": round(max(0.0, time.time() - event_ts) * 1000, 3) if event_ts else None,
                    "processing_latency_ms": round(processing_latency_ms, 3),
                })
                alert_store.insert_alert(alert)
                if not alert.suppressed:
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

app.include_router(replay_router)


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
        "redis_status": "connected" if window_store.is_redis_connected else "fallback_memory",
        "clickhouse_status": "connected" if alert_store.is_connected else "fallback_memory",
        "ingest_source": os.getenv("INGEST_SOURCE", "synthetic").lower(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "redis": {
                "connected": window_store.is_redis_connected,
                "fallback_active": window_store.fallback_active,
                "mode": "redis-cluster" if window_store.is_redis_connected else "in-memory-fallback",
            },
            "clickhouse": {
                "connected": alert_store.is_connected,
                "fallback_active": alert_store.fallback_active,
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
    status: Optional[AlertStatusEnum] = Query(None, description="Optional alert lifecycle status filter"),
):
    """
    Retrieves recent threat alerts from ClickHouse or in-memory fallback archive with filtering.
    """
    alerts = alert_store.get_recent_alerts(limit=limit + offset, threat_class=threat_class, status=status.value if status else None)
    return alerts[offset : offset + limit]


@app.patch("/api/alerts/{flow_id:path}/status", response_model=ThreatAlertSchema, tags=["Alerts"])
def update_alert_status(flow_id: str, status: AlertStatusEnum):
    """Updates post-creation workflow status for an alert flow."""
    updated = alert_store.update_alert_status(flow_id, status)
    if updated is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Alert flow not found")
    return updated


@app.post("/api/alerts/{flow_id:path}/notes", response_model=AnalystNoteSchema, tags=["Alerts"])
def add_alert_note(flow_id: str, note: AnalystNoteCreate):
    return alert_store.add_note(AnalystNoteSchema(flow_id=flow_id, text=note.text))


@app.get("/api/alerts/{flow_id:path}/notes", response_model=List[AnalystNoteSchema], tags=["Alerts"])
def get_alert_notes(flow_id: str):
    return alert_store.get_notes(flow_id)


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


@app.get("/api/incidents", response_model=List[Dict[str, Any]], tags=["Incidents"])
def get_incidents(limit: int = Query(100, ge=1, le=500)):
    """Returns recent source-correlated incidents with constituent alert records."""
    grouped: Dict[str, Dict[str, Any]] = {}
    for alert in alert_store.get_recent_alerts(limit=limit):
        if not alert.incident_id:
            continue
        incident = grouped.setdefault(alert.incident_id, {
            "incident_id": alert.incident_id,
            "source_ip": alert.source_ip or alert.evidence.source_ip,
            "first_seen": alert.timestamp,
            "last_seen": alert.timestamp,
            "threat_classes": [],
            "alerts": [],
        })
        incident["first_seen"] = min(incident["first_seen"], alert.timestamp)
        incident["last_seen"] = max(incident["last_seen"], alert.timestamp)
        threat_class = alert.threat_class.value if isinstance(alert.threat_class, ThreatClassEnum) else str(alert.threat_class)
        if threat_class not in incident["threat_classes"]:
            incident["threat_classes"].append(threat_class)
        incident["alerts"].append(alert.model_dump(mode="json"))
    return sorted(grouped.values(), key=lambda item: item["last_seen"], reverse=True)[:limit]


@app.get("/api/config/thresholds", response_model=ThresholdConfigResponse, tags=["Detection Configuration"])
def get_detection_thresholds():
    """
    Returns every analyst-configurable detector threshold with its live value,
    valid range, controlling rule, and the engine that consumes it.
    """
    return ThresholdConfigResponse(
        storage_mode=runtime_config.storage_mode,
        persistent=runtime_config.persistent,
        thresholds=describe_thresholds(),
    )


@app.put("/api/config/thresholds", response_model=ThresholdConfigResponse, tags=["Detection Configuration"])
def update_detection_threshold(payload: ThresholdUpdateRequest):
    """
    Applies a single threshold change. The new value takes effect on the next
    detector evaluation; no container restart is required.
    """
    try:
        previous = get_threshold(payload.rule, payload.parameter)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown threshold rule '{payload.rule}'")

    try:
        entry = runtime_config.set_threshold(payload.rule, payload.parameter, payload.value)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Unknown threshold rule '{payload.rule}'")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    logger.info(
        "AUDIT threshold_change rule=%s parameter=%s old=%r new=%r consumed_by=%s persistent=%s",
        entry["rule"], entry["parameter"], previous, entry["value"],
        entry["consumed_by"], runtime_config.persistent,
    )
    return ThresholdConfigResponse(
        storage_mode=runtime_config.storage_mode,
        persistent=runtime_config.persistent,
        thresholds=describe_thresholds(),
    )


@app.post("/api/config/thresholds/reset", response_model=ThresholdResetResponse, tags=["Detection Configuration"])
def reset_detection_thresholds():
    """Restores every threshold to its environment-derived baseline."""
    logger.info("AUDIT threshold_reset persistent=%s", runtime_config.persistent)
    return ThresholdResetResponse(
        storage_mode=runtime_config.storage_mode,
        persistent=runtime_config.persistent,
        thresholds=runtime_config.reset_thresholds(),
    )


@app.get("/api/export/iocs", tags=["Export"])
def export_iocs(
    window_minutes: int = Query(60, ge=1, le=10080),
    format: str = Query("json", pattern="^(json|csv)$"),
):
    """Exports source IPs, DGA domains, and malware JA3/JA4 indicators."""
    cutoff = datetime.now(timezone.utc).timestamp() - window_minutes * 60
    indicators: List[Dict[str, Any]] = []
    for alert in alert_store.get_recent_alerts(limit=500):
        timestamp = alert.timestamp if alert.timestamp.tzinfo else alert.timestamp.replace(tzinfo=timezone.utc)
        if timestamp.timestamp() < cutoff:
            continue
        evidence = alert.evidence
        source_ip = alert.source_ip or evidence.source_ip
        if source_ip:
            indicators.append({"type": "source_ip", "value": source_ip, "threat_class": alert.threat_class.value, "timestamp": timestamp.isoformat()})
        if alert.threat_class == ThreatClassEnum.DGA_DNS and evidence.dns_query:
            indicators.append({"type": "dns_domain", "value": evidence.dns_query, "threat_class": alert.threat_class.value, "timestamp": timestamp.isoformat()})
        if alert.threat_class == ThreatClassEnum.ENCRYPTED_MALWARE:
            for indicator_type, value in (("ja3", evidence.ja3_hash), ("ja4", evidence.ja4_hash)):
                if value:
                    indicators.append({"type": indicator_type, "value": value, "threat_class": alert.threat_class.value, "timestamp": timestamp.isoformat()})
    if format == "csv":
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=["type", "value", "threat_class", "timestamp"])
        writer.writeheader()
        writer.writerows(indicators)
        return Response(content=output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=threatlens-iocs.csv"})
    return {"window_minutes": window_minutes, "indicators": indicators}


@app.post("/api/replay/start", response_model=Dict[str, Any], tags=["Replay"])
async def start_replay(payload: Dict[str, str]):
    """Starts an isolated PCAP replay; replay alerts are tagged and not broadcast."""
    pcap_path = payload.get("pcap_path", "")
    if not pcap_path or not Path(pcap_path).is_file():
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="pcap_path must reference an existing file")
    if replay_state["status"] == "running":
        from fastapi import HTTPException
        raise HTTPException(status_code=409, detail="Replay already running")
    asyncio.create_task(asyncio.to_thread(run_replay, pcap_path))
    return {"status": "started", "pcap_path": pcap_path, "source": "replay"}


@app.get("/api/replay/status", response_model=Dict[str, Any], tags=["Replay"])
def get_replay_status():
    return replay_state


@app.get("/api/analytics/trends", response_model=Dict[str, Any], tags=["Analytics"])
def get_alert_trends(
    window_minutes: int = Query(60, ge=5, le=1440),
    bucket_minutes: int = Query(5, ge=1, le=60),
):
    """Returns selectable time-bucketed alert counts for all six threat vectors."""
    alerts = alert_store.get_recent_alerts(limit=500)
    now = datetime.now(timezone.utc).timestamp()
    classes = [c.value for c in ThreatClassEnum]
    bucket_seconds = bucket_minutes * 60
    start = (now - window_minutes * 60) // bucket_seconds * bucket_seconds
    buckets: Dict[int, Dict[str, int]] = {}
    for alert in alerts:
        alert_timestamp = alert.timestamp
        if alert_timestamp.tzinfo is None:
            alert_timestamp = alert_timestamp.replace(tzinfo=timezone.utc)
        timestamp = alert_timestamp.astimezone(timezone.utc).timestamp()
        if timestamp < start:
            continue
        bucket = int((timestamp - start) // bucket_seconds)
        counts = buckets.setdefault(bucket, {threat_class: 0 for threat_class in classes})
        threat_class = alert.threat_class.value if isinstance(alert.threat_class, ThreatClassEnum) else str(alert.threat_class)
        if threat_class in counts:
            counts[threat_class] += 1

    points = []
    bucket_count = max(1, int(window_minutes * 60 // bucket_seconds) + 1)
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


@app.get("/api/config/suppressions", response_model=List[SuppressionRule], tags=["Detection Configuration"])
def list_suppression_rules():
    """Lists analyst suppression rules, newest first."""
    rules = runtime_config.get_suppression_rules()
    return sorted(rules, key=lambda rule: rule.created_at, reverse=True)


@app.post("/api/config/suppressions", response_model=SuppressionRule, status_code=201, tags=["Detection Configuration"])
def create_suppression_rule(rule: SuppressionRuleCreate):
    """
    Creates a suppression rule. Matching alerts are still detected and persisted
    with full evidence; only delivery to the analyst console is withheld.
    """
    created = runtime_config.create_suppression_rule(
        SuppressionRule(id=str(uuid.uuid4()), **rule.model_dump())
    )
    logger.info(
        "AUDIT suppression_added id=%s type=%s source=%s destination=%s threat_class=%s enabled=%s persistent=%s",
        created.id, created.rule_type, created.source_ip, created.destination_ip,
        created.threat_class.value if created.threat_class else None,
        created.enabled, runtime_config.persistent,
    )
    return created


@app.patch("/api/config/suppressions/{rule_id}", response_model=SuppressionRule, tags=["Detection Configuration"])
def update_suppression_rule(rule_id: str, payload: SuppressionRuleUpdate):
    """
    Partially updates a suppression rule (enable/disable, description, expiry).
    """
    existing = next((r for r in runtime_config.get_suppression_rules() if r.id == rule_id), None)
    if existing is None:
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    updated = runtime_config.update_suppression_rule(
        rule_id,
        enabled=payload.enabled,
        description=payload.description,
        expires_at=payload.expires_at,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    logger.info(
        "AUDIT suppression_updated id=%s enabled=%s->%s expires_at=%s persistent=%s",
        updated.id, existing.enabled, updated.enabled, updated.expires_at,
        runtime_config.persistent,
    )
    return updated


@app.delete("/api/config/suppressions/{rule_id}", tags=["Detection Configuration"])
def delete_suppression_rule(rule_id: str):
    """Deletes a suppression rule by id."""
    if not runtime_config.delete_suppression_rule(rule_id):
        raise HTTPException(status_code=404, detail="Suppression rule not found")
    logger.info("AUDIT suppression_removed id=%s persistent=%s", rule_id, runtime_config.persistent)
    return {"deleted": True, "id": rule_id}


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
