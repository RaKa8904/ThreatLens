"""
ThreatLens Analytical Storage Client
====================================
High-density ClickHouse columnar persistence for threat alerts and forensic evidence,
featuring an automatic, thread-safe in-memory ring buffer fallback.
"""

from collections import deque
from datetime import datetime, timezone
import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional

from backend.app.schemas import AnalystNoteSchema, AlertStatusEnum, EvidenceSchema, SeverityEnum, ThreatAlertSchema, ThreatClassEnum

logger = logging.getLogger(__name__)


def normalize_utc_timestamp(timestamp: datetime) -> datetime:
    """Treat database DateTime64 values without tzinfo as UTC."""
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


class ClickHouseAlertStore:
    """
    Persistent alert archive backed by ClickHouse MergeTree columnar table,
    with seamless in-memory circular buffer fallback.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        database: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        max_memory_buffer: int = 1000,
        auto_connect: bool = True,
    ):
        self.host = host or os.getenv("CLICKHOUSE_HOST", "localhost")
        self.port = int(port or os.getenv("CLICKHOUSE_PORT", 8123))
        self.database = database or os.getenv("CLICKHOUSE_DB", "threatlens")
        self.user = user or os.getenv("CLICKHOUSE_USER", "default")
        self.password = password or os.getenv("CLICKHOUSE_PASSWORD", "")

        self.client = None
        self.is_connected = False
        self.fallback_active = False
        # Reconnect on use only when persistent storage was requested.
        # auto_connect=False stores (test harness) stay pure in-memory and
        # must never reach out to a real ClickHouse server.
        self._allow_reconnect = auto_connect

        # In-memory circular buffer fallback (Thread-safe)
        self._memory_ring: deque[ThreatAlertSchema] = deque(maxlen=max_memory_buffer)
        self._status_overrides: Dict[str, AlertStatusEnum] = {}
        self._lock = threading.Lock()
        self._ch_lock = threading.Lock()
        self._last_reconnect_attempt = 0.0

        if auto_connect:
            self.connect()
        else:
            self.fallback_active = True

    def connect(self) -> bool:
        """Attempts to establish connection with ClickHouse and initialize tables."""
        import time
        self._last_reconnect_attempt = time.time()

        # Fast socket pre-flight check to avoid urllib3 retry flood when ClickHouse daemon is offline
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            res = sock.connect_ex((self.host, self.port))
            sock.close()
            if res != 0:
                self.client = None
                self.is_connected = False
                self.fallback_active = True
                return False
        except Exception:
            self.client = None
            self.is_connected = False
            self.fallback_active = True
            return False

        try:
            import clickhouse_connect

            client = clickhouse_connect.get_client(
                host=self.host,
                port=self.port,
                username=self.user,
                password=self.password,
                connect_timeout=2,
                send_receive_timeout=3,
            )
            # Create database if not exists
            client.command(f"CREATE DATABASE IF NOT EXISTS {self.database}")
            
            # Switch to database and initialize alerts schema
            init_table_sql = f"""
            CREATE TABLE IF NOT EXISTS {self.database}.alerts (
                timestamp DateTime64(3, 'UTC'),
                flow_id String,
                threat_class LowCardinality(String),
                confidence_score Float32,
                severity Nullable(String),
                evidence_json String,
                inter_arrival_variance Float64,
                shannon_entropy Float32,
                byte_ratio Float32,
                fan_out_count UInt32,
                ja3_hash Nullable(String),
                details String
            ) ENGINE = MergeTree()
            PARTITION BY toYYYYMM(timestamp)
            ORDER BY (threat_class, timestamp, flow_id)
            """
            client.command(init_table_sql)
            client.command(f"ALTER TABLE {self.database}.alerts ADD COLUMN IF NOT EXISTS status LowCardinality(String) DEFAULT 'new'")
            client.command(f"ALTER TABLE {self.database}.alerts ADD COLUMN IF NOT EXISTS incident_id Nullable(String)")
            client.command(f"ALTER TABLE {self.database}.alerts ADD COLUMN IF NOT EXISTS suppressed UInt8 DEFAULT 0")
            client.command(f"ALTER TABLE {self.database}.alerts ADD COLUMN IF NOT EXISTS source LowCardinality(String) DEFAULT 'live'")
            client.command(f"ALTER TABLE {self.database}.alerts ADD COLUMN IF NOT EXISTS alert_id String DEFAULT ''")
            client.command(f"ALTER TABLE {self.database}.alerts ADD COLUMN IF NOT EXISTS severity Nullable(String)")
            client.command(f"CREATE TABLE IF NOT EXISTS {self.database}.alert_notes (flow_id String, text String, created_at DateTime64(3, 'UTC')) ENGINE = MergeTree() ORDER BY (flow_id, created_at)")

            self.client = client
            self.is_connected = True
            self.fallback_active = False
            logger.info("Connected to ClickHouse at %s:%s (db=%s)", self.host, self.port, self.database)
            return True
        except Exception as exc:
            logger.warning(
                "ClickHouse unavailable (%s). Operating in-memory alert ring buffer fallback.",
                exc,
            )
            self.client = None
            self.is_connected = False
            self.fallback_active = True
            return False

    def insert_alert(self, alert: ThreatAlertSchema) -> bool:
        """
        Inserts an alert into ClickHouse and stores it in the in-memory ring buffer.
        """
        # Always maintain in thread-safe memory ring
        with self._lock:
            self._memory_ring.appendleft(alert)

        if not self.is_connected or self.client is None:
            return True

        try:
            evidence = alert.evidence
            row = [
                alert.timestamp,
                alert.alert_id or "",
                alert.flow_id,
                alert.threat_class.value if isinstance(alert.threat_class, ThreatClassEnum) else str(alert.threat_class),
                float(alert.confidence_score),
                alert.severity.value if alert.severity else None,
                evidence.model_dump_json(),
                float(evidence.inter_arrival_variance),
                float(evidence.shannon_entropy),
                float(evidence.byte_ratio),
                int(evidence.fan_out_count),
                evidence.ja3_hash,
                evidence.details,
                alert.status.value,
                alert.incident_id,
                int(alert.suppressed),
                alert.source,
            ]
            columns = [
                "timestamp", "alert_id", "flow_id", "threat_class", "confidence_score", "severity",
                "evidence_json", "inter_arrival_variance", "shannon_entropy",
                "byte_ratio", "fan_out_count", "ja3_hash", "details", "status", "incident_id", "suppressed", "source"
            ]
            with self._ch_lock:
                self.client.insert(
                    f"{self.database}.alerts",
                    [row],
                    column_names=columns,
                )
            return True
        except Exception as exc:
            logger.error("ClickHouse insert failed: %s. Stored in memory ring buffer.", exc)
            self.is_connected = False
            return False

    def get_recent_alerts(
        self,
        limit: int = 50,
        threat_class: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[ThreatAlertSchema]:
        """
        Retrieves recent alerts from ClickHouse or falls back to in-memory ring buffer.
        """
        import time
        if not self.is_connected and self._allow_reconnect and (time.time() - self._last_reconnect_attempt > 60):
            self.connect()

        if self.is_connected and self.client is not None:
            try:
                query = f"""
                SELECT timestamp, alert_id, flow_id, threat_class, confidence_score, severity, evidence_json, status, incident_id, suppressed, source
                FROM {self.database}.alerts
                """
                params: Dict[str, Any] = {"limit": limit}
                if threat_class:
                    query += " WHERE threat_class = %(threat_class)s"
                    params["threat_class"] = threat_class
                # Do not push status filter into ClickHouse SQL query if in-memory status overrides exist,
                # as ClickHouse ALTER TABLE UPDATE mutations execute asynchronously.
                # Python post-filtering on line 220 ensures immediate consistency.

                query += " ORDER BY timestamp DESC LIMIT %(limit)s"

                with self._ch_lock:
                    result = self.client.query(query, parameters=params)
                alerts: List[ThreatAlertSchema] = []
                for row in result.result_rows:
                    ts, alert_id, f_id, t_class, conf, severity, ev_json, alert_status, incident_id, suppressed, source = row
                    ev_dict = json.loads(ev_json) if isinstance(ev_json, str) else ev_json
                    alert = ThreatAlertSchema(
                            timestamp=normalize_utc_timestamp(ts if isinstance(ts, datetime) else datetime.fromisoformat(str(ts))),
                            alert_id=alert_id or None,
                            flow_id=f_id,
                            source_ip=ev_dict.get("source_ip"),
                            source_port=ev_dict.get("source_port"),
                            destination_ip=ev_dict.get("destination_ip"),
                            destination_port=ev_dict.get("destination_port"),
                            protocol=ev_dict.get("protocol"),
                            threat_class=ThreatClassEnum(t_class),
                            confidence_score=float(conf),
                            # Legacy rows written before the severity column existed
                            # carry NULL and are calibrated from their confidence.
                            severity=SeverityEnum(severity) if severity else None,
                            status=self._status_overrides.get(f_id, AlertStatusEnum(alert_status or AlertStatusEnum.NEW.value)),
                            incident_id=incident_id,
                            suppressed=bool(suppressed),
                            source=source or "live",
                            evidence=EvidenceSchema(**ev_dict),
                        )
                    if status and alert.status.value != status:
                        continue
                    alerts.append(alert)
                return alerts
            except Exception as exc:
                logger.error("ClickHouse query failed: %s. Falling back to memory ring buffer.", exc)
                self.is_connected = False

        # In-memory retrieval fallback
        with self._lock:
            all_alerts = list(self._memory_ring)

        filtered = []
        for a in all_alerts:
            if threat_class:
                class_str = a.threat_class.value if isinstance(a.threat_class, ThreatClassEnum) else str(a.threat_class)
                if class_str != threat_class and a.threat_class != threat_class:
                    continue
            if status and a.status.value != status:
                continue
            filtered.append(a)
            if len(filtered) >= limit:
                break

        return filtered

    def update_alert_status(self, flow_id: str, status: AlertStatusEnum) -> Optional[ThreatAlertSchema]:
        """Updates all matching flow records and returns the newest matching alert."""
        updated: Optional[ThreatAlertSchema] = None
        with self._lock:
            self._status_overrides[flow_id] = status
            for index, alert in enumerate(self._memory_ring):
                if alert.flow_id == flow_id:
                    changed = alert.model_copy(update={"status": status})
                    self._memory_ring[index] = changed
                    updated = changed
        if self.is_connected and self.client is not None:
            try:
                with self._ch_lock:
                    self.client.command(
                        f"ALTER TABLE {self.database}.alerts UPDATE status = %(status)s WHERE flow_id = %(flow_id)s",
                        parameters={"status": status.value, "flow_id": flow_id},
                    )
            except Exception as exc:
                logger.error("ClickHouse status update failed: %s", exc)
        return updated

    def add_note(self, note: AnalystNoteSchema) -> AnalystNoteSchema:
        with self._lock:
            if not hasattr(self, "_notes"):
                self._notes: List[AnalystNoteSchema] = []
            self._notes.append(note)
        if self.is_connected and self.client is not None:
            try:
                with self._ch_lock:
                    self.client.insert(f"{self.database}.alert_notes", [[note.flow_id, note.text, note.created_at]], column_names=["flow_id", "text", "created_at"])
            except Exception as exc:
                logger.error("ClickHouse note insert failed: %s", exc)
        return note

    def get_notes(self, flow_id: str) -> List[AnalystNoteSchema]:
        if self.is_connected and self.client is not None:
            try:
                with self._ch_lock:
                    result = self.client.query(f"SELECT flow_id, text, created_at FROM {self.database}.alert_notes WHERE flow_id = %(flow_id)s ORDER BY created_at ASC", parameters={"flow_id": flow_id})
                return [AnalystNoteSchema(flow_id=row[0], text=row[1], created_at=normalize_utc_timestamp(row[2])) for row in result.result_rows]
            except Exception as exc:
                logger.error("ClickHouse note query failed: %s", exc)
        with self._lock:
            return [note for note in getattr(self, "_notes", []) if note.flow_id == flow_id]

    def get_alert_count(self) -> int:
        """Returns total alerts recorded in ClickHouse or in-memory ring buffer."""
        if self.is_connected and self.client is not None:
            try:
                with self._ch_lock:
                    res = self.client.command(f"SELECT count() FROM {self.database}.alerts")
                return int(res)
            except Exception:
                pass

        with self._lock:
            return len(self._memory_ring)
