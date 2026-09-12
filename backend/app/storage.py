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

from backend.app.schemas import EvidenceSchema, ThreatAlertSchema, ThreatClassEnum

logger = logging.getLogger(__name__)


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

        # In-memory circular buffer fallback (Thread-safe)
        self._memory_ring: deque[ThreatAlertSchema] = deque(maxlen=max_memory_buffer)
        self._lock = threading.Lock()

        if auto_connect:
            self.connect()

    def connect(self) -> bool:
        """Attempts to establish connection with ClickHouse and initialize tables."""
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

            self.client = client
            self.is_connected = True
            logger.info("Connected to ClickHouse at %s:%s (db=%s)", self.host, self.port, self.database)
            return True
        except Exception as exc:
            logger.warning(
                "ClickHouse unavailable (%s). Operating in-memory alert ring buffer fallback.",
                exc,
            )
            self.client = None
            self.is_connected = False
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
                alert.flow_id,
                alert.threat_class.value if isinstance(alert.threat_class, ThreatClassEnum) else str(alert.threat_class),
                float(alert.confidence_score),
                evidence.model_dump_json(),
                float(evidence.inter_arrival_variance),
                float(evidence.shannon_entropy),
                float(evidence.byte_ratio),
                int(evidence.fan_out_count),
                evidence.ja3_hash,
                evidence.details,
            ]
            columns = [
                "timestamp", "flow_id", "threat_class", "confidence_score",
                "evidence_json", "inter_arrival_variance", "shannon_entropy",
                "byte_ratio", "fan_out_count", "ja3_hash", "details"
            ]
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
    ) -> List[ThreatAlertSchema]:
        """
        Retrieves recent alerts from ClickHouse or falls back to in-memory ring buffer.
        """
        if self.is_connected and self.client is not None:
            try:
                query = f"""
                SELECT timestamp, flow_id, threat_class, confidence_score, evidence_json
                FROM {self.database}.alerts
                """
                params: Dict[str, Any] = {"limit": limit}
                if threat_class:
                    query += " WHERE threat_class = %(threat_class)s"
                    params["threat_class"] = threat_class

                query += " ORDER BY timestamp DESC LIMIT %(limit)s"

                result = self.client.query(query, parameters=params)
                alerts: List[ThreatAlertSchema] = []
                for row in result.result_rows:
                    ts, f_id, t_class, conf, ev_json = row
                    ev_dict = json.loads(ev_json) if isinstance(ev_json, str) else ev_json
                    alerts.append(
                        ThreatAlertSchema(
                            timestamp=ts if isinstance(ts, datetime) else datetime.fromisoformat(str(ts)),
                            flow_id=f_id,
                            threat_class=ThreatClassEnum(t_class),
                            confidence_score=float(conf),
                            evidence=EvidenceSchema(**ev_dict),
                        )
                    )
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
            filtered.append(a)
            if len(filtered) >= limit:
                break

        return filtered

    def get_alert_count(self) -> int:
        """Returns total alerts recorded in ClickHouse or in-memory ring buffer."""
        if self.is_connected and self.client is not None:
            try:
                res = self.client.command(f"SELECT count() FROM {self.database}.alerts")
                return int(res)
            except Exception:
                pass

        with self._lock:
            return len(self._memory_ring)
