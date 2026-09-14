"""
ThreatLens Unified Alert Aggregator & Scorer
============================================
Dispatches network telemetry across all 6 specialized detection engines,
performs multi-signal confidence scoring, and produces validated ThreatAlertSchema alerts.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import logging
import threading
import uuid
from typing import List, Optional

from backend.app.schemas import EvidenceSchema, ThreatAlertSchema
from engine.models.base import BaseDetectionEngine, DetectionCandidate
from engine.models.beaconing_engine import BeaconingEngine
from engine.models.ddos_engine import DDoSEngine
from engine.models.dns_engine import DNSEngine
from engine.models.exfiltration_engine import ExfiltrationEngine
from engine.models.malware_engine import EncryptedMalwareEngine
from engine.models.recon_engine import ReconEngine
from engine.config import THRESHOLDS

logger = logging.getLogger(__name__)


class AlertAggregator:
    """
    Unified multi-engine detection orchestrator and alert confidence scorer.
    """

    def __init__(self, engines: Optional[List[BaseDetectionEngine]] = None, max_workers: int = 6):
        if engines is not None:
            self.engines = engines
        else:
            self.engines = [
                DDoSEngine(),
                BeaconingEngine(),
                DNSEngine(),
                EncryptedMalwareEngine(),
                ReconEngine(),
                ExfiltrationEngine(),
            ]
        self.max_workers = max_workers
        self.correlation_window_seconds = THRESHOLDS["correlation"]["window_seconds"]
        self._source_incidents: dict[str, tuple[float, str]] = {}
        self._correlation_lock = threading.Lock()

    def _incident_id_for_source(self, source_ip: Optional[str], timestamp: float) -> Optional[str]:
        if not source_ip:
            return None
        with self._correlation_lock:
            previous = self._source_incidents.get(source_ip)
            if previous and timestamp - previous[0] <= self.correlation_window_seconds:
                incident_id = previous[1]
            else:
                incident_id = str(uuid.uuid4())
            self._source_incidents[source_ip] = (timestamp, incident_id)
            cutoff = timestamp - self.correlation_window_seconds
            self._source_incidents = {
                key: value for key, value in self._source_incidents.items() if value[0] >= cutoff
            }
            return incident_id

    def _evaluate_single_engine(
        self,
        engine: BaseDetectionEngine,
        event: dict,
        store: any,
    ) -> Optional[DetectionCandidate]:
        """Safely invokes a single engine evaluation with exception trapping."""
        try:
            return engine.evaluate(event, store)
        except Exception as exc:
            logger.error("Engine %s evaluation error: %s", engine.__class__.__name__, exc)
            return None

    def aggregate(self, event: dict, store: any) -> List[ThreatAlertSchema]:
        """
        Dispatches incoming network flow event across all engines concurrently,
        normalizes confidence scores, correlates multi-engine signals,
        and returns validated ThreatAlertSchema alerts.

        Args:
            event: Canonical network flow dictionary.
            store: SlidingWindowStore instance.

        Returns:
            List[ThreatAlertSchema]: Validated alert instances.
        """
        candidates: List[DetectionCandidate] = []

        # Execute engines concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                executor.submit(self._evaluate_single_engine, engine, event, store)
                for engine in self.engines
            ]
            for future in futures:
                result = future.result()
                if result is not None:
                    candidates.append(result)

        if not candidates:
            return []

        # Extract flow metadata
        flow_id = event.get("flow_id")
        if not flow_id:
            src_ip = event.get("src_ip", "0.0.0.0")
            src_port = event.get("src_port", 0)
            dst_ip = event.get("dst_ip", "0.0.0.0")
            dst_port = event.get("dst_port", 0)
            flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"

        # Resolve timestamp
        event_ts = event.get("timestamp")
        if isinstance(event_ts, (int, float)):
            alert_time = datetime.fromtimestamp(event_ts, tz=timezone.utc)
        elif isinstance(event_ts, str):
            try:
                alert_time = datetime.fromisoformat(event_ts.replace("Z", "+00:00"))
            except Exception:
                alert_time = datetime.now(timezone.utc)
        else:
            alert_time = datetime.now(timezone.utc)

        # Multi-engine corroboration bonus (if multiple models flag the same flow simultaneously)
        corroboration_bonus = 0.03 if len(candidates) > 1 else 0.0

        alerts: List[ThreatAlertSchema] = []
        incident_id = self._incident_id_for_source(event.get("src_ip"), alert_time.timestamp())
        for candidate in candidates:
            # Normalize and clamp confidence score into [0.00, 1.00]
            final_conf = min(1.0, max(0.0, candidate.confidence_score + corroboration_bonus))
            normalized_score = float(round(final_conf, 2))

            evidence = candidate.to_evidence().model_copy(update={
                "packets_in": event.get("packets_in"),
                "packets_out": event.get("packets_out"),
                "inbound_bytes": event.get("bytes_in"),
                "outbound_bytes": event.get("bytes_out"),
                "source_ip": event.get("src_ip"),
                "source_port": event.get("src_port"),
                "destination_ip": event.get("dst_ip"),
                "destination_port": event.get("dst_port"),
                "protocol": event.get("protocol"),
                "ja4_hash": event.get("ja4_hash"),
                "sni": event.get("sni"),
                "splt_packet_sizes": event.get("splt_packet_sizes"),
                "splt_interarrival_times": event.get("splt_interarrival_times"),
                "dns_query": event.get("dns_query"),
                "dns_query_length": len(event["dns_query"]) if event.get("dns_query") else None,
                "dns_query_type": event.get("dns_query_type"),
                "detectors_fired": [item.threat_class.value for item in candidates],
                "detector_count": len(candidates),
                "confidence_basis": (
                    f"{len(candidates)} detectors corroborated; +{corroboration_bonus:.2f} bonus"
                    if len(candidates) > 1
                    else "Single detector result; no corroboration bonus"
                ),
            })
            alert = ThreatAlertSchema(
                timestamp=alert_time,
                flow_id=flow_id,
                source_ip=event.get("src_ip"),
                source_port=event.get("src_port"),
                destination_ip=event.get("dst_ip"),
                destination_port=event.get("dst_port"),
                protocol=event.get("protocol"),
                threat_class=candidate.threat_class,
                confidence_score=normalized_score,
                incident_id=incident_id,
                source=event.get("source", "live"),
                evidence=evidence,
            )
            alerts.append(alert)

        return alerts
