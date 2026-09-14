"""
ThreatLens Detection Pipeline Orchestrator
==========================================
Coordinates telemetry ingestion into multi-tier sliding windows, dispatches
events across all specialized detection models, and outputs standardized ThreatAlertSchema alerts.
"""

import asyncio
from datetime import datetime, timezone
import ipaddress
import time
from typing import List, Optional

from backend.app.schemas import ThreatAlertSchema
from engine.features.store import SlidingWindowStore
from engine.models.aggregator import AlertAggregator


class DetectionPipeline:
    """
    End-to-end detection pipeline managing stateful sliding windows
    and unified multi-engine alert evaluation.
    """

    def __init__(
        self,
        store: Optional[SlidingWindowStore] = None,
        aggregator: Optional[AlertAggregator] = None,
        suppression_provider=None,
    ):
        self.store = store if store is not None else SlidingWindowStore(use_redis=True)
        self.aggregator = aggregator if aggregator is not None else AlertAggregator()
        self.suppression_provider = suppression_provider

    @staticmethod
    def _ip_matches(value: str, criterion: str) -> bool:
        try:
            return ipaddress.ip_address(value) in ipaddress.ip_network(criterion, strict=False)
        except ValueError:
            return value == criterion

    def _is_suppressed(self, alert: ThreatAlertSchema) -> bool:
        if self.suppression_provider is None:
            return False
        for rule in self.suppression_provider.get_active_suppression_rules():
            if rule.expires_at and rule.expires_at <= datetime.now(timezone.utc):
                continue
            source_match = bool(alert.source_ip and rule.source_ip and self._ip_matches(alert.source_ip, rule.source_ip))
            destination_match = bool(alert.destination_ip and rule.destination_ip and self._ip_matches(alert.destination_ip, rule.destination_ip))
            class_match = not rule.threat_class or alert.threat_class == rule.threat_class
            if rule.rule_type == "source_ip" and source_match:
                return True
            if rule.rule_type == "destination_ip" and destination_match:
                return True
            if rule.rule_type == "source_ip_threat_class" and source_match and class_match:
                return True
        return False

    def ingest_to_store(self, event: dict) -> None:
        """Updates rolling sliding windows with current flow event telemetry."""
        src_ip = event.get("src_ip", "0.0.0.0")
        dst_ip = event.get("dst_ip", "0.0.0.0")
        dst_port = event.get("dst_port", 0)
        flow_id = event.get("flow_id") or f"{src_ip}:{event.get('src_port', 0)}->{dst_ip}:{dst_port}"
        timestamp = float(event.get("timestamp") or time.time())
        bytes_out = int(event.get("bytes_out", 0))
        bytes_in = int(event.get("bytes_in", 0))
        flags = event.get("flags", [])
        ja3_hash = event.get("ja3_hash")
        dns_query = event.get("dns_query")
        dns_query_type = event.get("dns_query_type", "A")

        is_syn = "SYN" in flags

        # 1. Update 10s Volumetric & Fan-out window
        self.store.record_10s_packet(
            src_ip=src_ip,
            timestamp=timestamp,
            dst_endpoint=f"{dst_ip}:{dst_port}",
            is_syn=is_syn,
            byte_count=bytes_out,
            target_key=f"target:{dst_ip}:{dst_port}",
        )

        # 2. Update 60s DNS window (if DNS telemetry present)
        if dns_query or dst_port == 53:
            self.store.record_60s_dns(
                src_ip=src_ip,
                timestamp=timestamp,
                domain=dns_query or "unknown.domain",
                query_type=dns_query_type or "A",
            )

        # 3. Update 60s Reconnaissance window
        self.store.record_60s_recon(
            src_ip=src_ip,
            timestamp=timestamp,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )

        # 4. Update 300s Long-Range C2 & Exfiltration window
        self.store.record_300s_flow(
            flow_id=flow_id,
            timestamp=timestamp,
            bytes_out=bytes_out,
            bytes_in=bytes_in,
            ja3_hash=ja3_hash,
        )

    def process_flow_event(self, event: dict) -> List[ThreatAlertSchema]:
        """
        Ingests flow into stateful feature store, executes all detection engines,
        and returns validated ThreatAlertSchema alerts.
        """
        # Step 1: Update sliding window feature store
        self.ingest_to_store(event)

        # Step 2: Evaluate detection engines via AlertAggregator
        alerts = self.aggregator.aggregate(event, self.store)

        return [alert.model_copy(update={"suppressed": self._is_suppressed(alert)}) for alert in alerts]

    async def async_process_flow_event(self, event: dict) -> List[ThreatAlertSchema]:
        """Asynchronous wrapper for non-blocking event loop execution."""
        return await asyncio.to_thread(self.process_flow_event, event)


# Global Default Pipeline Instance
default_pipeline = DetectionPipeline()


def process_flow_event(event: dict) -> List[ThreatAlertSchema]:
    """Callable functional entrypoint for single-event pipeline processing."""
    return default_pipeline.process_flow_event(event)
