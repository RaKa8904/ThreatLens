"""
ThreatLens Detection Pipeline Orchestrator
==========================================
Coordinates telemetry ingestion into multi-tier sliding windows, dispatches
events across all specialized detection models, and outputs standardized ThreatAlertSchema alerts.

Canonical event contract: FlowEventSchema (backend/app/schemas.py). Events that
fail contract validation are rejected before touching the feature store.

Dispatch rules per validated event:
  - 10s window: every event records packet telemetry (SYN flag, byte count,
    destination endpoint) for volumetric burst and fan-out tracking.
  - 60s window: DNS queries (dst_port 53 with a dns_query payload) record
    domain telemetry; TCP flows carrying a SYN flag record reconnaissance
    probes (prototype deviation: recon uses the 60s tier; the blueprint
    specifies a 5s tier).
  - 300s window: every event records flow telemetry (byte asymmetry, JA3
    fingerprints, inter-arrival timing) for C2 beaconing and exfiltration
    tracking.
"""

import asyncio
from typing import List, Optional

from pydantic import ValidationError

from backend.app.schemas import FlowEventSchema, ThreatAlertSchema
from engine.features.store import SlidingWindowStore
from engine.models.aggregator import AlertAggregator


class DetectionPipeline:
    """
    End-to-end detection pipeline managing stateful sliding windows
    and unified multi-engine alert evaluation. Sole owner of the
    event-to-feature-store dispatch logic.
    """

    def __init__(
        self,
        store: Optional[SlidingWindowStore] = None,
        aggregator: Optional[AlertAggregator] = None,
    ):
        self.store = store if store is not None else SlidingWindowStore(use_redis=True)
        self.aggregator = aggregator if aggregator is not None else AlertAggregator()

    def ingest_to_store(self, event: dict) -> bool:
        """
        Validates the event against FlowEventSchema and updates rolling sliding
        windows with the flow telemetry. Returns True if ingested, False if the
        event was rejected.
        """
        try:
            flow = FlowEventSchema.model_validate(event)
        except ValidationError:
            return False

        timestamp = float(flow.timestamp)
        is_syn = "SYN" in flow.flags

        # 1. Update 10s Volumetric & Fan-out window
        self.store.record_10s_packet(
            src_ip=flow.src_ip,
            timestamp=timestamp,
            dst_endpoint=f"{flow.dst_ip}:{flow.dst_port}",
            is_syn=is_syn,
            byte_count=flow.bytes_out,
        )

        # 2. Update 60s DNS window (only real DNS telemetry: query payload on port 53)
        if flow.dns_query and flow.dst_port == 53:
            self.store.record_60s_dns(
                src_ip=flow.src_ip,
                timestamp=timestamp,
                domain=flow.dns_query,
                query_type=flow.dns_query_type or "A",
                query_len=len(flow.dns_query),
            )

        # 3. Update 60s Reconnaissance window (SYN-carrying TCP probes only)
        if is_syn and flow.protocol == "TCP":
            self.store.record_60s_recon(
                src_ip=flow.src_ip,
                timestamp=timestamp,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
            )

        # 4. Update 300s Long-Range C2 & Exfiltration window
        self.store.record_300s_flow(
            flow_id=flow.flow_id,
            timestamp=timestamp,
            bytes_out=flow.bytes_out,
            bytes_in=flow.bytes_in,
            ja3_hash=flow.ja3_hash,
        )
        return True

    def try_process_flow_event(self, event: dict) -> Optional[List[ThreatAlertSchema]]:
        """
        Ingests the flow into the stateful feature store and executes all
        detection engines. Returns None if the event was rejected by contract
        validation, otherwise the (possibly empty) list of validated alerts.
        """
        if not self.ingest_to_store(event):
            return None
        return self.aggregator.aggregate(event, self.store)

    def process_flow_event(self, event: dict) -> List[ThreatAlertSchema]:
        """
        Ingests flow into stateful feature store, executes all detection engines,
        and returns validated ThreatAlertSchema alerts. Invalid events yield [].
        """
        return self.try_process_flow_event(event) or []

    async def async_process_flow_event(self, event: dict) -> List[ThreatAlertSchema]:
        """Asynchronous wrapper for non-blocking event loop execution."""
        return await asyncio.to_thread(self.process_flow_event, event)
