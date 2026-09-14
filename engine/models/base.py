"""
ThreatLens Base Detection Engine Interface
==========================================
Defines the base contract and result schema for modular threat detection engines.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from backend.app.schemas import EvidenceSchema, ThreatClassEnum


@dataclass
class DetectionCandidate:
    """
    Intermediate detection candidate produced by an individual detection engine
    prior to final confidence normalization and alert aggregation.
    """
    threat_class: ThreatClassEnum
    confidence_score: float
    inter_arrival_variance: float = 0.0
    shannon_entropy: float = 0.0
    byte_ratio: float = 0.0
    fan_out_count: int = 0
    ja3_hash: Optional[str] = None
    details: str = ""
    inbound_connections: Optional[int] = None
    outbound_connections: Optional[int] = None
    port_connections: Optional[int] = None
    observation_window_seconds: Optional[int] = None
    ja4_hash: Optional[str] = None
    sni: Optional[str] = None
    splt_packet_sizes: Optional[List[int]] = None
    splt_interarrival_times: Optional[List[float]] = None
    fft_concentration: Optional[float] = None
    beacon_period_seconds: Optional[float] = None
    inter_arrival_stddev: Optional[float] = None
    dns_query: Optional[str] = None
    dns_query_length: Optional[int] = None
    dns_query_type: Optional[str] = None
    ngram_score: Optional[float] = None
    packets_per_second: Optional[float] = None
    z_score: Optional[float] = None
    source_ip_entropy: Optional[float] = None
    unique_destination_hosts: Optional[int] = None
    unique_destination_ports: Optional[int] = None
    window_10s_fan_out: Optional[int] = None
    window_60s_fan_out: Optional[int] = None
    total_uploaded_bytes: Optional[int] = None

    def to_evidence(self) -> EvidenceSchema:
        """Converts detection metrics into a validated Pydantic EvidenceSchema."""
        return EvidenceSchema(
            inter_arrival_variance=float(round(max(0.0, self.inter_arrival_variance), 6)),
            shannon_entropy=float(round(max(0.0, self.shannon_entropy), 4)),
            byte_ratio=float(round(max(0.0, self.byte_ratio), 4)),
            fan_out_count=int(max(0, self.fan_out_count)),
            ja3_hash=self.ja3_hash,
            ja4_hash=self.ja4_hash,
            sni=self.sni,
            splt_packet_sizes=self.splt_packet_sizes,
            splt_interarrival_times=self.splt_interarrival_times,
            fft_concentration=self.fft_concentration,
            beacon_period_seconds=self.beacon_period_seconds,
            inter_arrival_stddev=self.inter_arrival_stddev,
            dns_query=self.dns_query,
            dns_query_length=self.dns_query_length,
            dns_query_type=self.dns_query_type,
            ngram_score=self.ngram_score,
            packets_per_second=self.packets_per_second,
            z_score=self.z_score,
            source_ip_entropy=self.source_ip_entropy,
            unique_destination_hosts=self.unique_destination_hosts,
            unique_destination_ports=self.unique_destination_ports,
            window_10s_fan_out=self.window_10s_fan_out,
            window_60s_fan_out=self.window_60s_fan_out,
            total_uploaded_bytes=self.total_uploaded_bytes,
            details=self.details,
            inbound_connections=self.inbound_connections,
            outbound_connections=self.outbound_connections,
            port_connections=self.port_connections,
            observation_window_seconds=self.observation_window_seconds,
        )


class BaseDetectionEngine(ABC):
    """Abstract base class for all ThreatLens specialized detection engines."""

    @property
    @abstractmethod
    def threat_class(self) -> ThreatClassEnum:
        """The threat classification handled by this engine."""
        pass

    @abstractmethod
    def evaluate(self, event: dict, store) -> Optional[DetectionCandidate]:
        """
        Evaluates an incoming flow event against historical window state.

        Args:
            event: Canonical network flow dictionary.
            store: SlidingWindowStore instance containing multi-tier rolling windows.

        Returns:
            Optional[DetectionCandidate]: Detection candidate if anomaly detected, else None.
        """
        pass
