"""
ThreatLens Core Data Contracts & Schemas
========================================
Standardized Pydantic v2 data models for real-time telemetry,
sliding-window anomaly detection, and threat alert serialization.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Union
from pydantic import BaseModel, Field, ConfigDict, StrictFloat, StrictInt, StrictStr


class FlowEventSchema(BaseModel):
    """
    Canonical network flow telemetry contract consumed by the detection pipeline.
    Mirrors the fields emitted by flow producers (synthetic generator, Zeek shipper).
    ``simulated_label`` is synthetic-generator ground truth, carried as test and
    evaluation metadata only; detection engines must never use it for decisions.
    """
    model_config = ConfigDict(
        extra="ignore",
        json_schema_extra={
            "example": {
                "timestamp": 1760000000.123,
                "flow_id": "192.168.1.105:54321->198.51.100.44:8443",
                "src_ip": "192.168.1.105",
                "src_port": 54321,
                "dst_ip": "198.51.100.44",
                "dst_port": 8443,
                "protocol": "TCP",
                "flags": ["ACK", "PSH"],
                "bytes_out": 128,
                "bytes_in": 64,
                "packets_out": 2,
                "packets_in": 2,
                "dns_query": None,
                "dns_query_type": None,
                "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
                "simulated_label": None,
            }
        },
    )

    timestamp: Union[StrictInt, StrictFloat] = Field(
        ...,
        description="Epoch timestamp of the flow event in seconds",
    )
    flow_id: StrictStr = Field(
        ...,
        min_length=1,
        description="Unique network flow identifier (e.g., 'src_ip:src_port->dst_ip:dst_port')",
    )
    src_ip: StrictStr = Field(
        ...,
        min_length=1,
        description="Source IP address of the flow",
    )
    src_port: StrictInt = Field(
        default=0,
        description="Source TCP/UDP port",
    )
    dst_ip: StrictStr = Field(
        ...,
        min_length=1,
        description="Destination IP address of the flow",
    )
    dst_port: StrictInt = Field(
        ...,
        description="Destination TCP/UDP port",
    )
    protocol: StrictStr = Field(
        default="TCP",
        description="Transport protocol (TCP/UDP/ICMP)",
    )
    flags: List[StrictStr] = Field(
        default_factory=list,
        description="TCP flag names present on the packet (e.g., ['SYN'])",
    )
    bytes_out: int = Field(
        default=0,
        description="Egress bytes in the flow",
    )
    bytes_in: int = Field(
        default=0,
        description="Ingress bytes in the flow",
    )
    packets_out: int = Field(
        default=0,
        description="Egress packet count in the flow",
    )
    packets_in: int = Field(
        default=0,
        description="Ingress packet count in the flow",
    )
    dns_query: Optional[StrictStr] = Field(
        default=None,
        description="DNS query name if the flow is a DNS request",
    )
    dns_query_type: Optional[StrictStr] = Field(
        default=None,
        description="DNS query type (A, TXT, NULL, ...) if applicable",
    )
    ja3_hash: Optional[StrictStr] = Field(
        default=None,
        description="JA3 TLS client fingerprint hash if TLS flow",
    )
    simulated_label: Optional[StrictStr] = Field(
        default=None,
        description="Synthetic ground-truth class label; test/evaluation metadata only, never a detection input",
    )


class ThreatClassEnum(str, Enum):
    """
    Standardized threat categories detected by the ThreatLens analytics pipeline.
    """
    VOLUMETRIC_DOS = "Volumetric & Protocol DDoS"
    BOTNET_C2 = "Botnet C2 Beaconing"
    DGA_DNS = "DGA & DNS Tunneling"
    ENCRYPTED_MALWARE = "Encrypted Malware"
    RECON_SCAN = "Reconnaissance Scan"
    DATA_EXFIL = "Data Exfiltration"


class EvidenceSchema(BaseModel):
    """
    Telemetry and heuristic evidence extracted from sliding-window flow aggregations
    and specialized ML/statistical inference detectors.
    """
    inter_arrival_variance: float = Field(
        ...,
        description="Variance in packet inter-arrival times (IAT) in seconds",
        ge=0.0,
    )
    shannon_entropy: float = Field(
        ...,
        description="Shannon entropy score of flow payloads, IP distributions, or DNS queries",
        ge=0.0,
    )
    byte_ratio: float = Field(
        ...,
        description="Ratio of egress to ingress bytes (outbound / inbound)",
        ge=0.0,
    )
    fan_out_count: int = Field(
        ...,
        description="Count of unique destination IP addresses or ports contacted in window",
        ge=0,
    )
    ja3_hash: Optional[str] = Field(
        default=None,
        description="JA3 TLS client fingerprint hash (32-character hex) if TLS flow",
    )
    details: str = Field(
        ...,
        description="Human-readable context and rationale for the triggered detection rule",
    )

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "inter_arrival_variance": 0.0012,
                "shannon_entropy": 3.82,
                "byte_ratio": 0.08,
                "fan_out_count": 1,
                "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
                "details": "Periodic beaconing detected at 15.0s intervals via jitter-ratio periodicity analysis.",
            }
        },
    )


class ThreatAlertSchema(BaseModel):
    """
    Standardized threat alert published over Kafka, archived in ClickHouse,
    and broadcast via WebSockets to the ThreatLens SOC dashboard.
    """
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the threat alert was evaluated",
    )
    flow_id: str = Field(
        ...,
        description="Unique network flow identifier (e.g., 'src_ip:src_port->dst_ip:dst_port')",
    )
    threat_class: ThreatClassEnum = Field(
        ...,
        description="Classified threat category",
    )
    confidence_score: float = Field(
        ...,
        description="Model or heuristic confidence probability score between 0.0 and 1.0",
        ge=0.0,
        le=1.0,
    )
    evidence: EvidenceSchema = Field(
        ...,
        description="Structured forensic evidence supporting the alert classification",
    )

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "timestamp": "2026-09-12T01:00:00.000Z",
                "flow_id": "192.168.1.105:54321->10.0.0.1:443",
                "threat_class": "Botnet C2 Beaconing",
                "confidence_score": 0.94,
                "evidence": {
                    "inter_arrival_variance": 0.0012,
                    "shannon_entropy": 3.82,
                    "byte_ratio": 0.08,
                    "fan_out_count": 1,
                    "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
                    "details": "Periodic beaconing detected at 15.0s intervals via jitter-ratio periodicity analysis.",
                },
            }
        },
    )
