"""
ThreatLens Core Data Contracts & Schemas
========================================
Standardized Pydantic v2 data models for real-time telemetry,
sliding-window anomaly detection, and threat alert serialization.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


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
    packets_in: Optional[int] = Field(default=None, ge=0)
    packets_out: Optional[int] = Field(default=None, ge=0)
    inbound_connections: Optional[int] = Field(default=None, ge=0)
    outbound_connections: Optional[int] = Field(default=None, ge=0)
    port_connections: Optional[int] = Field(default=None, ge=0)
    inbound_bytes: Optional[int] = Field(default=None, ge=0)
    outbound_bytes: Optional[int] = Field(default=None, ge=0)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = None
    observation_window_seconds: Optional[int] = Field(default=None, ge=0)

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "inter_arrival_variance": 0.0012,
                "shannon_entropy": 3.82,
                "byte_ratio": 0.08,
                "fan_out_count": 1,
                "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
                "details": "Periodic beaconing detected at 15.0s intervals via FFT harmonic analysis.",
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
                    "details": "Periodic beaconing detected at 15.0s intervals via FFT harmonic analysis.",
                },
            }
        },
    )
