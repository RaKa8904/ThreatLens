"""
ThreatLens Core Data Contracts & Schemas
========================================
Standardized Pydantic v2 data models for real-time telemetry,
sliding-window anomaly detection, and threat alert serialization.
"""

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Literal, Optional
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator


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


class AlertStatusEnum(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AnalystNoteCreate(BaseModel):
    text: str = Field(..., min_length=1, max_length=10_000)


class AnalystNoteSchema(BaseModel):
    flow_id: str
    text: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def _validated_ip_criterion(value: Optional[str]) -> Optional[str]:
    """Accepts an IPv4/IPv6 address or CIDR network. None passes through."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("must be a string IP address or CIDR network")
    criterion = value.strip()
    if not criterion:
        raise ValueError("must not be empty")
    try:
        ipaddress.ip_network(criterion, strict=False)
    except ValueError:
        raise ValueError(f"{value!r} is not a valid IP address or CIDR network")
    return criterion


def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
    """Coerces an optional timestamp to timezone-aware UTC."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class SuppressionRule(BaseModel):
    id: str
    rule_type: Literal["source_ip", "destination_ip", "source_ip_threat_class"]
    description: Optional[str] = Field(default=None, max_length=500)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    threat_class: Optional[ThreatClassEnum] = None
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_criteria(cls, value: Optional[str]) -> Optional[str]:
        return _validated_ip_criterion(value)

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: Optional[datetime]) -> Optional[datetime]:
        return _as_utc(value)

    @model_validator(mode="after")
    def validate_target(self) -> "SuppressionRule":
        if self.rule_type in ("source_ip", "source_ip_threat_class") and not self.source_ip:
            raise ValueError(f"rule_type '{self.rule_type}' requires source_ip")
        if self.rule_type == "destination_ip" and not self.destination_ip:
            raise ValueError("rule_type 'destination_ip' requires destination_ip")
        return self


class SuppressionRuleCreate(BaseModel):
    rule_type: Literal["source_ip", "destination_ip", "source_ip_threat_class"]
    description: Optional[str] = Field(default=None, max_length=500)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    threat_class: Optional[ThreatClassEnum] = None
    enabled: bool = True
    expires_at: Optional[datetime] = None

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_criteria(cls, value: Optional[str]) -> Optional[str]:
        return _validated_ip_criterion(value)

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: Optional[datetime]) -> Optional[datetime]:
        return _as_utc(value)

    @model_validator(mode="after")
    def validate_target(self) -> "SuppressionRuleCreate":
        if self.rule_type in ("source_ip", "source_ip_threat_class") and not self.source_ip:
            raise ValueError(f"rule_type '{self.rule_type}' requires source_ip")
        if self.rule_type == "destination_ip" and not self.destination_ip:
            raise ValueError("rule_type 'destination_ip' requires destination_ip")
        return self


class ThresholdEntry(BaseModel):
    """One analyst-configurable detector threshold with its metadata and live value."""

    rule: str
    rule_label: str
    parameter: str
    label: str
    description: str
    kind: Literal["int", "float", "int_list"]
    min: Optional[float] = None
    max: Optional[float] = None
    value: Any
    default: Any
    modified: bool
    consumed_by: str
    active: bool


class ThresholdConfigResponse(BaseModel):
    """
    Runtime threshold configuration.

    `persistent` is False when the configuration store has no durable backend, in
    which case changes apply immediately but are lost on restart.
    """

    storage_mode: Literal["redis", "memory"]
    persistent: bool
    thresholds: List[ThresholdEntry]


class ThresholdUpdateRequest(BaseModel):
    """A single threshold change. The value is validated against its rule spec."""

    rule: str = Field(..., min_length=1, max_length=64)
    parameter: str = Field(..., min_length=1, max_length=64)
    value: Any


class ThresholdResetResponse(BaseModel):
    storage_mode: Literal["redis", "memory"]
    persistent: bool
    thresholds: List[ThresholdEntry]


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
    ja4_hash: Optional[str] = Field(default=None, description="JA4 TLS fingerprint if available")
    sni: Optional[str] = Field(default=None, description="TLS Server Name Indication")
    splt_packet_sizes: Optional[List[int]] = Field(default=None, description="SPLT packet-size sequence")
    splt_interarrival_times: Optional[List[float]] = Field(default=None, description="SPLT inter-arrival sequence")
    fft_concentration: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    beacon_period_seconds: Optional[float] = Field(default=None, ge=0.0)
    inter_arrival_stddev: Optional[float] = Field(default=None, ge=0.0)
    dns_query: Optional[str] = None
    dns_query_length: Optional[int] = Field(default=None, ge=0)
    dns_query_type: Optional[str] = None
    ngram_score: Optional[float] = Field(default=None, ge=0.0)
    packets_per_second: Optional[float] = Field(default=None, ge=0.0)
    z_score: Optional[float] = None
    source_ip_entropy: Optional[float] = Field(default=None, ge=0.0)
    unique_destination_hosts: Optional[int] = Field(default=None, ge=0)
    unique_destination_ports: Optional[int] = Field(default=None, ge=0)
    window_10s_fan_out: Optional[int] = Field(default=None, ge=0)
    window_60s_fan_out: Optional[int] = Field(default=None, ge=0)
    unique_source_count: Optional[int] = Field(default=None, ge=0)
    total_uploaded_bytes: Optional[int] = Field(default=None, ge=0)
    detectors_fired: List[str] = Field(default_factory=list)
    detector_count: int = Field(default=1, ge=1)
    confidence_basis: Optional[str] = None
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
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
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
    source_ip: Optional[str] = None
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[str] = None
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
    status: AlertStatusEnum = AlertStatusEnum.NEW
    incident_id: Optional[str] = None
    suppressed: bool = Field(
        default=False,
        description=(
            "True when an analyst suppression rule matched. The detection is still "
            "recorded with full evidence; only analyst delivery is withheld."
        ),
    )
    suppression_rule_id: Optional[str] = Field(
        default=None,
        description="Id of the suppression rule that withheld this alert, when suppressed.",
    )
    source: Literal["live", "replay"] = "live"
    ingest_latency_ms: Optional[float] = Field(default=None, ge=0.0)
    processing_latency_ms: Optional[float] = Field(default=None, ge=0.0)
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
