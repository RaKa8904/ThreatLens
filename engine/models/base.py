"""
ThreatLens Base Detection Engine Interface
==========================================
Defines the base contract and result schema for modular threat detection engines.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

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

    def to_evidence(self) -> EvidenceSchema:
        """Converts detection metrics into a validated Pydantic EvidenceSchema."""
        return EvidenceSchema(
            inter_arrival_variance=float(round(max(0.0, self.inter_arrival_variance), 6)),
            shannon_entropy=float(round(max(0.0, self.shannon_entropy), 4)),
            byte_ratio=float(round(max(0.0, self.byte_ratio), 4)),
            fan_out_count=int(max(0, self.fan_out_count)),
            ja3_hash=self.ja3_hash,
            details=self.details,
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
