"""
ThreatLens Detection Models & Aggregator
=======================================
Modular threat detection engines and alert scoring aggregator.
"""

from engine.models.aggregator import AlertAggregator
from engine.models.base import BaseDetectionEngine, DetectionCandidate
from engine.models.beaconing_engine import BeaconingEngine
from engine.models.ddos_engine import DDoSEngine
from engine.models.dns_engine import DNSEngine
from engine.models.exfiltration_engine import ExfiltrationEngine
from engine.models.malware_engine import EncryptedMalwareEngine
from engine.models.recon_engine import ReconEngine

__all__ = [
    "BaseDetectionEngine",
    "DetectionCandidate",
    "DDoSEngine",
    "BeaconingEngine",
    "DNSEngine",
    "EncryptedMalwareEngine",
    "ReconEngine",
    "ExfiltrationEngine",
    "AlertAggregator",
]
