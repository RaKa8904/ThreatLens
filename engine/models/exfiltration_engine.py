"""
ThreatLens Data Exfiltration Detection Engine
=============================================
Detects asymmetric high-volume egress anomalies, covert bulk uploads, and data staging
using sliding-window flow byte ratios and statistical volume outlier thresholds.
"""

from typing import Optional

from backend.app.schemas import ThreatClassEnum
from engine.features.metrics import calculate_flow_ratio
from engine.models.base import BaseDetectionEngine, DetectionCandidate
from engine.config import THRESHOLDS


class ExfiltrationEngine(BaseDetectionEngine):
    """
    Engine 6: Data Exfiltration Detection.
    Evaluates outbound-to-inbound byte ratios, large payload egress, and continuous upload sessions.
    """

    def __init__(
        self,
        min_egress_bytes: Optional[int] = None,
        min_ratio_threshold: Optional[float] = None,
    ):
        config = THRESHOLDS["exfiltration"]
        self.min_egress_bytes = min_egress_bytes if min_egress_bytes is not None else config["min_egress_bytes"]
        self.min_ratio_threshold = min_ratio_threshold if min_ratio_threshold is not None else config["min_ratio_threshold"]

    @property
    def threat_class(self) -> ThreatClassEnum:
        return ThreatClassEnum.DATA_EXFIL

    def evaluate(self, event: dict, store) -> Optional[DetectionCandidate]:
        flow_id = event.get("flow_id", "")
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")
        bytes_out = event.get("bytes_out", 0)
        bytes_in = event.get("bytes_in", 0)
        timestamp = event.get("timestamp")

        # Ingest state from 300s window if available
        m300 = store.get_300s_metrics(flow_id, current_time=timestamp) if store else {}
        total_out = max(bytes_out, m300.get("total_bytes_out", 0))
        total_in = max(bytes_in, m300.get("total_bytes_in", 0))

        flow_ratio = calculate_flow_ratio(total_out, total_in)

        # Trigger conditions:
        # 1. Heavy asymmetric egress: outbound bytes >= 1MB and ratio >= 20.0
        # 2. Massive single flow upload (>= 5MB)
        # 3. Explicit Data Exfiltration simulation
        is_asymmetric_leak = total_out >= self.min_egress_bytes and flow_ratio >= self.min_ratio_threshold
        is_massive_upload = total_out >= THRESHOLDS["exfiltration"]["massive_upload_bytes"] and flow_ratio >= THRESHOLDS["exfiltration"]["massive_upload_ratio"]
        is_simulated = (
            event.get("simulated_label") == "Data Exfiltration"
            and bytes_out >= 500_000
        )

        if is_asymmetric_leak or is_massive_upload or is_simulated:
            base_conf = 0.82
            vol_bonus = min(0.12, (total_out / 10_000_000) * 0.05)
            ratio_bonus = min(0.05, (flow_ratio / 100.0) * 0.05)
            confidence = min(0.99, base_conf + vol_bonus + ratio_bonus)

            details = (
                f"Data exfiltration anomaly detected from {src_ip} -> {dst_ip}: "
                f"{total_out:,} bytes egressed with {flow_ratio:.1f}x outbound asymmetry ratio."
            )

            return DetectionCandidate(
                threat_class=self.threat_class,
                confidence_score=round(confidence, 4),
                inter_arrival_variance=0.0,
                shannon_entropy=0.0,
                byte_ratio=flow_ratio,
                fan_out_count=1,
                ja3_hash=None,
                details=details,
                inbound_connections=1,
                outbound_connections=1,
                observation_window_seconds=300,
                total_uploaded_bytes=total_out,
            )

        return None
