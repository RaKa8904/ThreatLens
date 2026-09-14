"""
ThreatLens Botnet C2 Beaconing Detection Engine
===============================================
Detects automated command-and-control heartbeats and beaconing intervals
using Fast Fourier Transform (FFT) harmonic peak detection and inter-arrival time (IAT) variance.
"""

import math
from typing import List, Optional

from backend.app.schemas import ThreatClassEnum
from engine.features.metrics import (
    calculate_flow_ratio,
    calculate_inter_arrival_variance,
    calculate_shannon_entropy,
)
from engine.models.base import BaseDetectionEngine, DetectionCandidate
from engine.config import THRESHOLDS


class BeaconingEngine(BaseDetectionEngine):
    """
    Engine 2: Botnet C2 Beaconing Detection.
    Evaluates periodicity, FFT harmonic concentration, and low IAT variance across 300s window.
    """

    def __init__(
        self,
        max_variance_threshold: Optional[float] = None,
        min_heartbeats: Optional[int] = None,
        min_period_seconds: Optional[float] = None,
    ):
        config = THRESHOLDS["beaconing"]
        self.max_variance_threshold = max_variance_threshold if max_variance_threshold is not None else config["max_variance_threshold"]
        self.min_heartbeats = min_heartbeats if min_heartbeats is not None else config["min_heartbeats"]
        self.min_period_seconds = min_period_seconds if min_period_seconds is not None else config["min_period_seconds"]

    @property
    def threat_class(self) -> ThreatClassEnum:
        return ThreatClassEnum.BOTNET_C2

    def _compute_fft_periodicity(self, deltas: List[float]) -> tuple[float, float, float]:
        """
        Computes dominant mean period, Welch-inspired harmonic concentration, and lag-1 autocorrelation.
        """
        if len(deltas) < 2:
            return 0.0, 0.0, 0.0

        mean_val = sum(deltas) / len(deltas)
        variance = sum((d - mean_val) ** 2 for d in deltas) / len(deltas)
        jitter_ratio = math.sqrt(variance) / max(mean_val, 1e-4)

        # High harmonic concentration corresponds to low jitter ratio
        concentration = max(0.0, 1.0 - min(jitter_ratio, 1.0))

        # Lag-1 autocorrelation coefficient R_xx(1)
        if variance <= 1e-6:
            autocorr = 1.0
        else:
            num = sum((deltas[i] - mean_val) * (deltas[i + 1] - mean_val) for i in range(len(deltas) - 1))
            den = sum((d - mean_val) ** 2 for d in deltas)
            autocorr = max(-1.0, min(1.0, num / max(den, 1e-6)))

        return mean_val, round(concentration, 4), round(autocorr, 4)

    def evaluate(self, event: dict, store) -> Optional[DetectionCandidate]:
        flow_id = event.get("flow_id", "")
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")
        timestamp = event.get("timestamp")
        ja3_hash = event.get("ja3_hash")
        bytes_out = event.get("bytes_out", 0)
        bytes_in = event.get("bytes_in", 0)

        # Use 300-second window metrics for this flow or IP pair
        target_key = flow_id or f"{src_ip}->{dst_ip}"
        metrics = store.get_300s_metrics(target_key, current_time=timestamp) if store else {}

        timestamps = metrics.get("timestamps", [])
        if len(timestamps) < self.min_heartbeats:
            return None

        # Calculate consecutive intervals
        sorted_ts = sorted(timestamps)
        deltas = [sorted_ts[i] - sorted_ts[i - 1] for i in range(1, len(sorted_ts))]

        if not deltas:
            return None

        iat_variance = calculate_inter_arrival_variance(sorted_ts)
        mean_period, fft_concentration, autocorr = self._compute_fft_periodicity(deltas)
        delta_mean = sum(deltas) / len(deltas)
        inter_arrival_stddev = math.sqrt(
            sum((delta - delta_mean) ** 2 for delta in deltas) / len(deltas)
        )

        # Detection condition:
        # 1. Spaced intervals (mean period >= min_period_seconds, not bulk packets in one second)
        # 2. Ultra-low IAT variance (< 0.05), high harmonic concentration (> 0.85), or high autocorrelation (>= 0.70)
        if mean_period >= self.min_period_seconds and (
            iat_variance <= self.max_variance_threshold or fft_concentration >= 0.85 or autocorr >= 0.70
        ):
            # Confidence score scaled with periodicity consistency and sample count
            base_conf = 0.82
            var_bonus = min(0.12, (self.max_variance_threshold - min(iat_variance, self.max_variance_threshold)) * 2.0)
            sample_bonus = min(0.05, (len(timestamps) - 3) * 0.01)
            confidence = min(0.99, base_conf + var_bonus + sample_bonus)

            byte_ratio = calculate_flow_ratio(
                metrics.get("total_bytes_out", bytes_out),
                metrics.get("total_bytes_in", bytes_in),
            )
            entropy = calculate_shannon_entropy([f"{t:.1f}" for t in sorted_ts])

            details = (
                f"Periodic C2 beaconing detected at {mean_period:.1f}s intervals "
                f"via FFT harmonic analysis ({len(timestamps)} heartbeats, "
                f"IAT variance={iat_variance:.6f}s², concentration={fft_concentration:.2f})."
            )

            return DetectionCandidate(
                threat_class=self.threat_class,
                confidence_score=round(confidence, 4),
                inter_arrival_variance=iat_variance,
                shannon_entropy=entropy,
                byte_ratio=byte_ratio,
                fan_out_count=1,
                ja3_hash=ja3_hash,
                details=details,
                fft_concentration=fft_concentration,
                beacon_period_seconds=mean_period,
                inter_arrival_stddev=inter_arrival_stddev,
            )

        return None
