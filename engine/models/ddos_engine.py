"""
ThreatLens Volumetric & Protocol DDoS Detection Engine
======================================================
Detects high-rate SYN flood, UDP storm, and PPS surges using rolling 10-second
sliding-window metrics and dynamic 3-sigma deviation thresholding.
"""

from typing import Optional

from backend.app.schemas import ThreatClassEnum
from engine.features.metrics import calculate_flow_ratio, calculate_shannon_entropy
from engine.config import THRESHOLDS
from engine.models.base import BaseDetectionEngine, DetectionCandidate


class DDoSEngine(BaseDetectionEngine):
    """
    Engine 1: Volumetric & Protocol DDoS Detection.
    Evaluates packet-per-second (PPS) rates, SYN flag concentration, and UDP bursts.
    """

    def __init__(
        self,
        baseline_pps_mean: Optional[float] = None,
        baseline_pps_std: Optional[float] = None,
        sigma_threshold: Optional[float] = None,
        syn_ratio_threshold: Optional[float] = None,
    ):
        config = THRESHOLDS["ddos"]
        self.baseline_mean = baseline_pps_mean if baseline_pps_mean is not None else config["baseline_pps_mean"]
        self.baseline_std = max(baseline_pps_std if baseline_pps_std is not None else config["baseline_pps_std"], 1.0)
        self.sigma_threshold = sigma_threshold if sigma_threshold is not None else config["sigma_threshold"]
        self.syn_ratio_threshold = syn_ratio_threshold if syn_ratio_threshold is not None else config["syn_ratio_threshold"]

    @property
    def threat_class(self) -> ThreatClassEnum:
        return ThreatClassEnum.VOLUMETRIC_DOS

    def evaluate(self, event: dict, store) -> Optional[DetectionCandidate]:
        src_ip = event.get("src_ip", "")
        dst_ip = event.get("dst_ip", "")
        packets_out = int(event.get("packets_out") or 0)
        packets_in = int(event.get("packets_in") or 0)
        bytes_out = event.get("bytes_out", 0)
        bytes_in = event.get("bytes_in", 0)
        flags = event.get("flags", [])
        protocol = event.get("protocol", "TCP")
        timestamp = event.get("timestamp")

        # Ingest state from 10s sliding window
        source_metrics = store.get_10s_metrics(src_ip, current_time=timestamp) if store else {}
        target_metrics = store.get_10s_metrics(f"target:{dst_ip}:{event.get('dst_port', 0)}", current_time=timestamp) if store else {}
        window_metrics = target_metrics if target_metrics.get("packet_count", 0) else source_metrics
        win_pps = window_metrics.get("packets_per_sec", 0.0)

        # Observed instantaneous or window PPS
        effective_pps = max(float(packets_in), float(packets_out), win_pps)
        inbound_dominant = packets_in > packets_out

        # 3-Sigma Z-Score calculation
        z_score = (effective_pps - self.baseline_mean) / self.baseline_std

        # SYN Flood Evaluation
        is_syn = "SYN" in flags and "ACK" not in flags
        syn_count = window_metrics.get("syn_count", 0) + (1 if is_syn else 0)
        total_packets = max(window_metrics.get("packet_count", 0), 1)
        syn_ratio = syn_count / total_packets if is_syn else 0.0

        # Trigger conditions:
        # 1. 3-Sigma PPS breach (Z > 3.0) with high volume
        # 2. Explicit massive packet burst with SYN flag (typical of SYN floods)
        # 3. High-velocity UDP burst with Z-score breach
        is_surge = z_score >= self.sigma_threshold and effective_pps >= THRESHOLDS["ddos"]["min_surge_pps"]
        is_syn_flood = inbound_dominant and ((is_syn and packets_in >= THRESHOLDS["ddos"]["syn_packet_burst"]) or (syn_ratio >= self.syn_ratio_threshold and effective_pps >= THRESHOLDS["ddos"]["min_surge_pps"]))
        is_udp_storm = protocol == "UDP" and effective_pps >= THRESHOLDS["ddos"]["min_udp_pps"] and z_score >= self.sigma_threshold

        if inbound_dominant and (is_surge or is_syn_flood or is_udp_storm):
            # Normalize confidence score between 0.75 and 0.99 based on Z-score severity
            confidence = min(0.99, 0.75 + min(0.24, (z_score - 3.0) * 0.03))
            if is_syn_flood:
                confidence = max(confidence, 0.92)

            byte_ratio = calculate_flow_ratio(bytes_out, bytes_in)
            target_entropy = calculate_shannon_entropy([dst_ip])

            source_count = window_metrics.get("unique_source_count", 1)
            attack_type = "Distributed SYN Flood" if is_syn_flood and source_count > 1 else ("SYN Flood / DoS" if is_syn_flood else ("UDP Storm" if is_udp_storm else "Volumetric PPS Surge"))
            details = (
                f"{attack_type} detected targeting {dst_ip}: {effective_pps:.1f} PPS "
                f"from {source_count} source(s) (Z-score={z_score:.2f} > {self.sigma_threshold:.1f}σ, SYN ratio={syn_ratio:.2f})."
            )

            return DetectionCandidate(
                threat_class=self.threat_class,
                confidence_score=round(confidence, 4),
                inter_arrival_variance=0.0,
                shannon_entropy=target_entropy,
                byte_ratio=byte_ratio,
                fan_out_count=1,
                ja3_hash=None,
                details=details,
                inbound_connections=syn_count,
                outbound_connections=packets_out,
                observation_window_seconds=window_metrics.get("window_sec", 10),
                packets_per_second=effective_pps,
                z_score=z_score,
                source_ip_entropy=window_metrics.get("source_ip_entropy", event.get("source_ip_entropy")),
                unique_source_count=window_metrics.get("unique_source_count", 1),
            )

        return None
