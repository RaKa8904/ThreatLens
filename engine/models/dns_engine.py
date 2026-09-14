"""
ThreatLens DGA & DNS Tunneling Detection Engine
===============================================
Detects Domain Generation Algorithms (DGA) and DNS-based data tunneling
using character-level Shannon entropy, FQDN length thresholds, and query type heuristics.
"""

from typing import Optional

from backend.app.schemas import ThreatClassEnum
from engine.features.metrics import calculate_flow_ratio, calculate_shannon_entropy
from engine.models.base import BaseDetectionEngine, DetectionCandidate
from engine.config import THRESHOLDS


class DNSEngine(BaseDetectionEngine):
    """
    Engine 3: DGA & DNS Tunneling Detection.
    Evaluates domain lexical entropy, record size anomalies, and TXT/NULL tunneling.
    """

    def __init__(
        self,
        entropy_threshold: Optional[float] = None,
        tunnel_length_threshold: Optional[int] = None,
    ):
        config = THRESHOLDS["dns"]
        self.entropy_threshold = entropy_threshold if entropy_threshold is not None else config["entropy_threshold"]
        self.tunnel_length_threshold = tunnel_length_threshold if tunnel_length_threshold is not None else config["tunnel_length_threshold"]

    @property
    def threat_class(self) -> ThreatClassEnum:
        return ThreatClassEnum.DGA_DNS

    def evaluate(self, event: dict, store) -> Optional[DetectionCandidate]:
        domain = event.get("dns_query")
        query_type = (event.get("dns_query_type") or "A").upper()
        bytes_out = event.get("bytes_out", 0)
        bytes_in = event.get("bytes_in", 0)
        dst_port = event.get("dst_port")

        if not domain and dst_port != 53:
            return None

        if not domain:
            return None

        # Analyze full domain and primary subdomain label
        parts = domain.split(".")
        labels_to_check = [domain]
        if len(parts) > 1:
            labels_to_check.append(parts[0])  # Subdomain or DGA label

        # Calculate Shannon entropy across labels
        entropies = [calculate_shannon_entropy(lbl) for lbl in labels_to_check]
        max_entropy = max(entropies) if entropies else 0.0
        query_len = len(domain)
        bigrams = [domain[index:index + 2] for index in range(max(0, query_len - 1))]
        ngram_score = len(set(bigrams)) / max(len(bigrams), 1)

        # Trigger conditions:
        # 1. High-entropy DGA domain (H >= 3.80 bits)
        # 2. Large DNS tunneling query (> 60 characters or TXT payload > 45 chars)
        # 3. Encoded binary tunnel in TXT or NULL records
        is_high_entropy = max_entropy >= self.entropy_threshold
        is_tunnel_length = query_len >= self.tunnel_length_threshold
        is_txt_tunnel = query_type in ["TXT", "NULL"] and (query_len >= THRESHOLDS["dns"]["txt_tunnel_length"] or max_entropy >= THRESHOLDS["dns"]["txt_entropy_threshold"])

        if is_high_entropy or is_tunnel_length or is_txt_tunnel:
            # Scale confidence from 0.78 up to 0.98
            base_conf = 0.80
            entropy_bonus = min(0.12, max(0.0, (max_entropy - self.entropy_threshold) * 0.3))
            length_bonus = 0.06 if is_tunnel_length else 0.0
            type_bonus = 0.05 if query_type in ["TXT", "NULL"] else 0.0
            confidence = min(0.99, base_conf + entropy_bonus + length_bonus + type_bonus)

            byte_ratio = calculate_flow_ratio(bytes_out, bytes_in)
            mechanism = "DNS Tunneling (TXT/Payload)" if (is_tunnel_length or is_txt_tunnel) else "DGA Generation"
            details = (
                f"{mechanism} detected on query '{domain[:50]}': Shannon entropy={max_entropy:.2f} "
                f"(threshold={self.entropy_threshold:.2f}), length={query_len} chars, record_type={query_type}."
            )

            return DetectionCandidate(
                threat_class=self.threat_class,
                confidence_score=round(confidence, 4),
                inter_arrival_variance=0.0,
                shannon_entropy=max_entropy,
                byte_ratio=byte_ratio,
                fan_out_count=1,
                ja3_hash=None,
                details=details,
                dns_query=domain,
                dns_query_length=query_len,
                dns_query_type=query_type,
                ngram_score=round(ngram_score, 4),
            )

        return None
