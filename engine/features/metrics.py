"""
ThreatLens Mathematical & Statistical Metric Calculators
========================================================
Core statistical functions for telemetry feature extraction, anomaly scoring,
and sliding-window heuristic detection.
"""

from collections import Counter
import math
from typing import Any, Sequence, Union


def calculate_shannon_entropy(data: Union[str, Sequence[Any]]) -> float:
    """
    Calculates Shannon Entropy: H(X) = -sum(P(x) * log2(P(x))).

    Used to detect:
      - High-entropy FQDN strings indicative of DGA (Domain Generation Algorithms)
        and DNS data tunneling.
      - Dispersed destination IP distributions across scanning and reconnaissance sweeps.

    Args:
        data: A string (e.g., domain name) or a sequence of discrete tokens (e.g., destination IPs).

    Returns:
        float: Shannon entropy score in bits (>= 0.0). Returns 0.0 for empty or single-symbol inputs.
    """
    if not data:
        return 0.0

    length = len(data)
    if length <= 1:
        return 0.0

    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        if probability > 0.0:
            entropy -= probability * math.log2(probability)

    return float(round(entropy, 4))


def calculate_flow_ratio(bytes_out: int, bytes_in: int) -> float:
    """
    Calculates the safe asymmetric egress-to-ingress byte ratio (outbound / inbound).

    Used to detect:
      - Asymmetric high-volume outbound data exfiltration.
      - Large payload downloads versus heartbeat queries.

    Args:
        bytes_out: Outbound bytes transferred (egress).
        bytes_in: Inbound bytes transferred (ingress).

    Returns:
        float: Ratio of bytes_out to bytes_in. If bytes_in is 0, returns float(bytes_out).
    """
    if bytes_out < 0 or bytes_in < 0:
        raise ValueError("Byte counts must be non-negative integers.")

    if bytes_in == 0:
        return float(bytes_out)

    return float(round(bytes_out / bytes_in, 4))


def calculate_inter_arrival_variance(timestamps: list[float]) -> float:
    """
    Calculates the variance of inter-arrival times (Δt) across consecutive timestamps.

    Used to detect:
      - Botnet C2 Beaconing: automated scripts contacting C2 servers at strict
        periodic intervals exhibit near-zero Δt variance (e.g. var < 0.05).
      - Human interactive browsing exhibits high, bursty Δt variance.

    Args:
        timestamps: Chronological or unsorted float timestamps (in seconds).

    Returns:
        float: Population variance of consecutive deltas: Var(Δt) = E[(Δt - mean(Δt))^2].
               Returns 0.0 if fewer than 2 deltas are available.
    """
    if not timestamps or len(timestamps) < 3:
        # Need at least 3 timestamps to produce 2 deltas for variance calculation
        return 0.0

    sorted_ts = sorted(timestamps)
    deltas = [sorted_ts[i] - sorted_ts[i - 1] for i in range(1, len(sorted_ts))]

    if len(deltas) < 2:
        return 0.0

    mean_delta = sum(deltas) / len(deltas)
    variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)

    return float(round(variance, 6))


def calculate_fan_out(destinations: Union[set, list, tuple]) -> int:
    """
    Calculates the cardinality (unique count) of external endpoints (IPs or IP:port pairs).

    Used to detect:
      - Reconnaissance port scans and IP sweeps where a single source IP contacts
        numerous distinct destination IPs or ports within a sliding window.

    Args:
        destinations: A set, list, or tuple of destination identifiers.

    Returns:
        int: Cardinality of unique external endpoints (>= 0).
    """
    if not destinations:
        return 0

    return len(set(destinations))
