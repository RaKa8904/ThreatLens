"""Environment-backed detector thresholds and runtime configuration."""

import os


def env_float(name: str, default: float) -> float:
    return float(os.getenv(name, str(default)))


def env_int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


THRESHOLDS = {
    "ddos": {
        "baseline_pps_mean": env_float("DDOS_BASELINE_PPS_MEAN", 50.0),
        "baseline_pps_std": env_float("DDOS_BASELINE_PPS_STD", 30.0),
        "sigma_threshold": env_float("DDOS_SIGMA_THRESHOLD", 3.0),
        "syn_ratio_threshold": env_float("DDOS_SYN_RATIO_THRESHOLD", 0.85),
        "min_surge_pps": env_float("DDOS_MIN_SURGE_PPS", 100.0),
        "min_udp_pps": env_float("DDOS_MIN_UDP_PPS", 200.0),
        "syn_packet_burst": env_int("DDOS_SYN_PACKET_BURST", 300),
    },
    "beaconing": {
        "max_variance_threshold": env_float("BEACON_MAX_VARIANCE", 0.05),
        "min_heartbeats": env_int("BEACON_MIN_HEARTBEATS", 3),
        "min_period_seconds": env_float("BEACON_MIN_PERIOD_SECONDS", 1.0),
    },
    "dns": {
        "entropy_threshold": env_float("DNS_ENTROPY_THRESHOLD", 3.80),
        "tunnel_length_threshold": env_int("DNS_TUNNEL_LENGTH_THRESHOLD", 60),
        "txt_tunnel_length": env_int("DNS_TXT_TUNNEL_LENGTH", 45),
        "txt_entropy_threshold": env_float("DNS_TXT_ENTROPY_THRESHOLD", 3.60),
    },
    "exfiltration": {
        "min_egress_bytes": env_int("EXFIL_MIN_EGRESS_BYTES", 1_000_000),
        "min_ratio_threshold": env_float("EXFIL_MIN_RATIO", 20.0),
        "massive_upload_bytes": env_int("EXFIL_MASSIVE_UPLOAD_BYTES", 5_000_000),
        "massive_upload_ratio": env_float("EXFIL_MASSIVE_UPLOAD_RATIO", 10.0),
    },
    "reconnaissance": {
        "min_target_cardinality": env_int("RECON_MIN_TARGET_CARDINALITY", 3),
        "max_probe_bytes": env_int("RECON_MAX_PROBE_BYTES", 100),
    },
    "correlation": {
        "window_seconds": env_int("ALERT_CORRELATION_WINDOW_SECONDS", 300),
    },
    "malware": {
        "tls_ports": [443, 8443, 9001, 4443],
    },
}
