"""
Environment-backed detector thresholds and runtime configuration.
================================================================
This module is the single authoritative source of detector thresholds.

`THRESHOLDS` is a live, mutable mapping. Detection engines read values from it at
evaluation time (never caching them), so an update applied through the runtime
configuration API takes effect on the next evaluation without a process restart.

Environment variables provide the startup baseline. Analyst overrides applied at
runtime are held in `THRESHOLDS` and persisted separately by
`engine.runtime_config.RuntimeConfigStore`; `_THRESHOLD_DEFAULTS` keeps the
environment baseline so `modified` state can be reported and values reset.
"""

import copy
import logging
import math
import os
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def env_float(name: str, default: float) -> float:
    return float(os.getenv(name, str(default)))


def env_int(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


@dataclass(frozen=True)
class ThresholdSpec:
    """Declarative metadata for a single analyst-tunable detection threshold."""

    rule: str
    rule_label: str
    parameter: str
    label: str
    description: str
    kind: str
    minimum: Optional[float]
    maximum: Optional[float]
    consumed_by: str


THRESHOLDS: Dict[str, Dict[str, Any]] = {
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

# Environment-derived baseline. Runtime overrides never mutate this snapshot.
_THRESHOLD_DEFAULTS: Dict[str, Dict[str, Any]] = copy.deepcopy(THRESHOLDS)

_THRESHOLD_LOCK = threading.RLock()

_RULE_LABELS = {
    "ddos": "Volumetric & Protocol DDoS",
    "beaconing": "Botnet C2 Beaconing",
    "dns": "DGA & DNS Tunneling",
    "exfiltration": "Data Exfiltration",
    "reconnaissance": "Reconnaissance Scan",
    "correlation": "Alert Correlation",
    "malware": "Encrypted Malware",
}

# Every entry below is read by the engine named in `consumed_by` on each
# evaluation. Values that are not consumed are deliberately absent.
SPECS: List[ThresholdSpec] = [
    ThresholdSpec("ddos", _RULE_LABELS["ddos"], "baseline_pps_mean", "Baseline PPS mean",
                  "Expected packets-per-second mean used as the Z-score baseline.",
                  "float", 0.1, 1_000_000.0, "DDoSEngine"),
    ThresholdSpec("ddos", _RULE_LABELS["ddos"], "baseline_pps_std", "Baseline PPS stddev",
                  "Standard deviation of the PPS baseline. Clamped to a minimum of 1.0.",
                  "float", 1.0, 1_000_000.0, "DDoSEngine"),
    ThresholdSpec("ddos", _RULE_LABELS["ddos"], "sigma_threshold", "Sigma threshold",
                  "Z-score above which a PPS surge is treated as volumetric DDoS.",
                  "float", 0.5, 20.0, "DDoSEngine"),
    ThresholdSpec("ddos", _RULE_LABELS["ddos"], "syn_ratio_threshold", "SYN ratio threshold",
                  "Fraction of window packets that must be SYN to flag a SYN flood.",
                  "float", 0.0, 1.0, "DDoSEngine"),
    ThresholdSpec("ddos", _RULE_LABELS["ddos"], "min_surge_pps", "Minimum surge PPS",
                  "Absolute PPS floor required before a surge or SYN flood can fire.",
                  "float", 1.0, 10_000_000.0, "DDoSEngine"),
    ThresholdSpec("ddos", _RULE_LABELS["ddos"], "min_udp_pps", "Minimum UDP storm PPS",
                  "Absolute PPS floor required before a UDP storm can fire.",
                  "float", 1.0, 10_000_000.0, "DDoSEngine"),
    ThresholdSpec("ddos", _RULE_LABELS["ddos"], "syn_packet_burst", "SYN packet burst",
                  "Inbound SYN packet count that triggers a flood regardless of ratio.",
                  "int", 1, 10_000_000, "DDoSEngine"),
    ThresholdSpec("beaconing", _RULE_LABELS["beaconing"], "max_variance_threshold", "Max IAT variance",
                  "Largest inter-arrival variance (s^2) still treated as machine periodic.",
                  "float", 0.0, 100.0, "BeaconingEngine"),
    ThresholdSpec("beaconing", _RULE_LABELS["beaconing"], "min_heartbeats", "Minimum heartbeats",
                  "Minimum observed flows in the 300s window before beaconing is evaluated.",
                  "int", 2, 1000, "BeaconingEngine"),
    ThresholdSpec("beaconing", _RULE_LABELS["beaconing"], "min_period_seconds", "Minimum period",
                  "Minimum mean inter-arrival period (s) to distinguish beacons from bursts.",
                  "float", 0.0, 86400.0, "BeaconingEngine"),
    ThresholdSpec("dns", _RULE_LABELS["dns"], "entropy_threshold", "Domain entropy threshold",
                  "Shannon entropy (bits/char) at or above which a domain is treated as DGA.",
                  "float", 0.0, 8.0, "DNSEngine"),
    ThresholdSpec("dns", _RULE_LABELS["dns"], "tunnel_length_threshold", "Tunnel query length",
                  "FQDN character length at or above which a query is treated as tunneling.",
                  "int", 1, 1000, "DNSEngine"),
    ThresholdSpec("dns", _RULE_LABELS["dns"], "txt_tunnel_length", "TXT tunnel length",
                  "Query length that flags a TXT/NULL record as a tunneling candidate.",
                  "int", 1, 1000, "DNSEngine"),
    ThresholdSpec("dns", _RULE_LABELS["dns"], "txt_entropy_threshold", "TXT entropy threshold",
                  "Entropy that flags a TXT/NULL record as a tunneling candidate.",
                  "float", 0.0, 8.0, "DNSEngine"),
    ThresholdSpec("exfiltration", _RULE_LABELS["exfiltration"], "min_egress_bytes", "Minimum egress bytes",
                  "Outbound byte floor for an asymmetric egress leak.",
                  "int", 0, 1_000_000_000_000, "ExfiltrationEngine"),
    ThresholdSpec("exfiltration", _RULE_LABELS["exfiltration"], "min_ratio_threshold", "Minimum egress ratio",
                  "Outbound/inbound byte ratio required for an asymmetric egress leak.",
                  "float", 0.0, 100000.0, "ExfiltrationEngine"),
    ThresholdSpec("exfiltration", _RULE_LABELS["exfiltration"], "massive_upload_bytes", "Massive upload bytes",
                  "Outbound byte floor for a single massive upload.",
                  "int", 0, 1_000_000_000_000, "ExfiltrationEngine"),
    ThresholdSpec("exfiltration", _RULE_LABELS["exfiltration"], "massive_upload_ratio", "Massive upload ratio",
                  "Egress ratio required alongside the massive upload byte floor.",
                  "float", 0.0, 100000.0, "ExfiltrationEngine"),
    ThresholdSpec("reconnaissance", _RULE_LABELS["reconnaissance"], "min_target_cardinality", "Minimum target cardinality",
                  "Distinct ports or hosts probed within the window before recon fires.",
                  "int", 1, 10000, "ReconEngine"),
    ThresholdSpec("reconnaissance", _RULE_LABELS["reconnaissance"], "max_probe_bytes", "Maximum probe bytes",
                  "Largest egress byte count still considered a scan probe payload.",
                  "int", 0, 1_000_000_000, "ReconEngine"),
    ThresholdSpec("correlation", _RULE_LABELS["correlation"], "window_seconds", "Incident correlation window",
                  "Seconds within which alerts from one source share an incident id.",
                  "int", 1, 86400, "AlertAggregator"),
    ThresholdSpec("malware", _RULE_LABELS["malware"], "tls_ports", "TLS ports",
                  "Destination ports treated as TLS sessions for fingerprint evaluation.",
                  "int_list", 1, 65535, "EncryptedMalwareEngine"),
]

_SPEC_INDEX: Dict[tuple, ThresholdSpec] = {(spec.rule, spec.parameter): spec for spec in SPECS}


def get_spec(rule: str, parameter: str) -> Optional[ThresholdSpec]:
    """Returns the metadata spec for a rule parameter, or None when unknown."""
    return _SPEC_INDEX.get((rule, parameter))


def get_threshold(rule: str, parameter: str) -> Any:
    """Reads the current live value of a threshold. Engines call this per evaluation."""
    with _THRESHOLD_LOCK:
        return THRESHOLDS[rule][parameter]


def _coerce_value(spec: ThresholdSpec, value: Any) -> Any:
    """Validates and coerces an incoming threshold value against its spec."""
    if isinstance(value, bool):
        raise ValueError(f"{spec.rule}.{spec.parameter} must be {spec.kind}, not a boolean")

    if spec.kind == "int_list":
        if isinstance(value, str):
            raw_items: List[Any] = [item.strip() for item in value.split(",") if item.strip()]
        elif isinstance(value, (list, tuple)):
            raw_items = list(value)
        else:
            raise ValueError(f"{spec.rule}.{spec.parameter} must be a list of integers")
        if not raw_items:
            raise ValueError(f"{spec.rule}.{spec.parameter} must contain at least one port")
        ports: List[int] = []
        for item in raw_items:
            if isinstance(item, bool):
                raise ValueError(f"{spec.rule}.{spec.parameter} contains a boolean")
            try:
                port = int(item)
            except (TypeError, ValueError):
                raise ValueError(f"{spec.rule}.{spec.parameter} contains non-integer port {item!r}")
            if spec.minimum is not None and port < spec.minimum:
                raise ValueError(f"port {port} is below the minimum of {int(spec.minimum)}")
            if spec.maximum is not None and port > spec.maximum:
                raise ValueError(f"port {port} exceeds the maximum of {int(spec.maximum)}")
            ports.append(port)
        if len(set(ports)) != len(ports):
            raise ValueError(f"{spec.rule}.{spec.parameter} contains duplicate ports")
        return ports

    if isinstance(value, str):
        try:
            numeric = float(value.strip())
        except ValueError:
            raise ValueError(f"{spec.rule}.{spec.parameter} must be a number")
    elif isinstance(value, (int, float)):
        numeric = float(value)
    else:
        raise ValueError(f"{spec.rule}.{spec.parameter} must be a number")

    if not math.isfinite(numeric):
        raise ValueError(f"{spec.rule}.{spec.parameter} must be a finite number")

    if spec.kind == "int":
        if numeric != int(numeric):
            raise ValueError(f"{spec.rule}.{spec.parameter} must be a whole number")
        numeric = int(numeric)

    if spec.minimum is not None and numeric < spec.minimum:
        raise ValueError(f"{spec.rule}.{spec.parameter} must be >= {spec.minimum}")
    if spec.maximum is not None and numeric > spec.maximum:
        raise ValueError(f"{spec.rule}.{spec.parameter} must be <= {spec.maximum}")
    return numeric


def set_threshold(rule: str, parameter: str, value: Any) -> Dict[str, Any]:
    """
    Validates and applies a threshold change to the live configuration.

    Raises ValueError when the rule/parameter is unknown or the value is invalid.
    Persistence is the caller's responsibility (see engine.runtime_config).
    """
    spec = get_spec(rule, parameter)
    if spec is None:
        raise ValueError(f"Unknown threshold parameter '{rule}.{parameter}'")

    coerced = _coerce_value(spec, value)
    with _THRESHOLD_LOCK:
        previous = THRESHOLDS[rule][parameter]
        THRESHOLDS[rule][parameter] = coerced

    logger.info(
        "Threshold updated: %s.%s %r -> %r (consumed by %s)",
        rule, parameter, previous, coerced, spec.consumed_by,
    )
    return describe_threshold(rule, parameter)


def describe_threshold(rule: str, parameter: str) -> Dict[str, Any]:
    """Returns one threshold entry with metadata, current value, and default."""
    spec = get_spec(rule, parameter)
    if spec is None:
        raise ValueError(f"Unknown threshold parameter '{rule}.{parameter}'")
    with _THRESHOLD_LOCK:
        value = THRESHOLDS[rule][parameter]
        default = _THRESHOLD_DEFAULTS[rule][parameter]
    return {
        "rule": spec.rule,
        "rule_label": spec.rule_label,
        "parameter": spec.parameter,
        "label": spec.label,
        "description": spec.description,
        "kind": spec.kind,
        "min": spec.minimum,
        "max": spec.maximum,
        "value": value,
        "default": default,
        "modified": value != default,
        "consumed_by": spec.consumed_by,
        "active": True,
    }


def describe_thresholds() -> List[Dict[str, Any]]:
    """Returns every configurable threshold with its metadata and live value."""
    return [describe_threshold(spec.rule, spec.parameter) for spec in SPECS]


def apply_threshold_overrides(overrides: Dict[str, Any]) -> int:
    """
    Applies persisted overrides (keyed 'rule.parameter') to the live configuration.

    Invalid or unknown entries are logged and skipped so a corrupt stored value
    can never prevent startup. Returns the number of overrides applied.
    """
    applied = 0
    for composite_key, value in overrides.items():
        rule, _, parameter = str(composite_key).partition(".")
        if not rule or not parameter:
            logger.warning("Skipping malformed threshold override key %r", composite_key)
            continue
        try:
            set_threshold(rule, parameter, value)
            applied += 1
        except (ValueError, KeyError) as exc:
            logger.warning("Skipping invalid threshold override %s: %s", composite_key, exc)
    return applied


def threshold_overrides() -> Dict[str, Any]:
    """Returns only the thresholds currently differing from the environment baseline."""
    overrides: Dict[str, Any] = {}
    with _THRESHOLD_LOCK:
        for rule, parameters in THRESHOLDS.items():
            for parameter, value in parameters.items():
                if value != _THRESHOLD_DEFAULTS[rule][parameter]:
                    overrides[f"{rule}.{parameter}"] = value
    return overrides


def reset_thresholds() -> None:
    """Restores every threshold to its environment-derived baseline."""
    with _THRESHOLD_LOCK:
        for rule, parameters in _THRESHOLD_DEFAULTS.items():
            THRESHOLDS[rule] = copy.deepcopy(parameters)
    logger.info("Detector thresholds reset to environment baseline")
