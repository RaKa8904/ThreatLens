"""
ThreatLens Evaluation Harness (C0)
==================================
Measures the CURRENT detection behavior of the six heuristic/statistical
detectors honestly, without tuning anything. This is an offline evaluation
tool: it drives the SAME canonical DetectionPipeline in-process (exactly as
the unit tests do) with a fresh in-memory SlidingWindowStore per scenario.
It is not a second production detection path and requires no Kafka, Redis,
ClickHouse, or dashboard.

Ground truth comes from the synthetic generator's ``simulated_label`` field,
which is evaluation metadata only — detector code never reads it (enforced
by backend/tests/test_no_label_leak.py).

Determinism: every scenario re-seeds the generator with
``seed + scenario_index``, and all event timestamps are fixed constants.
Two runs with the same seed produce byte-identical result files.

Usage:
    py -3.12 -m engine.evaluation [--output eval_results.json]
                                  [--seed 1337] [--scenarios-per-class 10]
"""

import argparse
import json
import random
from typing import Any, Dict, List, Optional

from backend.app.schemas import ThreatClassEnum
from engine.features.store import SlidingWindowStore
from engine.models.aggregator import AlertAggregator
from engine.pipeline import DetectionPipeline
from ingest.producers.mock_producer import SyntheticFlowGenerator

BENIGN_LABEL = "Benign"

# Fixed timestamp bases per scenario type (epoch seconds, arbitrary constants)
BASE_TIMESTAMPS = {
    BENIGN_LABEL: 1_000_000.0,
    "Volumetric & Protocol DDoS": 2_000_000.0,
    "Botnet C2 Beaconing": 3_000_000.0,
    "DGA & DNS Tunneling": 4_000_000.0,
    "Encrypted Malware": 5_000_000.0,
    "Reconnaissance Scan": 6_000_000.0,
    "Data Exfiltration": 7_000_000.0,
}

# Number of events per scenario for classes that need window accumulation
C2_BEACONS_PER_SCENARIO = 4  # beaconing engine requires >= 3 heartbeats
RECON_PROBES_PER_SCENARIO = 5  # recon engine requires >= 3 unique targets


def build_scenarios(seed: int = 1337, scenarios_per_class: int = 10) -> List[Dict[str, Any]]:
    """
    Builds the deterministic evaluation scenario set: N scenarios per class
    (benign + all 6 threat classes). Each scenario is a pure-class event
    sequence — no background-traffic mixing in C0 (documented limitation).
    """
    scenarios: List[Dict[str, Any]] = []

    def add(label: str, index: int, events: List[Dict[str, Any]]):
        scenarios.append(
            {
                "id": f"{label.lower().replace(' & ', '_').replace(' ', '_')}_{index:03d}",
                "expected_class": label,
                "events": events,
            }
        )

    for i in range(scenarios_per_class):
        gen = SyntheticFlowGenerator(seed=seed + 100 + i)
        add(BENIGN_LABEL, i, [gen.generate_benign_flow(timestamp=BASE_TIMESTAMPS[BENIGN_LABEL] + j) for j in range(5)])

        gen = SyntheticFlowGenerator(seed=seed + 200 + i)
        add("Volumetric & Protocol DDoS", i, [gen.generate_volumetric_ddos(timestamp=BASE_TIMESTAMPS["Volumetric & Protocol DDoS"])])

        gen = SyntheticFlowGenerator(seed=seed + 300 + i)
        add("Botnet C2 Beaconing", i, [gen.generate_botnet_c2(timestamp=BASE_TIMESTAMPS["Botnet C2 Beaconing"] + k * 15.0) for k in range(C2_BEACONS_PER_SCENARIO)])

        gen = SyntheticFlowGenerator(seed=seed + 400 + i)
        add("DGA & DNS Tunneling", i, [gen.generate_dga_dns_tunnel(timestamp=BASE_TIMESTAMPS["DGA & DNS Tunneling"])])

        gen = SyntheticFlowGenerator(seed=seed + 500 + i)
        add("Encrypted Malware", i, [gen.generate_encrypted_malware(timestamp=BASE_TIMESTAMPS["Encrypted Malware"])])

        gen = SyntheticFlowGenerator(seed=seed + 600 + i)
        add("Reconnaissance Scan", i, [gen.generate_recon_scan(timestamp=BASE_TIMESTAMPS["Reconnaissance Scan"] + k, target_ip="203.0.113.9") for k in range(RECON_PROBES_PER_SCENARIO)])

        gen = SyntheticFlowGenerator(seed=seed + 700 + i)
        add("Data Exfiltration", i, [gen.generate_data_exfiltration(timestamp=BASE_TIMESTAMPS["Data Exfiltration"])])

    return scenarios


def run_scenario(scenario: Dict[str, Any]) -> Dict[str, Any]:
    """
    Replays one scenario through a fresh canonical DetectionPipeline and
    records which detector classes fired. Events are passed through
    unmodified (including simulated_label) — the harness reads the label
    for ground truth, the detectors do not.
    """
    store = SlidingWindowStore(use_redis=False)
    pipeline = DetectionPipeline(store=store, aggregator=AlertAggregator())

    alerts_fired = []
    for event in scenario["events"]:
        alerts_fired.extend(pipeline.process_flow_event(event))

    detected = sorted({alert.threat_class.value for alert in alerts_fired})
    expected = scenario["expected_class"]

    if expected == BENIGN_LABEL:
        correct = not detected
        false_positive_classes = detected
        missed_class = None
    else:
        correct = expected in detected
        false_positive_classes = [d for d in detected if d != expected]
        missed_class = expected if expected not in detected else None

    return {
        "scenario_id": scenario["id"],
        "expected_class": expected,
        "detector_fired": detected,
        "alert_count": len(alerts_fired),
        "correct_detection": correct,
        "false_positive_classes": false_positive_classes,
        "missed_class": missed_class,
    }


def compute_metrics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes one-vs-rest TP/TN/FP/FN, precision, recall, F1, and FPR per threat class plus micro-overall."""
    classes = [c.value for c in ThreatClassEnum]
    per_class: Dict[str, Any] = {}

    total_tp = total_fp = total_fn = total_tn = 0
    for cls in classes:
        tp = sum(1 for r in records if r["expected_class"] == cls and cls in r["detector_fired"])
        fn = sum(1 for r in records if r["expected_class"] == cls and cls not in r["detector_fired"])
        fp = sum(1 for r in records if r["expected_class"] != cls and cls in r["detector_fired"])
        tn = len(records) - tp - fn - fp
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        per_class[cls] = {
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
        }
        total_tp += tp
        total_fp += fp
        total_fn += fn
        total_tn += tn

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0.0

    benign_records = [r for r in records if r["expected_class"] == BENIGN_LABEL]
    benign_with_alerts = sum(1 for r in benign_records if r["detector_fired"])

    overall = {
        "tp": total_tp, "fp": total_fp, "fn": total_fn, "tn": total_tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0,
        "false_positive_rate": round(total_fp / (total_fp + total_tn), 4) if (total_fp + total_tn) else 0.0,
        # micro accuracy over (scenario x class) decision points: TP+TN / all points
        "accuracy": round(
            (total_tp + total_tn) / (total_tp + total_fp + total_fn + total_tn), 4
        )
        if (total_tp + total_fp + total_fn + total_tn)
        else 0.0,
        "benign_scenarios": len(benign_records),
        "benign_scenarios_with_alerts": benign_with_alerts,
    }
    return {"overall": overall, "per_class": per_class}


def evaluate(seed: int = 1337, scenarios_per_class: int = 10) -> Dict[str, Any]:
    """Runs the full evaluation and returns the machine-readable result document."""
    scenarios = build_scenarios(seed=seed, scenarios_per_class=scenarios_per_class)
    records = [run_scenario(s) for s in scenarios]
    metrics = compute_metrics(records)
    return {
        "harness": "ThreatLens C0 evaluation",
        "detector_types": "heuristic/statistical (rule thresholds, Shannon entropy, IAT variance, JA3 exact matching) — not machine-learned classifiers",
        "input": "synthetic generator scenarios (pure-class, no background-traffic mixing)",
        "seed": seed,
        "scenarios_per_class": scenarios_per_class,
        "ground_truth_source": "simulated_label (evaluation metadata only; detectors never read it)",
        "metrics": metrics,
        "scenarios": records,
    }


def print_summary(result: Dict[str, Any]) -> None:
    metrics = result["metrics"]
    print(f"ThreatLens C0 evaluation (seed={result['seed']}, "
          f"{result['scenarios_per_class']} scenarios/class, "
          f"{len(result['scenarios'])} total)")
    print(f"Detectors: {result['detector_types']}")
    print()
    overall = metrics["overall"]
    print(f"{'OVERALL (micro)':<34}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>4}  "
          f"P={overall['precision']:.3f} R={overall['recall']:.3f} "
          f"F1={overall['f1']:.3f} FPR={overall['false_positive_rate']:.3f}")
    print()
    print(f"{'Threat class':<34}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>4}  "
          f"{'Precision':>9}{'Recall':>9}{'F1':>9}{'FPR':>9}")
    for cls, m in metrics["per_class"].items():
        print(f"{cls:<34}{m['tp']:>4}{m['fp']:>4}{m['fn']:>4}{m['tn']:>4}  "
              f"{m['precision']:>9.3f}{m['recall']:>9.3f}{m['f1']:>9.3f}{m['false_positive_rate']:>9.3f}")
    print()
    print(f"Benign scenarios with any alert: {overall['benign_scenarios_with_alerts']}/{overall['benign_scenarios']}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ThreatLens C0 evaluation harness")
    parser.add_argument("--output", type=str, default=None, help="Path to write the machine-readable JSON result")
    parser.add_argument("--seed", type=int, default=1337, help="Deterministic seed for scenario generation")
    parser.add_argument("--scenarios-per-class", type=int, default=10, help="Scenarios per class (benign + 6 threat classes)")
    args = parser.parse_args(argv)

    random.seed(args.seed)
    result = evaluate(seed=args.seed, scenarios_per_class=args.scenarios_per_class)
    print_summary(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"\nMachine-readable results written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
