"""
ThreatLens Evaluation Harness Tests (C0)
========================================
Verifies the evaluation framework itself (not detector quality):
  1. Determinism: identical seeds produce identical results.
  2. Scenario coverage: benign + all 6 threat classes are evaluated.
  3. Metric math: TP/TN/FP/FN, precision, recall, F1, FPR against
     hand-computed values.
  4. Scenario records distinguish detector-fired / expected / correct /
     false-positive / missed.
  5. Ground truth comes from simulated_label, which is preserved on the
     events passed to the pipeline (and never stripped or altered).
  6. The harness runs fully offline (in-memory store, no Kafka/Redis).
"""

import json
import tempfile
import unittest
from pathlib import Path

from backend.app.schemas import ThreatClassEnum
from engine.evaluation import (
    BENIGN_LABEL,
    build_scenarios,
    compute_metrics,
    evaluate,
    main,
    run_scenario,
)

EVALUATION_SOURCE = Path(__file__).resolve().parents[2] / "engine" / "evaluation.py"


class TestScenarioConstruction(unittest.TestCase):
    def test_all_classes_covered(self):
        scenarios = build_scenarios(seed=42, scenarios_per_class=3)
        labels = {s["expected_class"] for s in scenarios}
        expected_labels = {BENIGN_LABEL} | {c.value for c in ThreatClassEnum}
        self.assertEqual(labels, expected_labels)
        self.assertEqual(len(scenarios), 7 * 3)

    def test_scenario_ids_unique_and_labeled(self):
        scenarios = build_scenarios(seed=42, scenarios_per_class=4)
        ids = [s["id"] for s in scenarios]
        self.assertEqual(len(ids), len(set(ids)))
        for scenario in scenarios:
            self.assertTrue(scenario["events"])
            for event in scenario["events"]:
                self.assertEqual(event["simulated_label"], scenario["expected_class"])

    def test_all_events_satisfy_flow_contract(self):
        from backend.app.schemas import FlowEventSchema

        for scenario in build_scenarios(seed=42, scenarios_per_class=2):
            for event in scenario["events"]:
                FlowEventSchema.model_validate(event)


class TestMetricMath(unittest.TestCase):
    def test_hand_computed_metrics(self):
        # 5 scenarios: 2 correct detections, 1 miss, 1 benign FP, 1 clean benign
        records = [
            {"expected_class": "Reconnaissance Scan", "detector_fired": ["Reconnaissance Scan"],
             "alert_count": 1, "correct_detection": True, "false_positive_classes": [], "missed_class": None},
            {"expected_class": "Reconnaissance Scan", "detector_fired": [],
             "alert_count": 0, "correct_detection": False, "false_positive_classes": [], "missed_class": "Reconnaissance Scan"},
            {"expected_class": BENIGN_LABEL, "detector_fired": ["DGA & DNS Tunneling"],
             "alert_count": 1, "correct_detection": False, "false_positive_classes": ["DGA & DNS Tunneling"], "missed_class": None},
            {"expected_class": BENIGN_LABEL, "detector_fired": [],
             "alert_count": 0, "correct_detection": True, "false_positive_classes": [], "missed_class": None},
            {"expected_class": "Data Exfiltration", "detector_fired": ["Data Exfiltration"],
             "alert_count": 1, "correct_detection": True, "false_positive_classes": [], "missed_class": None},
        ]
        metrics = compute_metrics(records)

        recon = metrics["per_class"]["Reconnaissance Scan"]
        self.assertEqual((recon["tp"], recon["fn"]), (1, 1))
        self.assertAlmostEqual(recon["recall"], 0.5)
        self.assertAlmostEqual(recon["precision"], 1.0)

        dga = metrics["per_class"]["DGA & DNS Tunneling"]
        self.assertEqual((dga["tp"], dga["fp"], dga["fn"]), (0, 1, 0))
        self.assertEqual(dga["precision"], 0.0)
        self.assertAlmostEqual(dga["false_positive_rate"], 1 / 5)  # fp=1, tn=4 of 5 records

        overall = metrics["overall"]
        self.assertEqual((overall["tp"], overall["fp"], overall["fn"]), (2, 1, 1))
        self.assertAlmostEqual(overall["precision"], 2 / 3, places=3)
        self.assertAlmostEqual(overall["recall"], 2 / 3, places=3)
        # micro accuracy over (scenario x class) decision points: (TP+TN)/all
        decision_points = overall["tp"] + overall["fp"] + overall["fn"] + overall["tn"]
        self.assertAlmostEqual(
            overall["accuracy"], (overall["tp"] + overall["tn"]) / decision_points, places=3
        )
        self.assertLessEqual(overall["accuracy"], 1.0)
        self.assertGreaterEqual(overall["accuracy"], 0.0)
        self.assertEqual(overall["benign_scenarios_with_alerts"], 1)
        self.assertEqual(overall["benign_scenarios"], 2)

    def test_empty_division_guards(self):
        metrics = compute_metrics([])
        self.assertEqual(metrics["overall"]["precision"], 0.0)
        self.assertEqual(metrics["overall"]["f1"], 0.0)


class TestEvaluationRun(unittest.TestCase):
    def test_deterministic_same_seed(self):
        first = evaluate(seed=99, scenarios_per_class=2)
        second = evaluate(seed=99, scenarios_per_class=2)
        self.assertEqual(first, second)

    def test_result_document_structure(self):
        result = evaluate(seed=7, scenarios_per_class=2)
        self.assertIn("metrics", result)
        self.assertIn("scenarios", result)
        self.assertEqual(len(result["scenarios"]), 14)
        # all six classes have per-class metrics
        for cls in ThreatClassEnum:
            self.assertIn(cls.value, result["metrics"]["per_class"])
        # every scenario record distinguishes the required fields
        for record in result["scenarios"]:
            self.assertIn("expected_class", record)
            self.assertIn("detector_fired", record)
            self.assertIn("correct_detection", record)
            self.assertIn("false_positive_classes", record)
            self.assertIn("missed_class", record)

    def test_c2_scenario_detection_semantics(self):
        # Known-trigger scenario: 4 beacons 15s apart must record C2 as
        # fired-and-correct if the detector works; the framework must
        # classify it as correct_detection either way consistently.
        scenarios = build_scenarios(seed=1337, scenarios_per_class=1)
        c2 = next(s for s in scenarios if s["expected_class"] == "Botnet C2 Beaconing")
        record = run_scenario(c2)
        self.assertIn("Botnet C2 Beaconing", record["detector_fired"])
        self.assertTrue(record["correct_detection"])
        self.assertEqual(record["missed_class"], None)

    def test_benign_scenario_clean_semantics(self):
        scenarios = build_scenarios(seed=1337, scenarios_per_class=1)
        benign = next(s for s in scenarios if s["expected_class"] == BENIGN_LABEL)
        record = run_scenario(benign)
        if not record["detector_fired"]:
            self.assertTrue(record["correct_detection"])
            self.assertEqual(record["false_positive_classes"], [])
        else:
            self.assertFalse(record["correct_detection"])
            self.assertEqual(record["false_positive_classes"], record["detector_fired"])

    def test_events_keep_simulated_label_through_pipeline(self):
        scenarios = build_scenarios(seed=5, scenarios_per_class=1)
        for scenario in scenarios:
            run_scenario(scenario)
            # events are not mutated by the harness
            for event in scenario["events"]:
                self.assertEqual(event["simulated_label"], scenario["expected_class"])

    def test_harness_does_not_strip_labels_or_tamper_with_events(self):
        # The harness must pass events through unmodified; ground truth is
        # read from the label, never written into detector inputs elsewhere.
        source = EVALUATION_SOURCE.read_text(encoding="utf-8")
        self.assertNotIn("pop(", source)
        self.assertNotIn("del event", source)


class TestCli(unittest.TestCase):
    def test_main_writes_machine_readable_json(self):
        import contextlib
        import io
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "results.json")
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = main(["--seed", "21", "--scenarios-per-class", "2", "--output", output_path])
            self.assertEqual(exit_code, 0)
            with open(output_path, "r", encoding="utf-8") as f:
                result = json.load(f)
            self.assertEqual(result["seed"], 21)
            self.assertIn("overall", result["metrics"])
            self.assertEqual(len(result["scenarios"]), 14)

    def test_main_quiet_when_not_writing_file(self):
        import contextlib
        import io

        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            exit_code = main(["--seed", "21", "--scenarios-per-class", "1"])
        self.assertEqual(exit_code, 0)
        self.assertIn("ThreatLens C0 evaluation", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
