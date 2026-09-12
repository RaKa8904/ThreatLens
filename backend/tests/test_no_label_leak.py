"""
ThreatLens Label-Leak Meta-Test
===============================
Fails if any detection engine source file references ``simulated_label``.
Detection decisions must be derived from traffic features only; the synthetic
generator's ground-truth label is test/evaluation metadata, never an input.
"""

import unittest
from pathlib import Path

ENGINE_MODELS_DIR = Path(__file__).resolve().parents[2] / "engine" / "models"
FORBIDDEN_TOKEN = "simulated_label"


class TestNoLabelLeak(unittest.TestCase):
    def test_no_engine_reads_simulated_label(self):
        offenders = [
            path.name
            for path in sorted(ENGINE_MODELS_DIR.glob("*.py"))
            if FORBIDDEN_TOKEN in path.read_text(encoding="utf-8")
        ]
        self.assertEqual(
            offenders,
            [],
            f"Detection engines must not read '{FORBIDDEN_TOKEN}': {offenders}",
        )


if __name__ == "__main__":
    unittest.main()
