"""Regression tests for repository-root .env loading.

Covers:
  1. load_dotenv() mechanism applies values from an env file.
  2. Importing backend.app.main loads the repo .env BEFORE configuration
     modules snapshot environment values (verified in a clean subprocess).
  3. Safe defaults hold when an env file/variable is missing.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = REPO_ROOT / ".env"


class TestDotenvMechanism(unittest.TestCase):
    def test_load_dotenv_applies_values_from_file(self):
        from dotenv import load_dotenv

        key = "THREATLENS_TEST_DOTENV_VAR"
        self.assertNotIn(key, os.environ)
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write(f"{key}=observed-value\n")
            path = fh.name
        try:
            load_dotenv(path)
            self.assertEqual(os.environ.get(key), "observed-value")
        finally:
            os.unlink(path)
            os.environ.pop(key, None)

    def test_load_dotenv_missing_file_is_safe(self):
        from dotenv import load_dotenv

        result = load_dotenv(REPO_ROOT / "definitely-missing.env")
        self.assertFalse(result)


class TestMainImportLoadsRepoEnv(unittest.TestCase):
    """Importing backend.app.main must apply .env before engine.config and
    backend.app.storage snapshot their values at import time."""

    def test_repo_env_visible_after_main_import(self):
        if not ENV_FILE.exists():
            self.skipTest("no .env file in repository root")

        expected = None
        for line in ENV_FILE.read_text(encoding="utf-8-sig").splitlines():
            if line.startswith("CORS_ORIGINS="):
                expected = line.split("=", 1)[1].strip()
        self.assertIsNotNone(expected, "CORS_ORIGINS missing from .env")
        code_default = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"
        self.assertNotEqual(expected, code_default, ".env CORS_ORIGINS equals the code default; test would prove nothing")

        child_env = {k: v for k, v in os.environ.items() if k not in ("CORS_ORIGINS", "DDOS_SIGMA_THRESHOLD")}
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import os, json; import backend.app.main; "
                "print(json.dumps({'cors': os.environ.get('CORS_ORIGINS'), "
                "'sigma': __import__('engine.config', fromlist=['THRESHOLDS']).THRESHOLDS['ddos']['sigma_threshold']}))",
            ],
            cwd=REPO_ROOT,
            env=child_env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        observed = json.loads(proc.stdout.strip().splitlines()[-1])

        self.assertEqual(observed["cors"], expected)
        # .env carries no threshold overrides, so the snapshot must fall back
        # to the documented engine default rather than anything undefined.
        self.assertIsNotNone(observed["sigma"])


class TestSafeDefaults(unittest.TestCase):
    def test_threshold_default_when_env_missing(self):
        child_env = {k: v for k, v in os.environ.items() if not k.startswith(("DDOS_", "BEACON_", "DNS_", "EXFIL_", "RECON_", "ALERT_"))}
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import json; from engine.config import THRESHOLDS, _THRESHOLD_DEFAULTS; "
                "print(json.dumps({'sigma': THRESHOLDS['ddos']['sigma_threshold'], "
                "'sigma_default': _THRESHOLD_DEFAULTS['ddos']['sigma_threshold']}))",
            ],
            cwd=REPO_ROOT,
            env=child_env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        observed = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(observed["sigma"], observed["sigma_default"])


if __name__ == "__main__":
    unittest.main()
