"""
ThreatLens PCAP Replay API Test Suite
======================================
Tests for PCAP directory listing, magic-byte file upload validation,
asynchronous replay job triggers, and live status reporting endpoints.
"""

import io
from pathlib import Path
import unittest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.routers.replay import PCAP_DIR, MAGIC_BYTES_PCAP_LE, MAGIC_BYTES_PCAPNG, is_valid_pcap_bytes


class TestReplayAPI(unittest.TestCase):
    """Integration and unit tests for /api/replay REST endpoints."""

    def setUp(self):
        self.client = TestClient(app)
        PCAP_DIR.mkdir(parents=True, exist_ok=True)
        # Ensure a test sample file exists
        self.sample_pcap = PCAP_DIR / "sample_attack.pcap"
        if not self.sample_pcap.exists():
            with open(self.sample_pcap, "wb") as f:
                f.write(MAGIC_BYTES_PCAP_LE + b"\x00" * 32)

    def test_magic_byte_validation(self):
        """Verifies magic byte detection for valid PCAP/PCAPNG headers vs invalid streams."""
        valid_pcap = MAGIC_BYTES_PCAP_LE + b"dummy header content"
        valid_pcapng = MAGIC_BYTES_PCAPNG + b"section header block"
        invalid_text = b"THIS IS A PLAIN TEXT FILE NOT A PCAP"

        self.assertTrue(is_valid_pcap_bytes(valid_pcap))
        self.assertTrue(is_valid_pcap_bytes(valid_pcapng))
        self.assertFalse(is_valid_pcap_bytes(invalid_text))

    def test_list_pcaps_endpoint(self):
        """GET /api/replay/pcaps returns directory listing with attack tags."""
        response = self.client.get("/api/replay/pcaps")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        self.assertGreaterEqual(len(data), 1)

        # Validate metadata fields on listed capture
        sample = next((item for item in data if item["filename"] == "sample_attack.pcap"), None)
        self.assertIsNotNone(sample)
        self.assertIn("filename", sample)
        self.assertIn("size_bytes", sample)
        self.assertIn("created_at", sample)
        self.assertIn("attack_tag", sample)

    def test_upload_pcap_valid(self):
        """POST /api/replay/upload accepts valid .pcap files with correct magic bytes."""
        file_content = MAGIC_BYTES_PCAP_LE + b"\x00" * 64
        file_obj = io.BytesIO(file_content)

        response = self.client.post(
            "/api/replay/upload",
            files={"file": ("test_upload.pcap", file_obj, "application/octet-stream")},
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["filename"], "test_upload.pcap")
        self.assertIn("attack_tag", data)

        # Cleanup uploaded test file
        uploaded_file = PCAP_DIR / "test_upload.pcap"
        if uploaded_file.exists():
            uploaded_file.unlink()

    def test_upload_pcap_invalid_extension(self):
        """POST /api/replay/upload rejects files without .pcap or .pcapng extension."""
        file_content = b"Plain text payload"
        file_obj = io.BytesIO(file_content)

        response = self.client.post(
            "/api/replay/upload",
            files={"file": ("malicious.exe", file_obj, "application/octet-stream")},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Only .pcap and .pcapng files are accepted", response.json()["detail"])

    def test_upload_pcap_invalid_magic_bytes(self):
        """POST /api/replay/upload rejects .pcap files with invalid header signatures."""
        file_content = b"INVALID_HEADER_STREAM_DAT"
        file_obj = io.BytesIO(file_content)

        response = self.client.post(
            "/api/replay/upload",
            files={"file": ("fake_capture.pcap", file_obj, "application/octet-stream")},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("magic bytes", response.json()["detail"])

    def test_trigger_pcap_replay_success(self):
        """POST /api/replay/trigger dispatches asynchronous replay task."""
        payload = {
            "filename": "sample_attack.pcap",
            "target_topics": ["traffic-flows", "dns-queries", "ssl-metadata"],
        }
        response = self.client.post("/api/replay/trigger", json=payload)
        self.assertEqual(response.status_code, 202)
        data = response.json()
        self.assertIn("job_id", data)
        self.assertEqual(data["filename"], "sample_attack.pcap")
        self.assertIn(data["status"], ("processing", "queued", "completed"))

        # Query job status endpoint
        job_id = data["job_id"]
        status_res = self.client.get(f"/api/replay/status/{job_id}")
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.json()
        self.assertEqual(status_data["job_id"], job_id)
        self.assertIn(status_data["status"], ("processing", "queued", "completed"))

    def test_trigger_pcap_replay_not_found(self):
        """POST /api/replay/trigger returns 404 for non-existent capture filename."""
        payload = {"filename": "non_existent_capture.pcap"}
        response = self.client.post("/api/replay/trigger", json=payload)
        self.assertEqual(response.status_code, 404)

    def test_replay_status_not_found(self):
        """GET /api/replay/status/{job_id} returns 404 for unknown job IDs."""
        response = self.client.get("/api/replay/status/unknown-uuid-1234")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
