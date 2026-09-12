"""
ThreatLens FlowEventSchema Contract Tests
=========================================
Verifies:
  1. Every producer-generated flow event (benign + all 6 threat classes)
     passes the canonical FlowEventSchema contract.
  2. Structurally invalid events are rejected safely.
  3. ``simulated_label`` is optional passthrough metadata, never required.
  4. Unknown extra fields (e.g. malware_family) are ignored, not rejected.
  5. The canonical WebSocket path is /ws/threats everywhere it is configured.
"""

import unittest
from pathlib import Path

from pydantic import ValidationError

from backend.app.schemas import FlowEventSchema
from ingest.producers.mock_producer import SyntheticFlowGenerator

REPO_ROOT = Path(__file__).resolve().parents[2]

BASE_EVENT = {
    "timestamp": 1000.0,
    "flow_id": "10.0.0.1:1000->10.0.0.2:80",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "dst_port": 80,
}


class TestValidProducerEvents(unittest.TestCase):
    def test_all_generator_event_types_pass(self):
        generator = SyntheticFlowGenerator(seed=42)
        events = [
            generator.generate_benign_flow(timestamp=1000.0),
            generator.generate_volumetric_ddos(timestamp=1001.0),
            generator.generate_botnet_c2(timestamp=1002.0),
            generator.generate_dga_dns_tunnel(timestamp=1003.0),
            generator.generate_encrypted_malware(timestamp=1004.0),
            generator.generate_recon_scan(timestamp=1005.0),
            generator.generate_data_exfiltration(timestamp=1006.0),
        ]
        for event in events:
            flow = FlowEventSchema.model_validate(event)
            self.assertEqual(flow.flow_id, event["flow_id"])
            self.assertEqual(flow.simulated_label, event["simulated_label"])

    def test_minimal_base_event_passes_with_defaults(self):
        flow = FlowEventSchema.model_validate(BASE_EVENT)
        self.assertEqual(flow.protocol, "TCP")
        self.assertEqual(flow.flags, [])
        self.assertEqual(flow.bytes_out, 0)
        self.assertIsNone(flow.dns_query)
        self.assertIsNone(flow.ja3_hash)
        self.assertIsNone(flow.simulated_label)

    def test_integer_timestamp_accepted(self):
        flow = FlowEventSchema.model_validate(dict(BASE_EVENT, timestamp=1760000000))
        self.assertEqual(flow.timestamp, 1760000000)

    def test_extra_fields_ignored(self):
        event = dict(BASE_EVENT, malware_family="TrickBot")
        flow = FlowEventSchema.model_validate(event)
        self.assertFalse(hasattr(flow, "malware_family"))


class TestInvalidEventsRejected(unittest.TestCase):
    def test_missing_required_fields_rejected(self):
        for field in ("timestamp", "flow_id", "src_ip", "dst_ip", "dst_port"):
            event = dict(BASE_EVENT)
            del event[field]
            with self.assertRaises(ValidationError, msg=f"missing {field} should be invalid"):
                FlowEventSchema.model_validate(event)

    def test_string_timestamp_rejected(self):
        with self.assertRaises(ValidationError):
            FlowEventSchema.model_validate(dict(BASE_EVENT, timestamp="1000.0"))

    def test_bool_timestamp_rejected(self):
        with self.assertRaises(ValidationError):
            FlowEventSchema.model_validate(dict(BASE_EVENT, timestamp=True))

    def test_string_port_rejected(self):
        with self.assertRaises(ValidationError):
            FlowEventSchema.model_validate(dict(BASE_EVENT, dst_port="80"))

    def test_empty_strings_rejected(self):
        for field in ("flow_id", "src_ip", "dst_ip"):
            with self.assertRaises(ValidationError, msg=f"empty {field} should be invalid"):
                FlowEventSchema.model_validate(dict(BASE_EVENT, **{field: ""}))

    def test_none_rejected(self):
        with self.assertRaises(ValidationError):
            FlowEventSchema.model_validate(None)


class TestSimulatedLabelIsOptionalMetadata(unittest.TestCase):
    def test_label_preserved_as_passthrough(self):
        flow = FlowEventSchema.model_validate(dict(BASE_EVENT, simulated_label="Reconnaissance Scan"))
        self.assertEqual(flow.simulated_label, "Reconnaissance Scan")

    def test_events_without_label_pass(self):
        event = dict(BASE_EVENT)
        self.assertNotIn("simulated_label", event)
        self.assertIsNone(FlowEventSchema.model_validate(event).simulated_label)


class TestWebSocketConfiguration(unittest.TestCase):
    def test_env_example_uses_canonical_ws_path(self):
        env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("/ws/threats", env_example)
        self.assertNotIn("/ws/alerts", env_example)

    def test_fastapi_registers_single_ws_endpoint_named_threats(self):
        main_py = (REPO_ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
        self.assertEqual(main_py.count("@app.websocket"), 1)
        self.assertIn('@app.websocket("/ws/threats")', main_py)


if __name__ == "__main__":
    unittest.main()
