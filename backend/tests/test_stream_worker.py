"""
ThreatLens Stream Worker Unit Tests
====================================
Verifies:
  1. Raw Kafka message parsing (valid JSON, invalid JSON, non-object payloads).
  2. Canonical pipeline dispatch of representative producer events (all 6
     threat classes + benign) into the correct SlidingWindowStore windows.
  3. Malformed events are rejected without polluting the feature store.
  4. The stream worker delegates to the pipeline instead of duplicating
     dispatch logic.
"""

import json
import unittest
from pathlib import Path

from backend.app.schemas import EvidenceSchema, ThreatAlertSchema, ThreatClassEnum
from engine.features.store import WINDOW_10S, WINDOW_60S, WINDOW_300S, SlidingWindowStore
from engine.pipeline import DetectionPipeline
from engine.stream_worker import parse_message, process_raw_message, publish_alert
from ingest.producers.mock_producer import SyntheticFlowGenerator

STREAM_WORKER_SOURCE = Path(__file__).resolve().parents[2] / "engine" / "stream_worker.py"

BASE_EVENT = {
    "timestamp": 1000.0,
    "flow_id": "10.0.0.1:1000->10.0.0.2:80",
    "src_ip": "10.0.0.1",
    "dst_ip": "10.0.0.2",
    "dst_port": 80,
}


class TestParseMessage(unittest.TestCase):
    """Test suite for raw Kafka message decoding."""

    def test_valid_json_bytes(self):
        event = parse_message(b'{"src_ip": "10.0.0.1", "timestamp": 100.0}')
        self.assertEqual(event["src_ip"], "10.0.0.1")

    def test_valid_json_string(self):
        event = parse_message('{"timestamp": 1}')
        self.assertIsInstance(event, dict)

    def test_dict_passthrough(self):
        self.assertEqual(parse_message({"a": 1}), {"a": 1})

    def test_invalid_json_rejected(self):
        self.assertIsNone(parse_message(b"{not json"))
        self.assertIsNone(parse_message(""))

    def test_non_object_json_rejected(self):
        self.assertIsNone(parse_message(b"[1, 2, 3]"))
        self.assertIsNone(parse_message(b'"string"'))
        self.assertIsNone(parse_message(b"42"))

    def test_bad_utf8_rejected(self):
        self.assertIsNone(parse_message(b"\xff\xfe\x00bad"))

    def test_none_rejected(self):
        self.assertIsNone(parse_message(None))


class TestCanonicalDispatch(unittest.TestCase):
    """Test suite dispatching representative producer events via the canonical pipeline."""

    def setUp(self):
        self.store = SlidingWindowStore(use_redis=False)
        self.pipeline = DetectionPipeline(store=self.store)
        self.generator = SyntheticFlowGenerator(seed=42)

    def test_benign_flow_populates_10s_and_300s(self):
        flow = self.generator.generate_benign_flow(timestamp=1000.0)
        self.assertTrue(self.pipeline.ingest_to_store(flow))

        metrics_10s = self.store.get_10s_metrics(flow["src_ip"], current_time=1000.0)
        self.assertEqual(metrics_10s["packet_count"], 1)
        self.assertEqual(metrics_10s["total_bytes"], flow["bytes_out"])
        self.assertEqual(metrics_10s["fan_out_count"], 1)
        self.assertFalse(metrics_10s["syn_count"])  # benign flows carry ACK/PSH or no flags

        metrics_300s = self.store.get_300s_metrics(flow["flow_id"], current_time=1000.0)
        self.assertEqual(metrics_300s["connection_count"], 1)
        self.assertEqual(metrics_300s["total_bytes_out"], flow["bytes_out"])
        self.assertEqual(metrics_300s["total_bytes_in"], flow["bytes_in"])

        # Non-DNS benign flows must not touch the 60s DNS window
        if flow["dst_port"] != 53:
            dns = self.store.get_60s_dns_metrics(flow["src_ip"], current_time=1000.0)
            self.assertEqual(dns["query_count"], 0)

    def test_dns_query_populates_60s_dns_window(self):
        event = self.generator.generate_dga_dns_tunnel(timestamp=2000.0)
        self.assertTrue(self.pipeline.ingest_to_store(event))

        dns = self.store.get_60s_dns_metrics(event["src_ip"], current_time=2000.0)
        self.assertEqual(dns["query_count"], 1)
        self.assertEqual(dns["unique_domain_count"], 1)
        self.assertGreater(dns["max_entropy"], 3.5)
        self.assertIn(event["dns_query"], dns["high_entropy_domains"])

    def test_recon_scan_populates_60s_recon_window(self):
        probes = [
            self.generator.generate_recon_scan(timestamp=3000.0 + i, target_ip="10.9.9.9")
            for i in range(5)
        ]
        for event in probes:
            self.assertTrue(self.pipeline.ingest_to_store(event))

        recon = self.store.get_60s_recon_metrics("192.168.1.88", current_time=3010.0)
        self.assertEqual(recon["probe_count"], 5)
        self.assertEqual(recon["unique_target_ips"], 1)
        self.assertGreaterEqual(recon["unique_target_ports"], 5)

        # SYN probes must also register in the 10s volumetric tier
        metrics_10s = self.store.get_10s_metrics("192.168.1.88", current_time=3010.0)
        self.assertEqual(metrics_10s["syn_count"], 5)

    def test_volumetric_ddos_registers_syn_packets(self):
        event = self.generator.generate_volumetric_ddos(timestamp=4000.0)
        self.assertTrue(self.pipeline.ingest_to_store(event))

        metrics_10s = self.store.get_10s_metrics(event["src_ip"], current_time=4000.0)
        self.assertEqual(metrics_10s["packet_count"], 1)
        self.assertEqual(metrics_10s["syn_count"], 1)

        # SYN-flood TCP traffic is also tracked as probing by source
        recon = self.store.get_60s_recon_metrics(event["src_ip"], current_time=4000.0)
        self.assertEqual(recon["probe_count"], 1)

    def test_botnet_c2_accumulates_periodic_flow_history(self):
        flow_id = "192.168.1.105:54321->198.51.100.44:8443"
        for step in [0, 15, 30, 45]:
            beacon = self.generator.generate_botnet_c2(timestamp=5000.0 + step)
            self.assertTrue(self.pipeline.ingest_to_store(beacon))

        metrics_300s = self.store.get_300s_metrics(flow_id, current_time=5000.0 + 100)
        self.assertEqual(metrics_300s["connection_count"], 4)
        self.assertAlmostEqual(metrics_300s["inter_arrival_variance"], 0.0, places=3)
        self.assertIn("e7d705a3286e19ea42f587b344ee6865", metrics_300s["ja3_hashes"])

        # Non-SYN C2 heartbeats must not appear in the recon window
        recon = self.store.get_60s_recon_metrics("192.168.1.105", current_time=5000.0 + 100)
        self.assertEqual(recon["probe_count"], 0)

    def test_data_exfiltration_byte_ratio_preserved(self):
        event = self.generator.generate_data_exfiltration(timestamp=6000.0)
        self.assertTrue(self.pipeline.ingest_to_store(event))

        metrics_300s = self.store.get_300s_metrics(event["flow_id"], current_time=6000.0)
        self.assertEqual(metrics_300s["total_bytes_out"], event["bytes_out"])
        self.assertEqual(metrics_300s["total_bytes_in"], event["bytes_in"])
        self.assertGreater(metrics_300s["byte_ratio"], 50.0)

    def test_encrypted_malware_ja3_preserved(self):
        event = self.generator.generate_encrypted_malware(timestamp=7000.0)
        self.assertTrue(self.pipeline.ingest_to_store(event))

        metrics_300s = self.store.get_300s_metrics(event["flow_id"], current_time=7000.0)
        self.assertEqual(metrics_300s["ja3_hashes"], [event["ja3_hash"]])

    def test_malformed_events_rejected_and_store_untouched(self):
        invalid_events = [
            {},
            {"src_ip": "10.0.0.1"},
            dict(timestamp="not-a-number", flow_id="f", src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80),
            dict(timestamp=100.0, flow_id="f", src_ip="", dst_ip="10.0.0.2", dst_port=80),
        ]
        for event in invalid_events:
            self.assertFalse(self.pipeline.ingest_to_store(event))
            self.assertIsNone(self.pipeline.try_process_flow_event(event))

        # No window tier may contain anything from rejected events
        self.assertEqual(self.store.get_events(WINDOW_10S, "10.0.0.1", current_time=100.0), [])
        self.assertEqual(self.store.get_events(WINDOW_60S, "dns:10.0.0.1", current_time=100.0), [])
        self.assertEqual(self.store.get_events(WINDOW_60S, "recon:10.0.0.1", current_time=100.0), [])
        self.assertEqual(self.store.get_events(WINDOW_300S, "f", current_time=100.0), [])


class StubPipeline:
    """Records delegated calls; stands in for DetectionPipeline in delegation tests."""

    def __init__(self, result=None):
        self.result = result
        self.calls = []

    def try_process_flow_event(self, event):
        self.calls.append(event)
        return self.result


class TestWorkerDelegation(unittest.TestCase):
    """Test suite proving the worker delegates to the pipeline instead of dispatching itself."""

    def test_valid_message_delegated_once(self):
        stub = StubPipeline(result=[])
        raw = json.dumps(BASE_EVENT).encode("utf-8")
        self.assertEqual(process_raw_message(stub, raw), [])
        self.assertEqual(len(stub.calls), 1)
        self.assertEqual(stub.calls[0]["flow_id"], BASE_EVENT["flow_id"])

    def test_malformed_message_not_delegated(self):
        stub = StubPipeline(result=[])
        for raw in (b"{not json", b"[1, 2, 3]", None, 42):
            self.assertIsNone(process_raw_message(stub, raw))
        self.assertEqual(stub.calls, [])

    def test_invalid_event_returns_none_via_pipeline(self):
        pipeline = DetectionPipeline(store=SlidingWindowStore(use_redis=False))
        raw = json.dumps({"src_ip": "10.0.0.1"}).encode("utf-8")
        self.assertIsNone(process_raw_message(pipeline, raw))

    def test_end_to_end_detection_through_worker_path(self):
        generator = SyntheticFlowGenerator(seed=7)
        pipeline = DetectionPipeline(store=SlidingWindowStore(use_redis=False))
        ddos = generator.generate_volumetric_ddos(timestamp=9000.0)
        raw = json.dumps(ddos).encode("utf-8")

        alerts = process_raw_message(pipeline, raw)
        self.assertIsNotNone(alerts)
        self.assertTrue(any(a.threat_class == ThreatClassEnum.VOLUMETRIC_DOS for a in alerts))
        for alert in alerts:
            self.assertIsInstance(alert, ThreatAlertSchema)

    def test_worker_contains_no_direct_store_dispatch(self):
        source = STREAM_WORKER_SOURCE.read_text(encoding="utf-8")
        for record_call in (
            "record_10s_packet",
            "record_60s_dns",
            "record_60s_recon",
            "record_300s_flow",
        ):
            self.assertNotIn(record_call, source)


class _OkFuture:
    def get(self, timeout=None):
        return None


class _FailedFuture:
    def __init__(self, exc):
        self.exc = exc

    def get(self, timeout=None):
        raise self.exc


class StubProducer:
    """Records send() calls; stands in for a KafkaProducer."""

    def __init__(self, fail=False, future=None):
        self.sent = []
        self.fail = fail
        self.future = future if future is not None else _OkFuture()

    def send(self, topic, value=None):
        if self.fail:
            raise ConnectionError("broker gone")
        self.sent.append((topic, value))
        return self.future


def make_alert(**overrides) -> ThreatAlertSchema:
    payload = dict(
        flow_id="10.0.0.1:1000->10.0.0.2:80",
        threat_class=ThreatClassEnum.RECON_SCAN,
        confidence_score=0.9,
        evidence=EvidenceSchema(
            inter_arrival_variance=0.0,
            shannon_entropy=0.0,
            byte_ratio=0.0,
            fan_out_count=5,
            details="test alert",
        ),
    )
    payload.update(overrides)
    return ThreatAlertSchema(**payload)


class TestPublishAlert(unittest.TestCase):
    def test_alert_published_as_json_bytes_to_topic(self):
        producer = StubProducer()
        alert = make_alert()
        self.assertTrue(publish_alert(producer, "threat-alerts", alert))
        self.assertEqual(len(producer.sent), 1)
        topic, value = producer.sent[0]
        self.assertEqual(topic, "threat-alerts")
        self.assertIsInstance(value, bytes)
        roundtrip = ThreatAlertSchema.model_validate_json(value)
        self.assertEqual(roundtrip.flow_id, alert.flow_id)

    def test_publish_failure_returns_false_not_raise(self):
        producer = StubProducer(fail=True)
        self.assertFalse(publish_alert(producer, "threat-alerts", make_alert()))

    def test_publish_delivery_timeout_returns_false(self):
        # send() itself returned, but broker confirmation never arrived
        producer = StubProducer(future=_FailedFuture(TimeoutError("delivery timed out")))
        self.assertFalse(publish_alert(producer, "threat-alerts", make_alert()))
        # the failed record is still recorded as attempted
        self.assertEqual(len(producer.sent), 1)

    def test_publish_broker_error_future_returns_false(self):
        producer = StubProducer(future=_FailedFuture(RuntimeError("broker went away")))
        self.assertFalse(publish_alert(producer, "threat-alerts", make_alert()))


if __name__ == "__main__":
    unittest.main()
