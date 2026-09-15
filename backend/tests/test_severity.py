"""
ThreatLens Centralized Severity Calibration Test Suite
======================================================
Verifies:
  1. Boundary behaviour of the canonical calibrate_severity mapping.
  2. ThreatAlertSchema severity auto-calibration and explicit preservation.
  3. Engine-produced alerts carry severity consistent with their real
     confidence (no simulated confidence/labels involved).
  4. Severity survives aggregator -> storage -> API -> WebSocket.
  5. End-to-end severity histogram across a six-threat-class sample with
     genuinely varied evidence strength.
"""

import asyncio
import copy
import json
import os
import unittest

# Disable background generator task during test execution to prevent background thread contention
os.environ["ENABLE_BACKGROUND_GENERATOR"] = "false"
# Keep test runs out of the developer ClickHouse database (store connects at import below)
os.environ.setdefault("CLICKHOUSE_DB", "threatlens_test")

from fastapi.testclient import TestClient

from backend.app.main import alert_store, app, ws_manager
from backend.app.schemas import (
    EvidenceSchema,
    SeverityEnum,
    ThreatAlertSchema,
    ThreatClassEnum,
    calibrate_severity,
)
from backend.app.storage import ClickHouseAlertStore
from engine import config as engine_config
from engine.features.store import SlidingWindowStore
from engine.models.aggregator import AlertAggregator
from engine.pipeline import DetectionPipeline
from ingest.producers.mock_producer import SyntheticFlowGenerator


def make_alert(flow_id: str, confidence: float, threat_class=ThreatClassEnum.VOLUMETRIC_DOS, severity=None) -> ThreatAlertSchema:
    return ThreatAlertSchema(
        flow_id=flow_id,
        threat_class=threat_class,
        confidence_score=confidence,
        severity=severity,
        evidence=EvidenceSchema(
            inter_arrival_variance=0.0,
            shannon_entropy=0.0,
            byte_ratio=1.0,
            fan_out_count=1,
            ja3_hash=None,
            details="Severity test alert.",
        ),
    )


class TestSeverityCalibrationBoundaries(unittest.TestCase):
    """Boundary coverage for the canonical confidence-to-severity mapping."""

    def test_critical_boundary(self):
        self.assertEqual(calibrate_severity(0.949), SeverityEnum.HIGH)
        self.assertEqual(calibrate_severity(0.95), SeverityEnum.CRITICAL)
        self.assertEqual(calibrate_severity(0.951), SeverityEnum.CRITICAL)

    def test_high_boundary(self):
        self.assertEqual(calibrate_severity(0.899), SeverityEnum.MODERATE)
        self.assertEqual(calibrate_severity(0.90), SeverityEnum.HIGH)
        self.assertEqual(calibrate_severity(0.901), SeverityEnum.HIGH)

    def test_moderate_boundary(self):
        self.assertEqual(calibrate_severity(0.799), SeverityEnum.LOW)
        self.assertEqual(calibrate_severity(0.80), SeverityEnum.MODERATE)
        self.assertEqual(calibrate_severity(0.801), SeverityEnum.MODERATE)

    def test_extremes(self):
        self.assertEqual(calibrate_severity(0.0), SeverityEnum.LOW)
        self.assertEqual(calibrate_severity(1.0), SeverityEnum.CRITICAL)

    def test_alert_schema_auto_calibrates_severity(self):
        alert = make_alert("10.0.0.1:1->10.0.0.2:2", 0.92)
        self.assertEqual(alert.severity, SeverityEnum.HIGH)

    def test_alert_schema_preserves_explicit_severity(self):
        alert = make_alert("10.0.0.1:3->10.0.0.2:4", 0.99, severity=SeverityEnum.LOW)
        self.assertEqual(alert.severity, SeverityEnum.LOW)

    def test_alert_json_serializes_severity(self):
        payload = json.loads(make_alert("10.0.0.1:5->10.0.0.2:6", 0.97).model_dump_json())
        self.assertEqual(payload["severity"], "critical")


class ThresholdBaselineTestCase(unittest.TestCase):
    """
    Imports of backend.app.main load any analyst threshold overrides persisted
    in Redis into the live global THRESHOLDS. Tests that assert specific
    severity bands must run against the documented environment baseline, so
    this base class snapshots and restores the live configuration.
    """

    def setUp(self):
        self._saved_thresholds = copy.deepcopy(engine_config.THRESHOLDS)
        engine_config.reset_thresholds()

    def tearDown(self):
        for rule, params in self._saved_thresholds.items():
            engine_config.THRESHOLDS[rule] = params


class TestEngineSeverityDiversity(ThresholdBaselineTestCase):
    """
    Different engines legitimately produce different severity levels from
    their genuine confidence scores — no simulated labels or confidence used.
    """

    def setUp(self):
        super().setUp()
        self.store = SlidingWindowStore(use_redis=False)
        self.pipeline = DetectionPipeline(store=self.store, aggregator=AlertAggregator())
        self.generator = SyntheticFlowGenerator(seed=42)

    def test_weak_volumetric_surge_is_low_severity(self):
        # PPS just above the 3-sigma gate: z = (145-50)/30 = 3.17 -> conf ~0.76
        flow = {
            "flow_id": "203.0.113.50:40000->10.0.0.1:80",
            "src_ip": "203.0.113.50",
            "src_port": 40000,
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": "TCP",
            "packets_in": 145,
            "packets_out": 5,
            "bytes_in": 60_000,
            "bytes_out": 2_000,
            "flags": ["ACK"],
            "timestamp": 3000.0,
        }
        alerts = self.pipeline.process_flow_event(flow)
        ddos = [a for a in alerts if a.threat_class == ThreatClassEnum.VOLUMETRIC_DOS]
        self.assertEqual(len(ddos), 1)
        self.assertLess(ddos[0].confidence_score, 0.80)
        self.assertEqual(ddos[0].severity, SeverityEnum.LOW)

    def test_malware_fingerprint_match_is_critical_severity(self):
        flow = self.generator.generate_encrypted_malware()
        alerts = self.pipeline.process_flow_event(flow)
        malware = [a for a in alerts if a.threat_class == ThreatClassEnum.ENCRYPTED_MALWARE]
        self.assertEqual(len(malware), 1)
        self.assertEqual(malware[0].confidence_score, 0.96)
        self.assertEqual(malware[0].severity, SeverityEnum.CRITICAL)

    def test_recon_scan_is_moderate_severity(self):
        scanner_ip = "192.168.1.201"
        alerts = []
        for port in [21, 22, 80, 443]:
            probe = self.generator.generate_recon_scan(scanner_ip=scanner_ip, target_ip="10.0.0.99")
            probe["dst_port"] = port
            probe["timestamp"] = 4000.0
            alerts = self.pipeline.process_flow_event(probe)
        recon = [a for a in alerts if a.threat_class == ThreatClassEnum.RECON_SCAN]
        self.assertEqual(len(recon), 1)
        self.assertEqual(recon[0].severity, SeverityEnum.MODERATE)

    def test_every_alert_severity_matches_canonical_calibration(self):
        flows = [
            self.generator.generate_volumetric_ddos(),
            self.generator.generate_dga_dns_tunnel(),
            self.generator.generate_encrypted_malware(),
            self.generator.generate_data_exfiltration(),
        ]
        for flow in flows:
            for alert in self.pipeline.process_flow_event(flow):
                self.assertEqual(alert.severity, calibrate_severity(alert.confidence_score))

    def test_no_simulated_confidence_or_label_in_alerts(self):
        for flow in [
            self.generator.generate_volumetric_ddos(),
            self.generator.generate_dga_dns_tunnel(),
            self.generator.generate_encrypted_malware(),
            self.generator.generate_data_exfiltration(),
        ]:
            for alert in self.pipeline.process_flow_event(flow):
                dumped = alert.model_dump_json()
                self.assertNotIn("simulated_confidence", dumped)
                self.assertNotIn("simulated_label", dumped)


class TestSeveritySurvivesPipelineLayers(unittest.TestCase):
    """detector -> aggregator -> storage -> API -> WebSocket severity preservation."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_aggregator_assigns_severity_to_pipeline_alerts(self):
        store = SlidingWindowStore(use_redis=False)
        pipeline = DetectionPipeline(store=store, aggregator=AlertAggregator())
        generator = SyntheticFlowGenerator(seed=7)

        alerts = pipeline.process_flow_event(generator.generate_volumetric_ddos())
        self.assertGreaterEqual(len(alerts), 1)
        for alert in alerts:
            self.assertIsNotNone(alert.severity)
            self.assertEqual(alert.severity, calibrate_severity(alert.confidence_score))

    def test_storage_roundtrip_preserves_severity(self):
        store = ClickHouseAlertStore(auto_connect=False)
        explicit = make_alert("10.1.1.1:1000->10.2.2.2:80", 0.93, severity=SeverityEnum.LOW)
        auto = make_alert("10.1.1.2:1001->10.2.2.2:80", 0.87)
        store.insert_alert(explicit)
        store.insert_alert(auto)

        stored = {a.flow_id: a for a in store.get_recent_alerts(limit=10)}
        self.assertEqual(stored[explicit.flow_id].severity, SeverityEnum.LOW)
        self.assertEqual(stored[auto.flow_id].severity, SeverityEnum.MODERATE)

    def test_api_returns_severity_field(self):
        alert = make_alert("10.3.3.3:2000->10.4.4.4:443", 0.92)
        alert_store.insert_alert(alert)

        response = self.client.get("/api/alerts?limit=50")
        self.assertEqual(response.status_code, 200)
        matching = [a for a in response.json() if a["flow_id"] == alert.flow_id]
        self.assertTrue(matching)
        self.assertEqual(matching[0]["severity"], "high")

    def test_websocket_broadcast_carries_severity(self):
        with self.client.websocket_connect("/ws/threats") as websocket:
            websocket.send_text("ping")
            self.assertEqual(websocket.receive_text(), '{"type":"pong"}')

            broadcast_alert = make_alert(
                "10.5.5.5:3000->10.6.6.6:8443",
                0.97,
                threat_class=ThreatClassEnum.BOTNET_C2,
                severity=SeverityEnum.LOW,
            )
            asyncio.run(ws_manager.broadcast(broadcast_alert))

            received = json.loads(websocket.receive_text())
            self.assertEqual(received["flow_id"], broadcast_alert.flow_id)
            self.assertEqual(received["severity"], "low")


class TestSeverityHistogramEndToEnd(ThresholdBaselineTestCase):
    """
    Six-threat-class sample with genuinely varied evidence strength driven
    through the real pipeline. Asserts the severity distribution is healthy
    and derived purely from real detector confidence.
    """

    def setUp(self):
        super().setUp()
        self.store = SlidingWindowStore(use_redis=False)
        self.pipeline = DetectionPipeline(store=self.store, aggregator=AlertAggregator())
        self.generator = SyntheticFlowGenerator(seed=99)

    def _flow(self, src_ip, src_port, dst_ip, dst_port, **overrides):
        flow = {
            "flow_id": f"{src_ip}:{src_port}->{dst_ip}:{dst_port}",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": "TCP",
            "packets_in": 0,
            "packets_out": 1,
            "bytes_in": 0,
            "bytes_out": 0,
            "flags": [],
            "timestamp": 5000.0,
        }
        flow.update(overrides)
        return flow

    def _beacon_train(self, src_ip, timestamps):
        alerts = []
        for ts in timestamps:
            event = self._flow(
                src_ip, 5555, "198.51.100.44", 8443,
                bytes_out=500, bytes_in=400, packets_out=2, packets_in=2,
                flags=["PSH", "ACK"], timestamp=ts,
            )
            alerts = self.pipeline.process_flow_event(event)
        return [a for a in alerts if a.threat_class == ThreatClassEnum.BOTNET_C2]

    def _recon_scan(self, scanner_ip, ports):
        alerts = []
        for port in ports:
            probe = self.generator.generate_recon_scan(scanner_ip=scanner_ip, target_ip="10.0.0.99")
            probe["dst_port"] = port
            probe["timestamp"] = 6000.0
            alerts = self.pipeline.process_flow_event(probe)
        return [a for a in alerts if a.threat_class == ThreatClassEnum.RECON_SCAN]

    def test_six_class_sample_produces_healthy_severity_histogram(self):
        collected = []

        # DDoS — weak surge (z ~3.2, conf ~0.76)
        collected += self.pipeline.process_flow_event(self._flow(
            "203.0.113.50", 40001, "10.0.0.1", 80,
            packets_in=145, packets_out=5, bytes_in=60_000, bytes_out=2_000,
            flags=["ACK"],
        ))
        # DDoS — moderate surge (z ~6.7, conf ~0.86)
        collected += self.pipeline.process_flow_event(self._flow(
            "203.0.113.51", 40002, "10.0.0.2", 80,
            packets_in=250, packets_out=5, bytes_in=100_000, bytes_out=2_000,
            flags=["ACK"],
        ))
        # DDoS — SYN flood (generator, conf 0.99)
        collected += self.pipeline.process_flow_event(self.generator.generate_volumetric_ddos())

        # C2 — slightly jittered beacons (IAT variance ~0.02, conf ~0.89)
        collected += self._beacon_train("10.7.7.7", [7000.0, 7014.85, 7030.0, 7044.85])
        # C2 — perfectly periodic beacons (variance 0, conf 0.95)
        collected += self._beacon_train("10.7.7.8", [8000.0, 8015.0, 8030.0, 8045.0])

        # DGA — minimal-margin entropy domain (conf ~0.83)
        collected += self.pipeline.process_flow_event(self._flow(
            "10.8.8.8", 40003, "8.8.8.8", 53,
            bytes_out=400, bytes_in=600, dns_query="abcdefghijklmn.example.com",
            dns_query_type="A",
        ))
        # DGA — full TXT tunnel (generator, conf 0.99)
        collected += self.pipeline.process_flow_event(self.generator.generate_dga_dns_tunnel())

        # Malware — known JA3 fingerprint (conf 0.96)
        collected += self.pipeline.process_flow_event(self.generator.generate_encrypted_malware())

        # Recon — 4-port scan (conf ~0.83)
        collected += self._recon_scan("192.168.1.201", [21, 22, 80, 443])
        # Recon — 7-port scan (conf ~0.92)
        collected += self._recon_scan("192.168.1.202", [21, 22, 23, 80, 443, 8080, 9000])

        # Exfil — 1MB asymmetric leak (conf ~0.84)
        collected += self.pipeline.process_flow_event(self._flow(
            "10.9.9.9", 40004, "203.0.113.99", 443,
            bytes_out=1_050_000, bytes_in=50_000, packets_out=100, packets_in=10,
        ))
        # Exfil — 25MB massive upload (conf 0.99)
        collected += self.pipeline.process_flow_event(self._flow(
            "10.9.9.10", 40005, "203.0.113.99", 443,
            bytes_out=25_000_000, bytes_in=250_000, packets_out=2000, packets_in=20,
        ))

        self.assertGreaterEqual(len(collected), 12)

        classes = {a.threat_class for a in collected}
        self.assertEqual(len(classes), 6, f"Expected all six threat classes, got: {classes}")

        # Every alert's severity is the canonical calibration of its real confidence.
        for alert in collected:
            self.assertEqual(alert.severity, calibrate_severity(alert.confidence_score))
            self.assertNotIn("simulated_confidence", alert.model_dump_json())

        histogram = {}
        for alert in collected:
            histogram[alert.severity] = histogram.get(alert.severity, 0) + 1

        self.assertGreaterEqual(
            len(histogram), 3,
            f"Expected at least 3 severity bands from varied-strength evidence, got: {histogram}",
        )
        dominant_share = max(histogram.values()) / len(collected)
        self.assertLess(
            dominant_share, 0.80,
            f"Single severity band covers {dominant_share:.0%} of alerts: {histogram}",
        )


if __name__ == "__main__":
    unittest.main()
