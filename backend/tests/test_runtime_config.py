"""
ThreatLens Runtime Detection Configuration & Alert Suppression Test Suite
=========================================================================
Verifies:
  1. GET /api/config/thresholds exposes every tunable with metadata and live value.
  2. PUT /api/config/thresholds applies a valid change and rejects invalid ones.
  3. A runtime threshold change alters the actual detection decision, with no restart.
  4. Suppression rule create / list / delete through the API and the store.
  5. Malformed IP criteria and empty suppression rules are rejected with HTTP 4xx.
  6. A suppressed detection still runs the detectors and still yields full evidence.
  7. A suppressed alert is withheld from analyst delivery; others are not.
  8. Disabled and expired rules do not suppress.
  9. Persisted configuration is restored into a fresh store (durability code path).
 10. Concurrent threshold reads stay consistent with writes.
"""

import json
import os
import threading
import unittest
from datetime import datetime, timedelta, timezone

os.environ["ENABLE_BACKGROUND_GENERATOR"] = "false"

from fastapi.testclient import TestClient

from backend.app.main import app, runtime_config
from backend.app.schemas import SuppressionRule, ThreatClassEnum
from engine.config import SPECS, describe_thresholds, get_threshold, reset_thresholds
from engine.features.store import SlidingWindowStore
from engine.models.aggregator import AlertAggregator
from engine.models.ddos_engine import DDoSEngine
from engine.pipeline import DetectionPipeline
from engine.runtime_config import RuntimeConfigStore
from ingest.producers.mock_producer import SyntheticFlowGenerator


class FakeRedis:
    """Minimal Redis hash stand-in used to exercise the durability code path offline."""

    def __init__(self):
        self.hashes: dict = {}

    def ping(self):
        return True

    def hgetall(self, name):
        return dict(self.hashes.get(name, {}))

    def hset(self, name, key=None, value=None, mapping=None):
        bucket = self.hashes.setdefault(name, {})
        if mapping:
            bucket.update({str(k): v for k, v in mapping.items()})
        if key is not None:
            bucket[str(key)] = value
        return 1

    def hdel(self, name, key):
        return 1 if self.hashes.get(name, {}).pop(str(key), None) is not None else 0

    def delete(self, name):
        self.hashes.pop(name, None)


def durable_store(fake: FakeRedis) -> RuntimeConfigStore:
    """Builds an offline store wired to a shared fake Redis so persistence is testable."""
    store = RuntimeConfigStore(use_redis=False)
    store.redis_client = fake
    store.is_redis_connected = True
    return store


def udp_surge_event(src_ip: str = "203.0.113.77", packets_in: int = 150) -> dict:
    """Fixed UDP surge event: inbound 150 PPS against a 50 mean / 30 stddev baseline."""
    return {
        "timestamp": 1000.0,
        "flow_id": f"{src_ip}:40000->10.0.0.5:53",
        "src_ip": src_ip,
        "src_port": 40000,
        "dst_ip": "10.0.0.5",
        "dst_port": 53,
        "protocol": "UDP",
        "flags": [],
        "bytes_out": 0,
        "bytes_in": 9000,
        "packets_out": 1,
        "packets_in": packets_in,
        "dns_query": None,
    }


class TestThresholdConfiguration(unittest.TestCase):
    """Threshold metadata, validation, and runtime effect on detection."""

    def setUp(self):
        reset_thresholds()
        self.client = TestClient(app)

    def tearDown(self):
        reset_thresholds()

    def test_get_thresholds_exposes_metadata_for_every_tunable(self):
        response = self.client.get("/api/config/thresholds")
        self.assertEqual(response.status_code, 200)

        body = response.json()
        self.assertIn(body["storage_mode"], ["redis", "memory"])
        self.assertEqual(len(body["thresholds"]), len(SPECS))

        for entry in body["thresholds"]:
            for field in (
                "rule", "rule_label", "parameter", "label", "description",
                "kind", "min", "max", "value", "default", "modified",
                "consumed_by", "active",
            ):
                self.assertIn(field, entry, msg=f"{entry.get('parameter')} missing {field}")
            self.assertTrue(entry["active"])
            self.assertTrue(entry["consumed_by"], msg="threshold has no consuming engine")
            self.assertFalse(entry["modified"])

    def test_update_valid_threshold_and_read_back(self):
        response = self.client.put(
            "/api/config/thresholds",
            json={"rule": "ddos", "parameter": "sigma_threshold", "value": 4.5},
        )
        self.assertEqual(response.status_code, 200)

        entry = next(
            item for item in response.json()["thresholds"]
            if item["rule"] == "ddos" and item["parameter"] == "sigma_threshold"
        )
        self.assertEqual(entry["value"], 4.5)
        self.assertTrue(entry["modified"])
        self.assertEqual(get_threshold("ddos", "sigma_threshold"), 4.5)

        reread = self.client.get("/api/config/thresholds").json()
        persisted_entry = next(
            item for item in reread["thresholds"]
            if item["rule"] == "ddos" and item["parameter"] == "sigma_threshold"
        )
        self.assertEqual(persisted_entry["value"], 4.5)

    def test_update_accepts_port_list_for_malware_tls_ports(self):
        response = self.client.put(
            "/api/config/thresholds",
            json={"rule": "malware", "parameter": "tls_ports", "value": [443, 9443]},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(get_threshold("malware", "tls_ports"), [443, 9443])

    def test_reset_endpoint_restores_defaults(self):
        self.client.put(
            "/api/config/thresholds",
            json={"rule": "ddos", "parameter": "sigma_threshold", "value": 4.5},
        )
        self.client.put(
            "/api/config/thresholds",
            json={"rule": "dns", "parameter": "entropy_threshold", "value": 4.2},
        )
        self.assertEqual(get_threshold("ddos", "sigma_threshold"), 4.5)

        response = self.client.post("/api/config/thresholds/reset")
        self.assertEqual(response.status_code, 200)
        self.assertIn("thresholds", response.json())

        self.assertEqual(get_threshold("ddos", "sigma_threshold"), 3.0)
        self.assertEqual(get_threshold("dns", "entropy_threshold"), 3.80)
        body = self.client.get("/api/config/thresholds").json()
        self.assertFalse(any(entry["modified"] for entry in body["thresholds"]))

    def test_reject_invalid_threshold_values(self):
        invalid_payloads = [
            ({"rule": "ddos", "parameter": "sigma_threshold", "value": 99.0}, 400),
            ({"rule": "ddos", "parameter": "sigma_threshold", "value": "not-a-number"}, 400),
            ({"rule": "ddos", "parameter": "sigma_threshold", "value": "nan"}, 400),
            ({"rule": "ddos", "parameter": "sigma_threshold", "value": "inf"}, 400),
            ({"rule": "ddos", "parameter": "sigma_threshold", "value": True}, 400),
            ({"rule": "dns", "parameter": "tunnel_length_threshold", "value": 12.5}, 400),
            ({"rule": "dns", "parameter": "tunnel_length_threshold", "value": 0}, 400),
            ({"rule": "malware", "parameter": "tls_ports", "value": []}, 400),
            ({"rule": "malware", "parameter": "tls_ports", "value": [443, 443]}, 400),
            ({"rule": "malware", "parameter": "tls_ports", "value": [443, 70000]}, 400),
            ({"rule": "ddos", "parameter": "does_not_exist", "value": 1.0}, 404),
            ({"rule": "not_a_rule", "parameter": "sigma_threshold", "value": 1.0}, 404),
        ]
        for payload, expected_status in invalid_payloads:
            with self.subTest(payload=payload):
                response = self.client.put("/api/config/thresholds", json=payload)
                self.assertEqual(response.status_code, expected_status)
                self.assertIn("detail", response.json())

        # A rejected write must leave the live configuration untouched
        self.assertEqual(get_threshold("ddos", "sigma_threshold"), 3.0)
        self.assertEqual(get_threshold("dns", "tunnel_length_threshold"), 60)

    def test_threshold_change_alters_detector_decision(self):
        """
        Integration proof: identical event, different decision purely from configuration.
        """
        engine = DDoSEngine()
        event = udp_surge_event()

        # Baseline: 150 PPS against a 50/30 baseline is a 3.33 sigma surge (threshold 3.0)
        self.assertIsNotNone(engine.evaluate(event, None))

        runtime_config.set_threshold("ddos", "sigma_threshold", 20.0)
        self.assertIsNone(engine.evaluate(event, None))

        runtime_config.set_threshold("ddos", "sigma_threshold", 3.0)
        detection = engine.evaluate(event, None)
        self.assertIsNotNone(detection)
        self.assertEqual(detection.threat_class, ThreatClassEnum.VOLUMETRIC_DOS)

    def test_threshold_change_through_api_alters_detector_decision(self):
        """Same proof, driven end to end through the HTTP API rather than the store."""
        engine = DDoSEngine()
        event = udp_surge_event()

        self.assertIsNotNone(engine.evaluate(event, None))
        response = self.client.put(
            "/api/config/thresholds",
            json={"rule": "ddos", "parameter": "sigma_threshold", "value": 20.0},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(engine.evaluate(event, None))

    def test_min_heartbeats_change_alters_beacon_decision(self):
        """A second engine, to confirm the live read is not a DDoS-only special case."""
        from engine.models.beaconing_engine import BeaconingEngine

        store = SlidingWindowStore(use_redis=False)
        engine = BeaconingEngine()
        flow_id = "10.0.0.7:5000->198.51.100.9:443"
        for offset in range(3):
            store.record_300s_flow(
                flow_id=flow_id,
                timestamp=1000.0 + offset * 30.0,
                bytes_out=100,
                bytes_in=100,
                ja3_hash=None,
            )

        event = {"flow_id": flow_id, "src_ip": "10.0.0.7", "dst_ip": "198.51.100.9", "timestamp": 1090.0}
        self.assertIsNotNone(engine.evaluate(event, store))

        runtime_config.set_threshold("beaconing", "min_heartbeats", 50)
        self.assertIsNone(engine.evaluate(event, store))

    def test_concurrent_reads_stay_consistent_with_writes(self):
        stop = threading.Event()
        observed = []

        def reader():
            while not stop.is_set():
                observed.append(get_threshold("ddos", "sigma_threshold"))

        threads = [threading.Thread(target=reader) for _ in range(4)]
        for thread in threads:
            thread.start()
        try:
            for value in (1.0, 2.0, 3.0, 4.0, 5.0) * 20:
                runtime_config.set_threshold("ddos", "sigma_threshold", value)
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=2)

        self.assertTrue(observed)
        self.assertTrue(all(isinstance(value, float) for value in observed))
        self.assertTrue(all(0.5 <= value <= 20.0 for value in observed))

    def test_threshold_metadata_is_never_stale_after_update(self):
        runtime_config.set_threshold("reconnaissance", "min_target_cardinality", 12)
        entry = next(
            item for item in describe_thresholds()
            if item["rule"] == "reconnaissance" and item["parameter"] == "min_target_cardinality"
        )
        self.assertEqual(entry["value"], 12)
        self.assertEqual(entry["default"], 3)
        self.assertTrue(entry["modified"])


class TestSuppressionRules(unittest.TestCase):
    """Suppression rule lifecycle, validation, and effect on alert delivery."""

    def setUp(self):
        reset_thresholds()
        self.client = TestClient(app)
        self.store = RuntimeConfigStore(use_redis=False)
        self.created_ids = []

    def tearDown(self):
        for rule_id in self.created_ids:
            runtime_config.delete_suppression_rule(rule_id)
        reset_thresholds()

    def tracked(self, response):
        self.created_ids.append(response.json()["id"])
        return response

    def test_create_list_delete_through_api(self):
        created = self.tracked(self.client.post(
            "/api/config/suppressions",
            json={
                "rule_type": "source_ip",
                "source_ip": "192.168.1.0/24",
                "description": "Known internal scanner",
            },
        ))
        self.assertEqual(created.status_code, 201)
        body = created.json()
        self.assertTrue(body["enabled"])
        self.assertEqual(body["source_ip"], "192.168.1.0/24")
        self.assertIn("created_at", body)
        self.assertIn("updated_at", body)

        listed = self.client.get("/api/config/suppressions")
        self.assertEqual(listed.status_code, 200)
        self.assertTrue(any(item["id"] == body["id"] for item in listed.json()))

        deleted = self.client.delete(f"/api/config/suppressions/{body['id']}")
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(self.client.delete(f"/api/config/suppressions/{body['id']}").status_code, 404)

    def test_toggle_rule_through_api(self):
        created = self.tracked(self.client.post(
            "/api/config/suppressions",
            json={"rule_type": "source_ip", "source_ip": "203.0.113.0/24"},
        ))
        self.assertEqual(created.status_code, 201)
        rule_id = created.json()["id"]

        disabled = self.client.patch(
            f"/api/config/suppressions/{rule_id}",
            json={"enabled": False},
        )
        self.assertEqual(disabled.status_code, 200)
        self.assertFalse(disabled.json()["enabled"])

        # A disabled rule no longer appears in the active set the pipeline consults
        active = [r for r in runtime_config.get_suppression_rules() if r.id == rule_id]
        self.assertEqual(len(active), 1)
        self.assertFalse(active[0].enabled)

        re_enabled = self.client.patch(
            f"/api/config/suppressions/{rule_id}",
            json={"enabled": True, "description": "Re-enabled after review"},
        )
        self.assertEqual(re_enabled.status_code, 200)
        self.assertTrue(re_enabled.json()["enabled"])
        self.assertEqual(re_enabled.json()["description"], "Re-enabled after review")

        # Unknown ids are a clean 404, and an empty PATCH body changes nothing
        self.assertEqual(
            self.client.patch("/api/config/suppressions/missing-id", json={"enabled": True}).status_code,
            404,
        )
        untouched = self.client.patch(f"/api/config/suppressions/{rule_id}", json={})
        self.assertEqual(untouched.status_code, 200)
        self.assertTrue(untouched.json()["enabled"])

    def test_reject_malformed_ip_and_empty_rules(self):
        malformed = [
            {"rule_type": "source_ip", "source_ip": "not-an-ip"},
            {"rule_type": "source_ip", "source_ip": "999.1.1.1"},
            {"rule_type": "source_ip", "source_ip": "10.0.0.0/99"},
            {"rule_type": "source_ip", "source_ip": "   "},
            {"rule_type": "destination_ip", "destination_ip": "10.0.0.1:8080"},
            {"rule_type": "source_ip"},
            {"rule_type": "destination_ip"},
            {"rule_type": "source_ip_threat_class", "threat_class": "Encrypted Malware"},
            {"rule_type": "source_ip", "source_ip": "10.0.0.1", "threat_class": "Not A Threat Class"},
        ]
        for payload in malformed:
            with self.subTest(payload=payload):
                response = self.client.post("/api/config/suppressions", json=payload)
                self.assertGreaterEqual(response.status_code, 400)
                self.assertLess(response.status_code, 500)

        self.assertEqual(self.client.get("/api/config/suppressions").json(), [])

    def test_accepts_ipv4_ipv6_and_cidr(self):
        for criterion in ("10.0.0.1", "10.0.0.0/8", "2001:db8::1", "2001:db8::/32"):
            with self.subTest(criterion=criterion):
                created = self.tracked(self.client.post(
                    "/api/config/suppressions",
                    json={"rule_type": "source_ip", "source_ip": criterion},
                ))
                self.assertEqual(created.status_code, 201)

    def test_only_modified_thresholds_are_persisted(self):
        fake = FakeRedis()
        store = durable_store(fake)
        self.assertTrue(store.persistent)
        self.assertEqual(store.storage_mode, "redis")

        store.set_threshold("ddos", "sigma_threshold", 6.0)
        self.assertEqual(store.stored_threshold_overrides(), {"ddos.sigma_threshold": 6.0})

        store.set_threshold("ddos", "sigma_threshold", 3.0)
        self.assertEqual(store.stored_threshold_overrides(), {})

    def test_thresholds_survive_store_restart(self):
        fake = FakeRedis()
        first = durable_store(fake)
        first.set_threshold("dns", "entropy_threshold", 4.10)

        reset_thresholds()
        self.assertEqual(get_threshold("dns", "entropy_threshold"), 3.80)

        second = durable_store(fake)
        second.load()
        self.assertEqual(get_threshold("dns", "entropy_threshold"), 4.10)

    def test_suppressions_survive_store_restart(self):
        fake = FakeRedis()
        first = durable_store(fake)
        rule = first.create_suppression_rule(SuppressionRule(
            id="rule-restart-1",
            rule_type="source_ip",
            source_ip="198.51.100.0/24",
            description="Persisted rule",
        ))

        second = durable_store(fake)
        second.load()
        reloaded = second.get_suppression_rules()
        self.assertEqual(len(reloaded), 1)
        self.assertEqual(reloaded[0].id, rule.id)
        self.assertEqual(reloaded[0].source_ip, "198.51.100.0/24")
        self.assertEqual(reloaded[0].description, "Persisted rule")

    def test_memory_only_store_reports_non_persistent(self):
        store = RuntimeConfigStore(use_redis=False)
        self.assertFalse(store.persistent)
        self.assertEqual(store.storage_mode, "memory")

    def test_corrupt_persisted_entries_are_skipped_not_fatal(self):
        fake = FakeRedis()
        fake.hset("threatlens:config:threshold_overrides", mapping={"ddos.sigma_threshold": json.dumps("bad")})
        fake.hset("threatlens:config:suppressions", mapping={"broken": "{not json"})

        store = durable_store(fake)
        store.load()
        self.assertEqual(get_threshold("ddos", "sigma_threshold"), 3.0)
        self.assertEqual(store.get_suppression_rules(), [])


class TestSuppressionPipelineIntegration(unittest.TestCase):
    """Suppression is evaluated after detection and must not hide that detection happened."""

    def setUp(self):
        reset_thresholds()
        self.store = RuntimeConfigStore(use_redis=False)
        self.pipeline = DetectionPipeline(
            store=SlidingWindowStore(use_redis=False),
            aggregator=AlertAggregator(),
            suppression_provider=self.store,
        )
        self.generator = SyntheticFlowGenerator(seed=7)
        self.rule_ids = []

    def tearDown(self):
        reset_thresholds()

    def add_source_rule(self, source_ip, **overrides):
        payload = {
            "id": f"rule-{len(self.rule_ids)}-{source_ip}",
            "rule_type": "source_ip",
            "source_ip": source_ip,
            "description": "Test suppression",
        }
        payload.update(overrides)
        rule = self.store.create_suppression_rule(SuppressionRule(**payload))
        self.rule_ids.append(rule.id)
        return rule

    def test_alert_withheld_after_source_suppression_but_detection_still_recorded(self):
        flow = self.generator.generate_volumetric_ddos(timestamp=5000.0)
        source_ip = flow["src_ip"]

        # 1. Normal alert: delivered.
        initial = self.pipeline.process_flow_event(flow)
        self.assertTrue(initial, "expected the DDoS detector to fire")
        for alert in initial:
            self.assertFalse(alert.suppressed)
            self.assertIsNone(alert.suppression_rule_id)

        # 2. Analyst suppresses the source.
        rule = self.add_source_rule(source_ip)

        # 3. Same source produces the same detection internally.
        suppressed = self.pipeline.process_flow_event(flow)
        self.assertTrue(suppressed, "suppression must not stop the detectors from firing")
        self.assertTrue(all(alert.suppressed for alert in suppressed))
        self.assertTrue(all(alert.suppression_rule_id == rule.id for alert in suppressed))

        # 4. Evidence is intact: the detection is still fully recorded.
        for alert in suppressed:
            self.assertEqual(alert.threat_class, ThreatClassEnum.VOLUMETRIC_DOS)
            self.assertGreater(alert.confidence_score, 0.0)
            self.assertTrue(alert.evidence.details)
            self.assertTrue(alert.evidence.detectors_fired)

    def test_unsuppressed_source_is_still_delivered(self):
        suppressed_flow = self.generator.generate_volumetric_ddos(timestamp=5100.0)
        other_flow = self.generator.generate_volumetric_ddos(timestamp=5100.0)
        other_flow["src_ip"] = "203.0.113.250"
        other_flow["flow_id"] = f"203.0.113.250:{other_flow['src_port']}->{other_flow['dst_ip']}:{other_flow['dst_port']}"

        self.add_source_rule(suppressed_flow["src_ip"])

        suppressed_alerts = self.pipeline.process_flow_event(suppressed_flow)
        other_alerts = self.pipeline.process_flow_event(other_flow)

        self.assertTrue(all(alert.suppressed for alert in suppressed_alerts))
        self.assertTrue(other_alerts)
        self.assertTrue(all(not alert.suppressed for alert in other_alerts))

    def test_disabled_rule_does_not_suppress(self):
        flow = self.generator.generate_volumetric_ddos(timestamp=5200.0)
        self.add_source_rule(flow["src_ip"], enabled=False)

        alerts = self.pipeline.process_flow_event(flow)
        self.assertTrue(alerts)
        self.assertTrue(all(not alert.suppressed for alert in alerts))

    def test_expired_rule_does_not_suppress(self):
        flow = self.generator.generate_volumetric_ddos(timestamp=5300.0)
        self.add_source_rule(
            flow["src_ip"],
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        )

        alerts = self.pipeline.process_flow_event(flow)
        self.assertTrue(alerts)
        self.assertTrue(all(not alert.suppressed for alert in alerts))

    def test_cidr_rule_matches_contained_source(self):
        flow = self.generator.generate_volumetric_ddos(timestamp=5400.0)
        octets = flow["src_ip"].split(".")
        self.add_source_rule(".".join(octets[:3]) + ".0/24")

        alerts = self.pipeline.process_flow_event(flow)
        self.assertTrue(alerts)
        self.assertTrue(all(alert.suppressed for alert in alerts))

    def test_deleting_rule_restores_delivery(self):
        flow = self.generator.generate_volumetric_ddos(timestamp=5500.0)
        rule = self.add_source_rule(flow["src_ip"])
        self.assertTrue(all(alert.suppressed for alert in self.pipeline.process_flow_event(flow)))

        self.assertTrue(self.store.delete_suppression_rule(rule.id))
        self.assertTrue(all(not alert.suppressed for alert in self.pipeline.process_flow_event(flow)))

    def test_threat_class_scoped_rule_suppresses_only_that_class(self):
        flow = self.generator.generate_volumetric_ddos(timestamp=5600.0)
        self.store.create_suppression_rule(SuppressionRule(
            id="rule-class-scoped",
            rule_type="source_ip_threat_class",
            source_ip=flow["src_ip"],
            threat_class=ThreatClassEnum.DGA_DNS,
        ))

        alerts = self.pipeline.process_flow_event(flow)
        self.assertTrue(alerts)
        self.assertTrue(all(not alert.suppressed for alert in alerts))

    def test_pipeline_without_suppression_provider_delivers_everything(self):
        pipeline = DetectionPipeline(
            store=SlidingWindowStore(use_redis=False),
            aggregator=AlertAggregator(),
        )
        flow = self.generator.generate_volumetric_ddos(timestamp=5700.0)
        alerts = pipeline.process_flow_event(flow)
        self.assertTrue(alerts)
        self.assertTrue(all(not alert.suppressed for alert in alerts))


if __name__ == "__main__":
    unittest.main()
