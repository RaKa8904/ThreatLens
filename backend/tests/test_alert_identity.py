"""Regression tests for the canonical alert identity (alert_id).

Covers:
  1. One event -> one alert per detector, each carrying an alert_id.
  2. Distinct detectors firing on the same flow produce distinct identities
     (flow_id is shared; alert_id and threat_class differ).
  3. Identity survives persistence roundtrip (memory-ring fallback path).
  4. Suppression tagging (model_copy) preserves identity.
"""

import unittest

from backend.app.schemas import ThreatClassEnum
from backend.app.storage import ClickHouseAlertStore
from engine.features.store import SlidingWindowStore
from engine.models.aggregator import AlertAggregator
from engine.models.base import BaseDetectionEngine, DetectionCandidate


class _StubEngine(BaseDetectionEngine):
    """Minimal detector returning a fixed candidate for any event."""

    def __init__(self, threat_class):
        super().__init__()
        self._threat_class = threat_class

    @property
    def threat_class(self):
        return self._threat_class

    def evaluate(self, event, store):
        return DetectionCandidate(
            threat_class=self._threat_class,
            confidence_score=0.90,
            inter_arrival_variance=0.0,
            shannon_entropy=1.0,
            byte_ratio=1.0,
            fan_out_count=1,
            ja3_hash=None,
            details="stub detection",
        )


class TestAlertIdentity(unittest.TestCase):
    def setUp(self):
        self.store = SlidingWindowStore(use_redis=False)
        self.event = {
            "flow_id": "192.168.1.105:54321->198.51.100.44:8443",
            "src_ip": "192.168.1.105",
            "src_port": 54321,
            "dst_ip": "198.51.100.44",
            "dst_port": 8443,
            "protocol": "TCP",
            "timestamp": 2000.0,
            "bytes_out": 100,
            "bytes_in": 100,
        }

    def test_single_engine_event_yields_one_alert_with_identity(self):
        aggregator = AlertAggregator(engines=[_StubEngine(ThreatClassEnum.BOTNET_C2)])
        alerts = aggregator.aggregate(self.event, self.store)
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0].alert_id)

    def test_distinct_detectors_same_flow_keep_distinct_identities(self):
        aggregator = AlertAggregator(
            engines=[
                _StubEngine(ThreatClassEnum.BOTNET_C2),
                _StubEngine(ThreatClassEnum.DATA_EXFIL),
            ]
        )
        alerts = aggregator.aggregate(self.event, self.store)
        self.assertEqual(len(alerts), 2)
        self.assertEqual({a.flow_id for a in alerts}, {self.event["flow_id"]})
        self.assertNotEqual(alerts[0].alert_id, alerts[1].alert_id)
        self.assertNotEqual(alerts[0].threat_class, alerts[1].threat_class)

    def test_identity_survives_persistence_roundtrip(self):
        store = ClickHouseAlertStore(auto_connect=False)
        aggregator = AlertAggregator(engines=[_StubEngine(ThreatClassEnum.BOTNET_C2)])
        alert = aggregator.aggregate(self.event, self.store)[0]
        store.insert_alert(alert)
        stored = store.get_recent_alerts(limit=10)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].alert_id, alert.alert_id)

    def test_suppression_tagging_preserves_identity(self):
        aggregator = AlertAggregator(engines=[_StubEngine(ThreatClassEnum.BOTNET_C2)])
        alert = aggregator.aggregate(self.event, self.store)[0]
        tagged = alert.model_copy(update={"suppressed": True, "suppression_rule_id": "rule-1"})
        self.assertEqual(tagged.alert_id, alert.alert_id)


if __name__ == "__main__":
    unittest.main()
