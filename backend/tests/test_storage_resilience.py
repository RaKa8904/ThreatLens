"""Regression tests for storage self-healing semantics.

A transient backend-infrastructure failure must not permanently pin a
persistent-mode store to its in-memory fallback: reconnect must be retried
on use. Stores constructed in pure memory mode (auto_connect=False /
use_redis=False, the offline test harness) must never reach out to a real
server.
"""

import os
import unittest

os.environ.setdefault("CLICKHOUSE_DB", "threatlens_test")

from backend.app.schemas import EvidenceSchema, ThreatAlertSchema, ThreatClassEnum
from backend.app.storage import ClickHouseAlertStore
from engine.features.store import SlidingWindowStore


def make_alert(flow_id: str) -> ThreatAlertSchema:
    return ThreatAlertSchema(
        flow_id=flow_id,
        threat_class=ThreatClassEnum.RECON_SCAN,
        confidence_score=0.9,
        evidence=EvidenceSchema(
            inter_arrival_variance=0.0,
            shannon_entropy=0.0,
            byte_ratio=1.0,
            fan_out_count=1,
            ja3_hash=None,
            details="Reconnect semantics test alert.",
        ),
    )


class TestClickHouseReconnectSemantics(unittest.TestCase):
    def test_persistent_store_retries_connection_on_use(self):
        store = ClickHouseAlertStore(auto_connect=False)
        # Simulate a store that was asked to be persistent but lost its connection
        store._allow_reconnect = True
        store.is_connected = False
        calls = []
        store.connect = lambda: calls.append(1) or False

        store.insert_alert(make_alert("10.0.0.1:1->10.0.0.2:2"))

        self.assertEqual(len(calls), 1, "insert must retry the connection after a drop")

    def test_memory_only_store_never_reaches_out(self):
        store = ClickHouseAlertStore(auto_connect=False)
        self.assertFalse(store._allow_reconnect)
        calls = []
        store.connect = lambda: calls.append(1) or False

        store.insert_alert(make_alert("10.0.0.3:3->10.0.0.4:4"))

        self.assertEqual(calls, [], "auto_connect=False stores must stay pure in-memory")

    def test_reads_retry_connection_in_persistent_mode(self):
        store = ClickHouseAlertStore(auto_connect=False)
        store._allow_reconnect = True
        store.is_connected = False
        calls = []
        store.connect = lambda: calls.append(1) or False

        store.get_recent_alerts(limit=5)

        self.assertEqual(len(calls), 1, "reads must retry the connection after a drop")


class TestRedisWindowStoreReconnectSemantics(unittest.TestCase):
    def test_memory_mode_never_attempts_redis(self):
        store = SlidingWindowStore(use_redis=False)
        calls = []
        store._try_connect_redis = lambda: calls.append(1) or False

        store.add_event(10, "src-ip", 1000.0, {"probe": True})

        self.assertEqual(calls, [], "use_redis=False stores must never touch Redis")
        events = store.get_events(10, "src-ip", current_time=1005.0)
        self.assertEqual(len(events), 1)

    def test_redis_mode_retries_connection_on_write(self):
        store = SlidingWindowStore(use_redis=False)
        # Simulate a Redis-mode store that lost its connection
        store._redis_params = ("localhost", 6379, 0, None)
        store.use_redis = True
        calls = []
        store._try_connect_redis = lambda: calls.append(1) or False

        store.add_event(10, "src-ip", 1000.0, {"probe": True})

        self.assertEqual(len(calls), 1, "writes must retry the Redis connection after a drop")


if __name__ == "__main__":
    unittest.main()
