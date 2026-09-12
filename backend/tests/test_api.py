"""
ThreatLens FastAPI Gateway & WebSocket Streaming Test Suite
===========================================================
Verifies:
  1. GET /api/health endpoint returns 200 with service health status.
  2. GET /api/alerts retrieves and filters historical threat alerts.
  3. GET /api/metrics/throughput reports accurate throughput telemetry.
  4. WebSocket /ws/threats client connection, heartbeats, and real-time alert broadcast.
"""

import asyncio
from datetime import datetime, timezone
import json
import os
import unittest

# Disable background generator task during test execution to prevent background thread contention
os.environ["ENABLE_BACKGROUND_GENERATOR"] = "false"

from fastapi.testclient import TestClient

from backend.app.main import alert_store, app, ws_manager
from backend.app.schemas import EvidenceSchema, ThreatAlertSchema, ThreatClassEnum


class TestFastAPIGateway(unittest.TestCase):
    """Test suite for FastAPI REST endpoints and WebSocket broadcast hub."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        # Insert known test alerts into the storage
        self.sample_alert_1 = ThreatAlertSchema(
            timestamp=datetime.now(timezone.utc),
            flow_id="192.168.1.100:54321->10.0.0.1:80",
            threat_class=ThreatClassEnum.VOLUMETRIC_DOS,
            confidence_score=0.95,
            evidence=EvidenceSchema(
                inter_arrival_variance=0.0,
                shannon_entropy=0.0,
                byte_ratio=10.5,
                fan_out_count=1,
                ja3_hash=None,
                details="Volumetric SYN surge detected via TestClient.",
            ),
        )
        self.sample_alert_2 = ThreatAlertSchema(
            timestamp=datetime.now(timezone.utc),
            flow_id="192.168.1.105:44332->198.51.100.44:8443",
            threat_class=ThreatClassEnum.BOTNET_C2,
            confidence_score=0.92,
            evidence=EvidenceSchema(
                inter_arrival_variance=0.001,
                shannon_entropy=2.5,
                byte_ratio=1.0,
                fan_out_count=1,
                ja3_hash="a0e9f5d64349fb13191bc781f81f42e1",
                details="Periodic C2 beaconing detected via TestClient.",
            ),
        )
        alert_store.insert_alert(self.sample_alert_1)
        alert_store.insert_alert(self.sample_alert_2)

    def test_health_endpoint(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("services", data)
        self.assertIn("redis", data["services"])
        self.assertIn("clickhouse", data["services"])
        self.assertIn("pipeline", data["services"])
        self.assertTrue(data["services"]["pipeline"]["active"])
        self.assertEqual(data["services"]["pipeline"]["engines_count"], 6)

    def test_get_alerts_unfiltered(self):
        response = self.client.get("/api/alerts?limit=10")
        self.assertEqual(response.status_code, 200)

        alerts = response.json()
        self.assertIsInstance(alerts, list)
        self.assertGreaterEqual(len(alerts), 2)

        # Validate schema shape on first alert
        first = alerts[0]
        self.assertIn("timestamp", first)
        self.assertIn("flow_id", first)
        self.assertIn("threat_class", first)
        self.assertIn("confidence_score", first)
        self.assertIn("evidence", first)
        self.assertIn("inter_arrival_variance", first["evidence"])

    def test_get_alerts_with_threat_class_filter(self):
        # Filter for Botnet C2 Beaconing
        response = self.client.get(f"/api/alerts?threat_class={ThreatClassEnum.BOTNET_C2.value}")
        self.assertEqual(response.status_code, 200)

        alerts = response.json()
        self.assertGreaterEqual(len(alerts), 1)
        for a in alerts:
            self.assertEqual(a["threat_class"], ThreatClassEnum.BOTNET_C2.value)

    def test_metrics_throughput_endpoint(self):
        response = self.client.get("/api/metrics/throughput")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn("flows_per_sec", data)
        self.assertIn("packets_per_sec", data)
        self.assertIn("bytes_per_sec", data)
        self.assertIn("total_alerts", data)

    def test_websocket_threat_stream(self):
        with self.client.websocket_connect("/ws/threats") as websocket:
            # Send client ping
            websocket.send_text("ping")
            pong = websocket.receive_text()
            self.assertEqual(pong, '{"type":"pong"}')

            # Broadcast a test alert asynchronously
            broadcast_alert = ThreatAlertSchema(
                timestamp=datetime.now(timezone.utc),
                flow_id="10.0.0.99:9999->8.8.8.8:53",
                threat_class=ThreatClassEnum.DGA_DNS,
                confidence_score=0.98,
                evidence=EvidenceSchema(
                    inter_arrival_variance=0.0,
                    shannon_entropy=4.25,
                    byte_ratio=0.5,
                    fan_out_count=1,
                    ja3_hash=None,
                    details="High-entropy DGA domain query: kj93hf902ndk3.biz.",
                ),
            )
            asyncio.run(ws_manager.broadcast(broadcast_alert))

            # Receive the broadcasted alert over WebSocket
            received_raw = websocket.receive_text()
            received_alert = json.loads(received_raw)

            self.assertEqual(received_alert["flow_id"], "10.0.0.99:9999->8.8.8.8:53")
            self.assertEqual(received_alert["threat_class"], ThreatClassEnum.DGA_DNS.value)
            self.assertEqual(received_alert["confidence_score"], 0.98)
            self.assertAlmostEqual(received_alert["evidence"]["shannon_entropy"], 4.25)


if __name__ == "__main__":
    unittest.main()
