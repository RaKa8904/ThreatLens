"""
ThreatLens Kafka Alert Consumer Tests
=====================================
Verifies the backend consumer of the 'threat-alerts' topic:
  1. Valid ThreatAlertSchema JSON messages are persisted and broadcast.
  2. Malformed or contract-invalid messages are counted and skipped.
  3. Persistence failures are counted without killing the consumer.
  4. The consumer loop exits cleanly on stop and never runs detectors.
"""

import asyncio
import json
import unittest

from backend.app.schemas import EvidenceSchema, ThreatAlertSchema, ThreatClassEnum
from engine.kafka_consumer import KafkaAlertConsumer


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


class StubStorage:
    def __init__(self, fail_insert=False):
        self.alerts = []
        self.fail_insert = fail_insert

    def insert_alert(self, alert):
        if self.fail_insert:
            raise RuntimeError("storage down")
        self.alerts.append(alert)

    def get_recent_alerts(self, limit=50, threat_class=None):
        return list(self.alerts[:limit])


class StubWsManager:
    def __init__(self):
        self.broadcasts = []

    async def broadcast(self, alert):
        self.broadcasts.append(alert)


class _StubMessage:
    def __init__(self, value):
        self.value = value


class StubConsumer:
    """Stands in for a live KafkaConsumer; yields queued messages then stops."""

    def __init__(self, messages):
        self.messages = [_StubMessage(m) for m in messages]
        self.closed = False
        self.close_calls = 0

    def poll(self, timeout_ms=0):
        drained = self.messages
        self.messages = []
        if drained:
            return {("threat-alerts", 0): drained}
        return {}

    def close(self):
        self.close_calls += 1
        self.closed = True


class TestProcessMessage(unittest.TestCase):
    def setUp(self):
        self.storage = StubStorage()
        self.ws = StubWsManager()
        self.consumer = KafkaAlertConsumer(storage=self.storage, consumer=StubConsumer([]))

    def test_valid_alert_persisted(self):
        alert = make_alert()
        result = self.consumer.process_message(alert.model_dump_json().encode("utf-8"))
        self.assertEqual(result.flow_id, alert.flow_id)
        self.assertEqual(self.consumer.processed, 1)
        self.assertEqual(len(self.storage.alerts), 1)

    def test_valid_alert_string_payload(self):
        alert = make_alert()
        self.assertIsNotNone(self.consumer.process_message(alert.model_dump_json()))
        self.assertEqual(self.consumer.processed, 1)

    def test_malformed_json_counted_and_skipped(self):
        self.assertIsNone(self.consumer.process_message(b"{not json"))
        self.assertIsNone(self.consumer.process_message(b"\xff\xfe"))
        self.assertIsNone(self.consumer.process_message(None))
        self.assertEqual(self.consumer.malformed, 3)
        self.assertEqual(self.consumer.processed, 0)
        self.assertEqual(self.storage.alerts, [])

    def test_contract_invalid_alert_rejected(self):
        bad = json.dumps({"flow_id": "x"})  # missing threat_class/evidence/confidence
        self.assertIsNone(self.consumer.process_message(bad.encode("utf-8")))
        self.assertEqual(self.consumer.malformed, 1)
        self.assertEqual(self.storage.alerts, [])

    def test_confidence_out_of_range_rejected(self):
        payload = make_alert().model_dump(mode="json")
        payload["confidence_score"] = 1.5
        self.assertIsNone(self.consumer.process_message(json.dumps(payload).encode("utf-8")))
        self.assertEqual(self.consumer.malformed, 1)

    def test_persist_failure_counted_not_fatal_not_broadcast(self):
        ws = StubWsManager()
        consumer = KafkaAlertConsumer(
            storage=StubStorage(fail_insert=True), ws_manager=ws, consumer=StubConsumer([])
        )
        alert = make_alert()
        result = consumer.process_message(alert.model_dump_json().encode("utf-8"))
        # Alert validated (returned) but not broadcast, not counted as processed
        self.assertIsNotNone(result)
        self.assertEqual(consumer.persist_errors, 1)
        self.assertEqual(consumer.processed, 0)
        self.assertEqual(ws.broadcasts, [])

    def test_valid_alert_not_counted_processed_until_persisted(self):
        storage = StubStorage()
        consumer = KafkaAlertConsumer(storage=storage, consumer=StubConsumer([]))
        self.assertEqual(consumer.processed, 0)
        consumer.process_message(make_alert().model_dump_json().encode("utf-8"))
        self.assertEqual(consumer.processed, 1)
        self.assertEqual(len(storage.alerts), 1)


class TestBroadcast(unittest.TestCase):
    def test_valid_alert_broadcast_scheduled_on_running_loop(self):
        storage = StubStorage()
        ws = StubWsManager()
        consumer = KafkaAlertConsumer(storage=storage, ws_manager=ws, consumer=StubConsumer([]))
        alert = make_alert()

        async def scenario():
            consumer.process_message(alert.model_dump_json().encode("utf-8"))
            await asyncio.sleep(0)  # let the scheduled broadcast task run

        asyncio.run(scenario())
        self.assertEqual(len(ws.broadcasts), 1)
        self.assertEqual(ws.broadcasts[0].flow_id, alert.flow_id)

    def test_broadcast_not_scheduled_when_persist_fails(self):
        ws = StubWsManager()
        consumer = KafkaAlertConsumer(
            storage=StubStorage(fail_insert=True), ws_manager=ws, consumer=StubConsumer([])
        )
        alert = make_alert()

        async def scenario():
            consumer.process_message(alert.model_dump_json().encode("utf-8"))
            await asyncio.sleep(0)

        asyncio.run(scenario())
        self.assertEqual(ws.broadcasts, [])


class TestConsumerLoop(unittest.TestCase):
    def test_loop_drains_messages_and_stops(self):
        alert = make_alert()
        storage = StubStorage()
        ws = StubWsManager()
        stub = StubConsumer([alert.model_dump_json().encode("utf-8"), b"garbage"])
        consumer = KafkaAlertConsumer(storage=storage, ws_manager=ws, consumer=stub)

        stop_event = asyncio.Event()

        async def scenario():
            task = asyncio.create_task(consumer.run_consumer_loop(stop_event=stop_event))
            for _ in range(50):
                if consumer.processed or consumer.malformed:
                    break
                await asyncio.sleep(0.05)
            stop_event.set()
            await asyncio.wait_for(task, timeout=5)

        asyncio.run(scenario())
        self.assertEqual(consumer.processed, 1)
        self.assertEqual(consumer.malformed, 1)
        self.assertEqual(len(storage.alerts), 1)
        self.assertTrue(stub.closed)

    def test_stop_is_cooperative_and_closes_consumer_once(self):
        stub = StubConsumer([])
        consumer = KafkaAlertConsumer(storage=StubStorage(), consumer=stub)
        consumer.stop()
        # stop() only signals; the consumer is not closed concurrently
        self.assertFalse(stub.closed)

        async def scenario():
            await asyncio.wait_for(consumer.run_consumer_loop(), timeout=5)

        asyncio.run(scenario())
        # loop exited via stop flag and closed the consumer exactly once
        self.assertTrue(stub.closed)
        self.assertEqual(stub.close_calls, 1)

    def test_stop_flag_interrupts_message_processing_between_polls(self):
        alert = make_alert()
        stub = StubConsumer([alert.model_dump_json().encode("utf-8")])
        consumer = KafkaAlertConsumer(storage=StubStorage(), consumer=stub)
        consumer.stop()  # already stopped before loop starts

        async def scenario():
            await asyncio.wait_for(consumer.run_consumer_loop(), timeout=5)

        asyncio.run(scenario())
        # loop exits before draining any messages
        self.assertEqual(consumer.processed, 0)

    def test_loop_poll_error_does_not_kill_loop(self):
        class FailingPoll:
            calls = 0
            closed = False

            def poll(self, timeout_ms=0):
                type(self).calls += 1
                raise ConnectionError("broker gone")

            def close(self):
                self.closed = True

        consumer = KafkaAlertConsumer(storage=StubStorage(), consumer=FailingPoll())
        stop_event = asyncio.Event()

        async def scenario():
            task = asyncio.create_task(consumer.run_consumer_loop(stop_event=stop_event))
            await asyncio.sleep(1.2)
            stop_event.set()
            await asyncio.wait_for(task, timeout=5)

        asyncio.run(scenario())
        self.assertGreater(FailingPoll.calls, 1)


class TestNoDetectionInAlertConsumer(unittest.TestCase):
    def test_consumer_source_contains_no_pipeline_invocation(self):
        from pathlib import Path

        source = Path(__file__).resolve().parents[2].joinpath("engine", "kafka_consumer.py").read_text(encoding="utf-8")
        self.assertNotIn("process_flow_event", source)
        self.assertNotIn("from engine.pipeline", source)
        self.assertNotIn("DetectionPipeline(", source)


if __name__ == "__main__":
    unittest.main()
