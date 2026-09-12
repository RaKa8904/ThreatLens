"""
ThreatLens Ingest Contract Tests
================================
Locks in the unified ingest architecture:
  1. Every module agrees on the canonical topics:
     'network-flows' (input) and 'threat-alerts' (output).
  2. No active source/config references the retired split topics
     ('traffic-flows', 'dns-queries', 'ssl-metadata').
  3. kafka-python is an explicit backend dependency.
  4. The FastAPI app has no in-process pipeline bypass: demo/synthetic
     events go through Kafka, like real traffic.
"""

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIRS = [REPO_ROOT / "engine", REPO_ROOT / "ingest", REPO_ROOT / "backend" / "app"]

STALE_TOPICS = ("traffic-flows", "dns-queries", "ssl-metadata")


class TestCanonicalTopics(unittest.TestCase):
    def test_stream_worker_defaults(self):
        from engine import stream_worker

        self.assertEqual(stream_worker.DEFAULT_TOPIC, "network-flows")
        self.assertEqual(stream_worker.DEFAULT_ALERT_TOPIC, "threat-alerts")

    def test_alert_consumer_default(self):
        from engine import kafka_consumer

        self.assertEqual(kafka_consumer.ALERT_TOPIC, "threat-alerts")

    def test_zeek_shipper_topic(self):
        from ingest.producers.zeek_kafka_shipper import TOPIC_FLOWS

        self.assertEqual(TOPIC_FLOWS, "network-flows")

    def test_mock_producer_default_topic(self):
        source = (REPO_ROOT / "ingest" / "producers" / "mock_producer.py").read_text(encoding="utf-8")
        self.assertIn('topic: str = "network-flows"', source)

    def test_env_example_documents_canonical_topics(self):
        env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("KAFKA_FLOW_TOPIC=network-flows", env_example)
        self.assertIn("KAFKA_ALERT_TOPIC=threat-alerts", env_example)

    def test_no_stale_topic_strings_in_active_source(self):
        offenders = []
        for source_dir in SOURCE_DIRS:
            for path in source_dir.rglob("*.py"):
                text = path.read_text(encoding="utf-8")
                for stale in STALE_TOPICS:
                    if stale in text:
                        offenders.append(f"{path.relative_to(REPO_ROOT)}: {stale}")
        self.assertEqual(offenders, [])

    def test_no_stale_topic_strings_in_compose_config(self):
        for config_name in ("docker-compose.yml", "docker-compose.yaml"):
            config_path = REPO_ROOT / config_name
            if config_path.exists():
                text = config_path.read_text(encoding="utf-8")
                for stale in STALE_TOPICS:
                    self.assertNotIn(stale, text)


class TestKafkaDependency(unittest.TestCase):
    def test_kafka_python_in_requirements(self):
        requirements = (REPO_ROOT / "backend" / "requirements.txt").read_text(encoding="utf-8")
        self.assertIn("kafka-python", requirements)


class TestNoPipelineBypassInApi(unittest.TestCase):
    def test_main_uses_kafka_path_not_in_process_pipeline(self):
        main_py = (REPO_ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
        self.assertNotIn("pipeline.process_flow_event", main_py)
        self.assertNotIn("KafkaIngestConsumer", main_py)
        self.assertIn("StreamWorker", main_py)
        self.assertIn("KafkaAlertConsumer", main_py)

    def test_synthetic_demo_publishes_to_kafka_topic(self):
        main_py = (REPO_ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
        self.assertIn("background_event_producer", main_py)
        self.assertIn("producer.send", main_py)

    def test_background_generation_can_be_disabled_for_tests(self):
        env_example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("INGEST_SOURCE", env_example)
        self.assertIn("ENABLE_BACKGROUND_GENERATOR", env_example)


if __name__ == "__main__":
    unittest.main()
