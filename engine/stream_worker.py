"""
ThreatLens Kafka Stream Worker
===============================
Thin Kafka consumer for the 'network-flows' topic. Decodes each raw message
and delegates validation, feature-store dispatch, and detection to the
canonical DetectionPipeline (engine/pipeline.py). Alerts produced by the
pipeline are published to the 'threat-alerts' topic, where the backend
KafkaAlertConsumer persists and broadcasts them.

Malformed or contract-invalid messages are counted and skipped without
interrupting the stream.
"""

import argparse
import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional, Tuple

from backend.app.schemas import ThreatAlertSchema
from engine.pipeline import DetectionPipeline

logger = logging.getLogger(__name__)

DEFAULT_TOPIC = os.getenv("KAFKA_FLOW_TOPIC", "network-flows")
DEFAULT_ALERT_TOPIC = os.getenv("KAFKA_ALERT_TOPIC", "threat-alerts")
DEFAULT_GROUP_ID = "threatlens-stream-worker"


def parse_message(raw: Any) -> Optional[Dict[str, Any]]:
    """
    Decodes a raw Kafka message value into an event dict.
    Returns None for undecodable bytes, invalid JSON, or non-object payloads.
    """
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return None
    if not isinstance(raw, dict):
        return None
    return raw


def process_raw_message(pipeline: DetectionPipeline, raw: Any) -> Optional[List[ThreatAlertSchema]]:
    """
    Decodes one raw Kafka message value and runs the canonical detection
    pipeline. Returns None if the message was malformed or the event invalid,
    otherwise the (possibly empty) list of alerts produced by the pipeline.
    """
    event = parse_message(raw)
    if event is None:
        return None
    return pipeline.try_process_flow_event(event)


def publish_alert(producer: Any, topic: str, alert: ThreatAlertSchema, delivery_timeout_seconds: float = 5.0) -> bool:
    """
    Publishes one validated alert to the alert topic as JSON bytes and waits
    for bounded broker delivery confirmation. Returns False (and logs) if the
    send raises or confirmation does not arrive within the timeout, so one
    bad publish never kills the worker loop or blocks it indefinitely.
    """
    try:
        future = producer.send(topic, value=alert.model_dump_json().encode("utf-8"))
        future.get(timeout=delivery_timeout_seconds)
        return True
    except Exception as exc:
        logger.error("Failed to publish alert %s to topic %s: %s", alert.flow_id, topic, exc)
        return False


class StreamWorker:
    """
    Kafka consumer loop that feeds every valid topic message into the
    canonical DetectionPipeline and publishes resulting alerts to the
    'threat-alerts' topic.
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str = DEFAULT_TOPIC,
        pipeline: Optional[DetectionPipeline] = None,
        group_id: str = DEFAULT_GROUP_ID,
        alert_producer: Optional[Any] = None,
        alert_topic: str = DEFAULT_ALERT_TOPIC,
    ):
        from kafka import KafkaConsumer, KafkaProducer

        self.topic = topic
        self.alert_topic = alert_topic
        self.pipeline = pipeline if pipeline is not None else DetectionPipeline()
        self.processed = 0
        self.skipped = 0
        self.alerts_detected = 0
        self.alerts_published = 0
        self.publish_errors = 0
        self._stop_event = threading.Event()
        self._closed = False

        self.consumer = KafkaConsumer(
            topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            auto_offset_reset="earliest",
        )
        if alert_producer is not None:
            self.alert_producer = alert_producer
        else:
            self.alert_producer = KafkaProducer(bootstrap_servers=bootstrap_servers)
        logger.info(
            "StreamWorker connected to Kafka at %s (flows=%s alerts=%s group=%s)",
            bootstrap_servers,
            topic,
            alert_topic,
            group_id,
        )

    def _handle_alerts(self, alerts: List[ThreatAlertSchema]) -> None:
        for alert in alerts:
            if publish_alert(self.alert_producer, self.alert_topic, alert):
                self.alerts_published += 1
            else:
                self.publish_errors += 1
            logger.info(
                "Alert: %s confidence=%.2f flow=%s",
                alert.threat_class.value,
                alert.confidence_score,
                alert.flow_id,
            )

    def stop(self) -> None:
        """Signals the run loop to exit; safe to call from another thread."""
        self._stop_event.set()

    def run(self, max_events: Optional[int] = None) -> Tuple[int, int]:
        """
        Consumes messages until stopped, interrupted, or max_events valid
        events are processed. Returns (processed, skipped) counts.
        """
        try:
            while not self._stop_event.is_set():
                records = self.consumer.poll(timeout_ms=500)
                for messages in records.values():
                    for message in messages:
                        alerts = process_raw_message(self.pipeline, message.value)
                        if alerts is None:
                            self.skipped += 1
                            logger.warning(
                                "Malformed or invalid message skipped (topic=%s partition=%s offset=%s)",
                                message.topic,
                                message.partition,
                                message.offset,
                            )
                            continue

                        self.processed += 1
                        if alerts:
                            self.alerts_detected += len(alerts)
                            self._handle_alerts(alerts)
                        if max_events is not None and self.processed >= max_events:
                            break
                    if self._stop_event.is_set() or (
                        max_events is not None and self.processed >= max_events
                    ):
                        break
                if self._stop_event.is_set() or (
                    max_events is not None and self.processed >= max_events
                ):
                    break
        except KeyboardInterrupt:
            logger.info("Stream worker stopped by user.")
        finally:
            self._shutdown()

        return self.processed, self.skipped

    def _shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.consumer.close()
        except Exception:
            pass
        try:
            self.alert_producer.flush()
            self.alert_producer.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="ThreatLens Kafka Stream Worker")
    parser.add_argument(
        "--bootstrap-servers",
        type=str,
        default=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        help="Kafka bootstrap servers (default: KAFKA_BOOTSTRAP_SERVERS or localhost:9092)",
    )
    parser.add_argument("--topic", type=str, default=DEFAULT_TOPIC, help="Kafka flows topic to consume")
    parser.add_argument("--alert-topic", type=str, default=DEFAULT_ALERT_TOPIC, help="Kafka topic to publish alerts to")
    parser.add_argument("--no-redis", action="store_true", help="Force in-memory feature store")
    parser.add_argument(
        "--max-events", type=int, default=None, help="Stop after processing N valid events"
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    from engine.features.store import SlidingWindowStore

    store = SlidingWindowStore(use_redis=not args.no_redis)
    pipeline = DetectionPipeline(store=store)
    worker = StreamWorker(
        args.bootstrap_servers,
        topic=args.topic,
        pipeline=pipeline,
        alert_topic=args.alert_topic,
    )
    processed, skipped = worker.run(max_events=args.max_events)

    print(
        f"\nStream worker finished. processed={processed} skipped={skipped} "
        f"alerts={worker.alerts_detected} published={worker.alerts_published}"
    )
    print(f"Feature store backend: {'redis' if store.is_redis_connected else 'in-memory'}")


if __name__ == "__main__":
    main()
