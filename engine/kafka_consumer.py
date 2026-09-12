"""
ThreatLens Kafka Alert Consumer
===============================
Consumes validated threat alerts from the canonical 'threat-alerts' topic
(published by the StreamWorker), persists them to the alert store, and
broadcasts them to connected SOC consoles via WebSockets.

Detection itself happens upstream in the StreamWorker + DetectionPipeline;
this consumer never runs detectors.
"""

import asyncio
import logging
import os
from typing import Any, Optional

from kafka import KafkaConsumer

from backend.app.schemas import ThreatAlertSchema
from backend.app.storage import ClickHouseAlertStore
from backend.app.websocket_manager import ConnectionManager

logger = logging.getLogger(__name__)

ALERT_TOPIC = os.getenv("KAFKA_ALERT_TOPIC", "threat-alerts")
ALERT_GROUP_ID = "threatlens-alert-consumer"


class KafkaAlertConsumer:
    """
    Kafka consumer for the 'threat-alerts' topic. Every message must validate
    against ThreatAlertSchema; invalid messages are counted and logged, never
    persisted or broadcast.
    """

    def __init__(
        self,
        storage: Optional[ClickHouseAlertStore] = None,
        ws_manager: Optional[ConnectionManager] = None,
        bootstrap_servers: Optional[str] = None,
        topic: str = ALERT_TOPIC,
        group_id: str = ALERT_GROUP_ID,
        consumer: Optional[KafkaConsumer] = None,
    ):
        self.storage = storage if storage is not None else ClickHouseAlertStore(auto_connect=True)
        self.ws_manager = ws_manager
        self.topic = topic
        self.processed = 0
        self.malformed = 0
        self.persist_errors = 0
        self._stop = False
        self._closed = False

        if consumer is not None:
            self.consumer = consumer
        else:
            servers = bootstrap_servers or os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
            self.consumer = KafkaConsumer(
                topic,
                bootstrap_servers=servers,
                group_id=group_id,
                auto_offset_reset="earliest",
                enable_auto_commit=True,
            )
        logger.info(
            "KafkaAlertConsumer initialized (topic=%s, group=%s)", self.topic, group_id
        )

    def process_message(self, raw: Any) -> Optional[ThreatAlertSchema]:
        """
        Validates one raw Kafka message value against ThreatAlertSchema, then
        persists it and schedules the WebSocket broadcast — in that order.
        A valid alert whose persistence fails is counted in persist_errors,
        logged, and NOT broadcast. Returns the alert if it validated (even on
        persist failure), None if malformed. Never raises.
        """
        try:
            alert = ThreatAlertSchema.model_validate_json(raw)
        except Exception as exc:
            self.malformed += 1
            logger.warning("Malformed alert message skipped (%s): %.200s", type(exc).__name__, raw)
            return None

        try:
            self.storage.insert_alert(alert)
        except Exception as exc:
            self.persist_errors += 1
            logger.error("Alert %s not broadcast: persistence failed: %s", alert.flow_id, exc)
            return alert

        if self.ws_manager:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.ws_manager.broadcast(alert))
            except RuntimeError:
                logger.debug("No running event loop; alert not broadcast.")

        self.processed += 1
        return alert

    async def run_consumer_loop(self, stop_event: Optional[asyncio.Event] = None):
        """Async poll loop; safe to run as an asyncio task alongside FastAPI."""
        logger.info("KafkaAlertConsumer loop started on topic '%s'.", self.topic)
        try:
            while not self._stop and not (stop_event and stop_event.is_set()):
                try:
                    records = await asyncio.to_thread(self.consumer.poll, timeout_ms=500)
                except Exception as exc:
                    logger.error("Kafka poll error in alert consumer: %s", exc)
                    await asyncio.sleep(1)
                    continue

                for _topic_partition, messages in records.items():
                    for message in messages:
                        if self._stop or (stop_event and stop_event.is_set()):
                            break
                        self.process_message(message.value)
        finally:
            self._close()

    def stop(self):
        """
        Cooperative stop: signals the poll loop to exit. The consumer is
        closed once, by the loop itself, after the in-flight poll returns
        (bounded by the 500ms poll timeout).
        """
        self._stop = True

    def _close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.consumer.close()
        except Exception:
            pass
        logger.info(
            "KafkaAlertConsumer stopped (processed=%d malformed=%d persist_errors=%d)",
            self.processed,
            self.malformed,
            self.persist_errors,
        )
