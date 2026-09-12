"""
ThreatLens Kafka Stream Consumer & Ingest Engine
================================================
Consumes normalized network telemetry from Kafka topics:
  - 'traffic-flows'
  - 'dns-queries'
  - 'ssl-metadata'
Feeds events into the DetectionPipeline, persists alerts to ClickHouse,
and broadcasts alerts to connected SOC consoles via WebSockets.
"""

import asyncio
import json
import logging
import os
import queue
from typing import Any, Callable, Dict, List, Optional

from backend.app.schemas import ThreatAlertSchema
from backend.app.storage import ClickHouseAlertStore
from backend.app.websocket_manager import ConnectionManager
from engine.pipeline import DetectionPipeline

logger = logging.getLogger(__name__)


class KafkaIngestConsumer:
    """
    Consumes telemetry from Kafka topics or an in-memory queue, routes events
    through the DetectionPipeline, and persists / disseminates alerts.
    """

    def __init__(
        self,
        pipeline: Optional[DetectionPipeline] = None,
        storage: Optional[ClickHouseAlertStore] = None,
        ws_manager: Optional[ConnectionManager] = None,
        kafka_bootstrap_servers: Optional[str] = None,
        topics: Optional[List[str]] = None,
        event_queue: Optional[queue.Queue] = None,
        on_message: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.pipeline = pipeline if pipeline is not None else DetectionPipeline()
        self.storage = storage if storage is not None else ClickHouseAlertStore(auto_connect=True)
        self.ws_manager = ws_manager
        self.event_queue = event_queue
        self.on_message = on_message
        self.topics = topics or ["traffic-flows", "dns-queries", "ssl-metadata"]

        self.kafka_consumer = None
        self.is_kafka_connected = False
        self._is_running = False

        servers = kafka_bootstrap_servers or os.getenv("KAFKA_BOOTSTRAP_SERVERS")
        if servers:
            try:
                from kafka import KafkaConsumer  # type: ignore
                self.kafka_consumer = KafkaConsumer(
                    *self.topics,
                    bootstrap_servers=servers,
                    value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                    auto_offset_reset="latest",
                    enable_auto_commit=True,
                    group_id="threatlens-pipeline-group",
                    consumer_timeout_ms=1000,
                )
                self.is_kafka_connected = True
                logger.info("KafkaIngestConsumer connected to %s on topics %s", servers, self.topics)
            except Exception as exc:
                logger.warning("Kafka consumer unavailable (%s). Operating in-memory mode.", exc)
                self.kafka_consumer = None
                self.is_kafka_connected = False

    def process_message(self, topic: str, payload: Dict[str, Any]) -> List[ThreatAlertSchema]:
        """
        Routes an ingested telemetry message into the DetectionPipeline,
        persisting and broadcasting any detected threat alerts.
        """
        # Execute optional telemetry callback
        if self.on_message:
            try:
                self.on_message(topic, payload)
            except Exception:
                pass

        # Execute multi-model detection pipeline
        alerts = self.pipeline.process_flow_event(payload)

        # Archive alerts into ClickHouse / memory ring buffer
        for alert in alerts:
            self.storage.insert_alert(alert)

            # Broadcast to live WebSockets if manager is configured
            if self.ws_manager:
                # Use async broadcast safely in event loop if available, else background task
                try:
                    loop = asyncio.get_running_loop()
                    loop.create_task(self.ws_manager.broadcast(alert))
                except RuntimeError:
                    # No active event loop; direct synchronous or queue handling
                    pass

        return alerts

    def consume_batch_from_queue(self, max_records: int = 100) -> List[ThreatAlertSchema]:
        """Drains records from internal in-memory queue for offline and PCAP replay testing."""
        if not self.event_queue:
            return []

        all_alerts: List[ThreatAlertSchema] = []
        count = 0
        while not self.event_queue.empty() and count < max_records:
            try:
                item = self.event_queue.get_nowait()
                topic = item.get("topic", "traffic-flows")
                data = item.get("data", item)
                alerts = self.process_message(topic, data)
                all_alerts.extend(alerts)
                count += 1
            except queue.Empty:
                break
        return all_alerts

    async def run_consumer_loop(self, stop_event: Optional[asyncio.Event] = None):
        """Asynchronous execution loop consuming from Kafka or in-memory queue."""
        self._is_running = True
        logger.info("Starting Kafka / Ingest consumer loop...")

        while self._is_running and (not stop_event or not stop_event.is_set()):
            if self.is_kafka_connected and self.kafka_consumer is not None:
                try:
                    records_dict = await asyncio.to_thread(self.kafka_consumer.poll, timeout_ms=500)
                    for tp, records in records_dict.items():
                        for msg in records:
                            if stop_event and stop_event.is_set():
                                break
                            self.process_message(msg.topic, msg.value)
                except Exception as exc:
                    logger.debug("Kafka poll error: %s", exc)
            elif self.event_queue:
                self.consume_batch_from_queue(max_records=50)

            await asyncio.sleep(0.1)

    def stop(self):
        """Stops the consumer loop and closes Kafka connections."""
        self._is_running = False
        if self.kafka_consumer:
            try:
                self.kafka_consumer.close()
            except Exception:
                pass
