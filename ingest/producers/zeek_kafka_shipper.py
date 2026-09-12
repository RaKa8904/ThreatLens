"""
ThreatLens Zeek Log Shipper to Kafka
====================================
Tails structured JSON Zeek logs (conn.log, dns.log, ssl.log), normalizes
entries into standardized telemetry payloads, and publishes them across Kafka topics:
  - conn.log -> 'traffic-flows'
  - dns.log  -> 'dns-queries'
  - ssl.log  -> 'ssl-metadata'

Supports asynchronous tailing and in-memory queue fallback for offline/PCAP replay testing.
"""

import asyncio
from datetime import datetime
import json
import logging
import os
import queue
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

TOPIC_FLOWS = "traffic-flows"
TOPIC_DNS = "dns-queries"
TOPIC_SSL = "ssl-metadata"


def parse_zeek_timestamp(ts_val: Any) -> float:
    """Safely parses a Zeek timestamp (float epoch or ISO string) to epoch seconds."""
    if isinstance(ts_val, (int, float)):
        return float(ts_val)
    if isinstance(ts_val, str):
        try:
            # Handle ISO8601 format from JSON::TS_ISO8601
            dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            return dt.timestamp()
        except Exception:
            try:
                return float(ts_val)
            except Exception:
                pass
    return time.time()


def parse_zeek_history_flags(history: Optional[str]) -> List[str]:
    """
    Translates Zeek TCP state history characters into canonical flag tokens.
    'S' = SYN from orig, 'h' = SYN+ACK from resp, 'A' = ACK, 'D' = Data, 'F' = FIN, 'R' = RST.
    """
    if not history:
        return []
    flags = []
    if "S" in history and "h" not in history and "A" not in history:
        flags.append("SYN")
    elif "S" in history:
        flags.append("SYN")
    if "A" in history:
        flags.append("ACK")
    if "D" in history:
        flags.append("PSH")
    if "F" in history:
        flags.append("FIN")
    if "R" in history:
        flags.append("RST")
    return flags


def safe_int(val: Any, default: int = 0) -> int:
    """Safely coerces value to integer, handling Zeek '-' null tokens and None."""
    if val is None or val == "-":
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def normalize_conn_record(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes Zeek conn.log entry into ThreatLens flow telemetry structure."""
    src_ip = entry.get("id.orig_h") or entry.get("src_ip", "0.0.0.0")
    src_port = safe_int(entry.get("id.orig_p") or entry.get("src_port", 0))
    dst_ip = entry.get("id.resp_h") or entry.get("dst_ip", "0.0.0.0")
    dst_port = safe_int(entry.get("id.resp_p") or entry.get("dst_port", 0))
    flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"

    protocol = str(entry.get("proto") or entry.get("protocol", "TCP")).upper()
    bytes_out = safe_int(entry.get("orig_bytes") or entry.get("orig_ip_bytes") or entry.get("bytes_out") or 0)
    bytes_in = safe_int(entry.get("resp_bytes") or entry.get("resp_ip_bytes") or entry.get("bytes_in") or 0)
    packets_out = safe_int(entry.get("orig_pkts") or entry.get("packets_out") or 1)
    packets_in = safe_int(entry.get("resp_pkts") or entry.get("packets_in") or 0)

    flags = parse_zeek_history_flags(entry.get("history"))
    if not flags and "flags" in entry:
        flags = entry["flags"]

    return {
        "timestamp": parse_zeek_timestamp(entry.get("ts")),
        "flow_id": flow_id,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "flags": flags,
        "bytes_out": bytes_out,
        "bytes_in": bytes_in,
        "packets_out": packets_out,
        "packets_in": packets_in,
        "dns_query": entry.get("dns_query"),
        "dns_query_type": entry.get("dns_query_type"),
        "ja3_hash": entry.get("ja3") or entry.get("ja3_hash"),
        "ja4_hash": entry.get("ja4"),
        "uid": entry.get("uid"),
    }


def normalize_dns_record(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes Zeek dns.log entry."""
    src_ip = entry.get("id.orig_h") or entry.get("src_ip", "0.0.0.0")
    src_port = safe_int(entry.get("id.orig_p") or entry.get("src_port", 0))
    dst_ip = entry.get("id.resp_h") or entry.get("dst_ip", "0.0.0.0")
    dst_port = safe_int(entry.get("id.resp_p") or entry.get("dst_port", 53), default=53)
    return {
        "timestamp": parse_zeek_timestamp(entry.get("ts")),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "dns_query": entry.get("query"),
        "dns_query_type": entry.get("qtype_name", "A"),
        "answers": entry.get("answers", []),
        "qclass_name": entry.get("qclass_name", "C_INTERNET"),
        "uid": entry.get("uid"),
    }


def normalize_ssl_record(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes Zeek ssl.log entry."""
    src_ip = entry.get("id.orig_h") or entry.get("src_ip", "0.0.0.0")
    src_port = safe_int(entry.get("id.orig_p") or entry.get("src_port", 0))
    dst_ip = entry.get("id.resp_h") or entry.get("dst_ip", "0.0.0.0")
    dst_port = safe_int(entry.get("id.resp_p") or entry.get("dst_port", 443), default=443)
    return {
        "timestamp": parse_zeek_timestamp(entry.get("ts")),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "server_name": entry.get("server_name"),
        "ja3_hash": entry.get("ja3"),
        "ja3s_hash": entry.get("ja3s"),
        "ja4_hash": entry.get("ja4"),
        "version": entry.get("version"),
        "cipher": entry.get("cipher"),
        "uid": entry.get("uid"),
    }


class ZeekLogShipper:
    """
    Tails Zeek JSON logs, normalizes entries, correlates connection metadata,
    and publishes to Kafka topics with an in-memory queue fallback.
    """

    def __init__(
        self,
        log_dir: str = "/logs",
        kafka_bootstrap_servers: Optional[str] = None,
        event_queue: Optional[queue.Queue] = None,
    ):
        self.log_dir = log_dir
        self.event_queue = event_queue if event_queue is not None else queue.Queue()
        self.kafka_producer = None
        self.is_kafka_connected = False

        # Session correlation state (uid -> metadata)
        self._correlation_cache: Dict[str, Dict[str, Any]] = {}

        servers = kafka_bootstrap_servers or os.getenv("KAFKA_BOOTSTRAP_SERVERS")
        if servers:
            try:
                from kafka import KafkaProducer  # type: ignore
                self.kafka_producer = KafkaProducer(
                    bootstrap_servers=servers,
                    value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
                    request_timeout_ms=2000,
                )
                self.is_kafka_connected = True
                logger.info("ZeekLogShipper connected to Kafka at %s", servers)
            except Exception as exc:
                logger.warning("Kafka unavailable (%s). Operating in-memory shipper mode.", exc)
                self.kafka_producer = None
                self.is_kafka_connected = False

    def emit(self, topic: str, payload: Dict[str, Any]) -> None:
        """Publishes record to target Kafka topic or enqueues in-memory."""
        if self.is_kafka_connected and self.kafka_producer is not None:
            try:
                self.kafka_producer.send(topic, payload)
                return
            except Exception as exc:
                logger.error("Failed to publish to Kafka topic %s: %s", topic, exc)

        # Enqueue with topic metadata for consumption
        self.event_queue.put({"topic": topic, "data": payload})

    def process_log_line(self, log_type: str, line: str) -> Optional[Dict[str, Any]]:
        """
        Parses a single JSON line from Zeek, normalizes, and emits to the appropriate topic.
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return None

        uid = entry.get("uid")

        if log_type == "conn":
            normalized = normalize_conn_record(entry)
            # Enrich with correlated metadata (DNS / SSL) if captured earlier on this UID
            if uid and uid in self._correlation_cache:
                cached = self._correlation_cache.pop(uid)
                if cached.get("dns_query") and not normalized.get("dns_query"):
                    normalized["dns_query"] = cached["dns_query"]
                    normalized["dns_query_type"] = cached.get("dns_query_type", "A")
                if cached.get("ja3_hash") and not normalized.get("ja3_hash"):
                    normalized["ja3_hash"] = cached["ja3_hash"]

            self.emit(TOPIC_FLOWS, normalized)
            return normalized

        elif log_type == "dns":
            normalized = normalize_dns_record(entry)
            if uid:
                self._correlation_cache[uid] = {
                    "dns_query": normalized.get("dns_query"),
                    "dns_query_type": normalized.get("dns_query_type"),
                }
            self.emit(TOPIC_DNS, normalized)
            return normalized

        elif log_type == "ssl":
            normalized = normalize_ssl_record(entry)
            if uid:
                if uid not in self._correlation_cache:
                    self._correlation_cache[uid] = {}
                self._correlation_cache[uid]["ja3_hash"] = normalized.get("ja3_hash")
            self.emit(TOPIC_SSL, normalized)
            return normalized

        return None

    def process_log_file(self, log_type: str, file_path: str) -> List[Dict[str, Any]]:
        """Synchronously processes an entire Zeek log file (e.g., from a completed PCAP replay)."""
        if not os.path.exists(file_path):
            return []

        results = []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                record = self.process_log_line(log_type, line)
                if record:
                    results.append(record)
        return results

    async def tail_file_async(
        self,
        log_type: str,
        file_path: str,
        stop_event: Optional[asyncio.Event] = None,
        poll_interval: float = 0.2,
    ):
        """Asynchronously tails an active Zeek log file."""
        while not os.path.exists(file_path) and (not stop_event or not stop_event.is_set()):
            await asyncio.sleep(poll_interval)

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, os.SEEK_END)  # Start at end of file
            while not stop_event or not stop_event.is_set():
                line = f.readline()
                if line:
                    self.process_log_line(log_type, line)
                else:
                    await asyncio.sleep(poll_interval)
