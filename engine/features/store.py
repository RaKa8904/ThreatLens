"""
ThreatLens Sliding-Window Feature Store
======================================
Multi-tier sliding-window aggregation supporting real-time anomaly detection:
  - 10s Window: Volumetric packet/SYN bursts and fast fan-out sweeps.
  - 60s Window: DNS telemetry, domain entropy, and reconnaissance tracking.
  - 300s Window: Persistent C2 beaconing (inter-arrival arrays) and data exfiltration byte ratios.

Uses Redis Sorted Sets (ZADD, ZRANGEBYSCORE, ZREMRANGEBYSCORE) when available,
with automatic, transparent fallback to an in-memory double-ended queue (deque) store.
"""

from collections import deque
import json
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional
import uuid

from engine.features.metrics import (
    calculate_fan_out,
    calculate_flow_ratio,
    calculate_inter_arrival_variance,
    calculate_shannon_entropy,
)

logger = logging.getLogger(__name__)

# Standard Sliding Window Durations (seconds)
WINDOW_10S = 10
WINDOW_60S = 60
WINDOW_300S = 300
SUPPORTED_WINDOWS = (WINDOW_10S, WINDOW_60S, WINDOW_300S)


class SlidingWindowStore:
    """
    Sliding-window aggregation engine backed by Redis sorted sets with an in-memory fallback.
    """

    def __init__(
        self,
        redis_host: Optional[str] = None,
        redis_port: Optional[int] = None,
        redis_db: int = 0,
        redis_password: Optional[str] = None,
        use_redis: bool = True,
    ):
        self.use_redis = use_redis
        self.redis_client = None
        self.is_redis_connected = False
        self.fallback_active = not use_redis

        # In-memory storage: key -> deque of (timestamp, payload)
        self._memory_store: Dict[str, deque] = {}
        self._lock = threading.Lock()

        if self.use_redis:
            host = redis_host or os.getenv("REDIS_HOST", "localhost")
            port = int(redis_port or os.getenv("REDIS_PORT", 6379))
            password = redis_password or os.getenv("REDIS_PASSWORD") or None

            try:
                import redis
                client = redis.Redis(
                    host=host,
                    port=port,
                    db=redis_db,
                    password=password,
                    decode_responses=True,
                    socket_connect_timeout=1.0,
                    socket_timeout=1.0,
                )
                client.ping()
                self.redis_client = client
                self.is_redis_connected = True
                self.fallback_active = False
                logger.info("Connected to Redis at %s:%s (db=%d)", host, port, redis_db)
            except Exception as exc:
                logger.warning(
                    "Redis unavailable (%s). Falling back to in-memory SlidingWindowStore.",
                    exc,
                )
                self.redis_client = None
                self.is_redis_connected = False
                self.fallback_active = True

    def _make_key(self, window_sec: int, key: str) -> str:
        """Constructs a namespaced storage key."""
        return f"threatlens:win:{window_sec}:{key}"

    # =========================================================================
    # Core Generic Sliding-Window Methods
    # =========================================================================

    def add_event(
        self,
        window_sec: int,
        key: str,
        timestamp: float,
        payload: Any,
    ) -> None:
        """
        Appends a timestamped event into the sliding window and prunes expired entries.

        Args:
            window_sec: Window size in seconds (e.g., 10, 60, 300).
            key: Entity identifier (e.g. source IP or flow_id).
            timestamp: Epoch timestamp of the event in seconds.
            payload: Serializable data payload associated with the event.
        """
        namespaced_key = self._make_key(window_sec, key)
        cutoff = timestamp - window_sec

        if self.is_redis_connected and self.redis_client is not None:
            try:
                # Add unique suffix to payload so Redis sorted sets do not overwrite duplicate items
                unique_item = json.dumps({"_uid": uuid.uuid4().hex[:8], "payload": payload})
                self.redis_client.zadd(namespaced_key, {unique_item: timestamp})
                # Prune items older than window
                self.redis_client.zremrangebyscore(namespaced_key, "-inf", cutoff)
                # Set TTL to auto-expire idle keys
                self.redis_client.expire(namespaced_key, window_sec * 2)
                return
            except Exception as exc:
                logger.error("Redis zadd failed: %s. Reverting to in-memory.", exc)
                self.is_redis_connected = False
                self.fallback_active = True

        # In-memory implementation
        with self._lock:
            if namespaced_key not in self._memory_store:
                self._memory_store[namespaced_key] = deque()

            dq = self._memory_store[namespaced_key]
            dq.append((timestamp, payload))

            # Prune elements older than cutoff
            while dq and dq[0][0] < cutoff:
                dq.popleft()

    def get_events(
        self,
        window_sec: int,
        key: str,
        current_time: Optional[float] = None,
    ) -> List[Any]:
        """
        Retrieves all active event payloads within the current sliding window.

        Args:
            window_sec: Window size in seconds.
            key: Entity identifier.
            current_time: Reference timestamp (defaults to time.time()).

        Returns:
            List of event payloads within [current_time - window_sec, current_time].
        """
        now = current_time if current_time is not None else time.time()
        namespaced_key = self._make_key(window_sec, key)
        cutoff = now - window_sec

        if self.is_redis_connected and self.redis_client is not None:
            try:
                # Prune first
                self.redis_client.zremrangebyscore(namespaced_key, "-inf", cutoff)
                raw_items = self.redis_client.zrangebyscore(namespaced_key, cutoff, "+inf")
                results = []
                for item in raw_items:
                    try:
                        parsed = json.loads(item)
                        results.append(parsed.get("payload", parsed))
                    except Exception:
                        results.append(item)
                return results
            except Exception as exc:
                logger.error("Redis zrangebyscore failed: %s. Using in-memory.", exc)
                self.is_redis_connected = False

        # In-memory implementation
        with self._lock:
            if namespaced_key not in self._memory_store:
                return []

            dq = self._memory_store[namespaced_key]
            # Prune expired items
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            # Return payloads within the active window
            return [payload for ts, payload in dq if ts <= now]

    def prune_window(
        self,
        window_sec: int,
        key: str,
        current_time: Optional[float] = None,
    ) -> int:
        """
        Explicitly prunes expired events from the window.

        Returns:
            int: Number of expired records removed.
        """
        now = current_time if current_time is not None else time.time()
        namespaced_key = self._make_key(window_sec, key)
        cutoff = now - window_sec

        if self.is_redis_connected and self.redis_client is not None:
            try:
                removed = self.redis_client.zremrangebyscore(namespaced_key, "-inf", cutoff)
                return int(removed)
            except Exception as exc:
                logger.error("Redis prune failed: %s", exc)
                self.is_redis_connected = False

        with self._lock:
            if namespaced_key not in self._memory_store:
                return 0

            dq = self._memory_store[namespaced_key]
            initial_count = len(dq)
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            removed = initial_count - len(dq)
            if not dq:
                del self._memory_store[namespaced_key]
            return removed

    # =========================================================================
    # Tier 1: 10s Window (Volumetric Packet/SYN Bursts & Fan-Out Sweeps)
    # =========================================================================

    def record_10s_packet(
        self,
        src_ip: str,
        timestamp: float,
        dst_endpoint: str,
        is_syn: bool = False,
        byte_count: int = 0,
        target_key: Optional[str] = None,
    ) -> None:
        """
        Records packet metadata for 10-second volumetric DDoS & fan-out detection.
        """
        payload = {
            "timestamp": timestamp,
            "dst_endpoint": dst_endpoint,
            "is_syn": is_syn,
            "byte_count": byte_count,
            "source_ip": src_ip,
        }
        self.add_event(WINDOW_10S, src_ip, timestamp, payload)
        if target_key:
            self.add_event(WINDOW_10S, target_key, timestamp, payload)

    def get_10s_metrics(
        self,
        src_ip: str,
        current_time: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Computes 10s sliding-window aggregations:
          - packet_count, syn_count, total_bytes
          - fan_out_count (unique endpoints)
          - packets_per_sec (PPS)
        """
        events = self.get_events(WINDOW_10S, src_ip, current_time)
        packet_count = len(events)
        syn_count = sum(1 for e in events if e.get("is_syn"))
        total_bytes = sum(e.get("byte_count", 0) for e in events)
        destinations = [e.get("dst_endpoint") for e in events if e.get("dst_endpoint")]
        fan_out = calculate_fan_out(destinations)

        return {
            "window_sec": WINDOW_10S,
            "packet_count": packet_count,
            "syn_count": syn_count,
            "total_bytes": total_bytes,
            "fan_out_count": fan_out,
            "packets_per_sec": round(packet_count / float(WINDOW_10S), 2),
            "unique_source_count": len({e.get("source_ip") for e in events if e.get("source_ip")}),
        }

    # =========================================================================
    # Tier 2: 60s Window (DNS Telemetry, Domain Entropy & Recon Tracking)
    # =========================================================================

    def record_60s_dns(
        self,
        src_ip: str,
        timestamp: float,
        domain: str,
        query_type: str = "A",
        query_len: int = 0,
    ) -> None:
        """
        Records DNS queries for 60-second DGA and DNS tunneling detection.
        """
        payload = {
            "timestamp": timestamp,
            "domain": domain,
            "query_type": query_type,
            "query_len": query_len or len(domain),
        }
        self.add_event(WINDOW_60S, f"dns:{src_ip}", timestamp, payload)

    def record_60s_recon(
        self,
        src_ip: str,
        timestamp: float,
        dst_ip: str,
        dst_port: int,
    ) -> None:
        """
        Records destination probes for 60-second port scan reconnaissance tracking.
        """
        payload = {
            "timestamp": timestamp,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "target": f"{dst_ip}:{dst_port}",
        }
        self.add_event(WINDOW_60S, f"recon:{src_ip}", timestamp, payload)

    def get_60s_dns_metrics(
        self,
        src_ip: str,
        current_time: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Computes 60s DNS query metrics including domain Shannon entropy distributions.
        """
        events = self.get_events(WINDOW_60S, f"dns:{src_ip}", current_time)
        query_count = len(events)
        domains = [e.get("domain", "") for e in events if e.get("domain")]
        unique_domains = list(set(domains))

        entropies = [calculate_shannon_entropy(d) for d in unique_domains]
        avg_entropy = round(sum(entropies) / len(entropies), 4) if entropies else 0.0
        max_entropy = max(entropies) if entropies else 0.0
        high_entropy_domains = [
            d for d in unique_domains if calculate_shannon_entropy(d) >= 3.8
        ]

        return {
            "window_sec": WINDOW_60S,
            "query_count": query_count,
            "unique_domain_count": len(unique_domains),
            "avg_entropy": avg_entropy,
            "max_entropy": max_entropy,
            "high_entropy_domains": high_entropy_domains,
        }

    def get_60s_recon_metrics(
        self,
        src_ip: str,
        current_time: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Computes 60s port scan reconnaissance metrics:
          - unique destination IPs contacted
          - unique destination ports contacted
        """
        events = self.get_events(WINDOW_60S, f"recon:{src_ip}", current_time)
        unique_ips = set(e.get("dst_ip") for e in events if e.get("dst_ip"))
        unique_ports = set(e.get("dst_port") for e in events if e.get("dst_port"))

        return {
            "window_sec": WINDOW_60S,
            "probe_count": len(events),
            "unique_target_ips": len(unique_ips),
            "unique_target_ports": len(unique_ports),
            "fan_out_cardinality": len(events),
        }

    # =========================================================================
    # Tier 3: 300s Window (Persistent C2 Heartbeats & Data Exfiltration)
    # =========================================================================

    def record_300s_flow(
        self,
        flow_id: str,
        timestamp: float,
        bytes_out: int,
        bytes_in: int,
        ja3_hash: Optional[str] = None,
    ) -> None:
        """
        Records flow telemetry for 300-second long-range C2 beaconing and exfiltration detection.
        """
        payload = {
            "timestamp": timestamp,
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "ja3_hash": ja3_hash,
        }
        self.add_event(WINDOW_300S, flow_id, timestamp, payload)

    def get_300s_metrics(
        self,
        flow_id: str,
        current_time: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Computes 300s sliding-window aggregations:
          - connection_count & inter_arrival_variance (C2 beacon periodicity)
          - total_bytes_out, total_bytes_in & asymmetric flow_ratio (Data exfiltration)
          - ja3_hash list
        """
        events = self.get_events(WINDOW_300S, flow_id, current_time)
        connection_count = len(events)
        timestamps = [e.get("timestamp", 0.0) for e in events]
        total_bytes_out = sum(e.get("bytes_out", 0) for e in events)
        total_bytes_in = sum(e.get("bytes_in", 0) for e in events)

        iat_variance = calculate_inter_arrival_variance(timestamps)
        byte_ratio = calculate_flow_ratio(total_bytes_out, total_bytes_in)

        ja3_hashes = list({e.get("ja3_hash") for e in events if e.get("ja3_hash")})

        return {
            "window_sec": WINDOW_300S,
            "connection_count": connection_count,
            "timestamps": sorted(timestamps),
            "inter_arrival_variance": iat_variance,
            "total_bytes_out": total_bytes_out,
            "total_bytes_in": total_bytes_in,
            "byte_ratio": byte_ratio,
            "ja3_hashes": ja3_hashes,
        }
