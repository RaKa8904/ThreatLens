"""
ThreatLens Synthetic Network Event Stream Generator
===================================================
Produces realistic network flow telemetry and controlled security anomalies
simulating all 6 ThreatLens threat classes:
  1. Volumetric & Protocol DDoS (SYN burst flood)
  2. Botnet C2 Beaconing (Strict periodic Δt heartbeats with near-zero variance)
  3. DGA & DNS Tunneling (High-entropy FQDNs, TXT queries >60 chars)
  4. Encrypted Malware (JA3 fingerprints matching known malicious profiles)
  5. Reconnaissance Scan (Rapid single-source IP fan-out across multiple ports)
  6. Data Exfiltration (Asymmetric high-volume outbound bytes from non-server IPs)

Supports streaming to:
  - In-memory thread-safe `queue.Queue` (for fast offline testing and verification)
  - Redpanda / Apache Kafka topic ('network-flows') via standard kafka client
"""

import argparse
import base64
import json
import logging
import os
import queue
import random
import string
import sys
import time
from typing import Any, Callable, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)

# Known Malicious JA3 Fingerprints
KNOWN_MALICIOUS_JA3 = {
    "TrickBot": "6734f37431670b3ab4292b8f60f29984",
    "Cobalt Strike": "a0e9f5d64349fb13191bc781f81f42e1",
    "Emotet": "4d7a28d6f22da2e8ee7038a0dd777ecd",
    "Metasploit Meterpreter": "b386946a5a44d1ddcc843bc75336df1a",
}

COMMON_BENIGN_DOMAINS = [
    "google.com",
    "github.com",
    "microsoft.com",
    "cloudflare.com",
    "aws.amazon.com",
    "apple.com",
    "wikipedia.org",
    "nic.in",
    "gov.in",
    "sbi.co.in",
    "airtel.in",
    "tcs.com",
    "infosys.com",
]

INDIA_PUBLIC_ENDPOINTS = [
    "8.8.8.8",
    "1.1.1.1",
    "142.250.190.46",
    "157.240.241.17",
    "104.16.132.229",
]


class SyntheticFlowGenerator:
    """
    Generates synthetic network flow records simulating benign enterprise
    traffic alongside the 6 specific ThreatLens anomaly profiles.
    """

    def __init__(self, seed: Optional[int] = 42):
        if seed is not None:
            random.seed(seed)
        self._beacon_state: Dict[str, float] = {}
        self._threat_bag: List[Callable[[], Dict[str, Any]]] = []
        self._distributed_ddos_queue: List[Dict[str, Any]] = []

    def _next_threat_generator(self) -> Callable[[], Dict[str, Any]]:
        """Return a randomized threat generator without repeating a vector until the bag is exhausted."""
        if not self._threat_bag:
            self._threat_bag = [
                self.generate_simulated_ddos,
                self.generate_botnet_c2,
                self.generate_dga_dns_tunnel,
                self.generate_encrypted_malware,
                self.generate_recon_scan,
                self.generate_data_exfiltration,
            ]
            random.shuffle(self._threat_bag)
        return self._threat_bag.pop()

    def _random_internal_ip(self) -> str:
        subnet = random.choice(["10.24", "10.42", "172.20", "192.168.40"])
        return f"{subnet}.{random.randint(1, 240)}.{random.randint(10, 240)}"

    def _random_external_ip(self) -> str:
        if random.random() < 0.55:
            return random.choice(INDIA_PUBLIC_ENDPOINTS)
        return f"{random.randint(11, 190)}.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"

    # -------------------------------------------------------------------------
    # Flow Generators by Class
    # -------------------------------------------------------------------------

    def generate_benign_flow(self, timestamp: Optional[float] = None) -> Dict[str, Any]:
        """Generates standard enterprise web, DNS, or API traffic."""
        ts = timestamp if timestamp is not None else time.time()
        src_ip = self._random_internal_ip()
        dst_ip = self._random_external_ip()
        dst_port = random.choices([53, 80, 443, 8080, 8443], weights=[25, 10, 45, 8, 12], k=1)[0]
        src_port = random.randint(30000, 65000)

        bytes_in = random.randint(500, 15000)
        bytes_out = random.randint(200, 4000)

        dns_query = None
        dns_type = None
        if dst_port == 53:
            dns_query = random.choice(COMMON_BENIGN_DOMAINS)
            dns_type = "A"

        return {
            "timestamp": ts,
            "flow_id": f"{src_ip}:{src_port}->{dst_ip}:{dst_port}",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": "UDP" if dst_port == 53 else "TCP",
            "flags": ["ACK", "PSH"] if dst_port != 53 else [],
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "packets_out": random.randint(2, 20),
            "packets_in": random.randint(3, 30),
            "dns_query": dns_query,
            "dns_query_type": dns_type,
            "ja3_hash": None,
            "simulated_label": "Benign",
        }

    def generate_volumetric_ddos(
        self,
        timestamp: Optional[float] = None,
        target_ip: str = "10.24.8.10",
        target_port: int = 80,
    ) -> Dict[str, Any]:
        """Simulates a single-source high-velocity DoS against a victim host."""
        ts = timestamp if timestamp is not None else time.time()
        src_ip = self._random_external_ip()
        src_port = random.randint(1024, 65535)

        return {
            "timestamp": ts,
            "flow_id": f"{src_ip}:{src_port}->{target_ip}:{target_port}",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": target_ip,
            "dst_port": target_port,
            "protocol": "TCP",
            "flags": ["SYN"],
            "bytes_out": random.randint(40, 64),
            "bytes_in": 0,
            "packets_out": random.randint(0, 4),
            "packets_in": random.randint(500, 2000),
            "dns_query": None,
            "dns_query_type": None,
            "ja3_hash": None,
            "simulated_label": "Protocol DoS",
            "attack_type": "single-source-dos",
        }

    def generate_simulated_ddos(self) -> Dict[str, Any]:
        """Start either a single-source DoS or a multi-source DDoS burst."""
        if random.random() < 0.5:
            burst = self.generate_distributed_ddos_batch(source_count=random.randint(4, 8))
            self._distributed_ddos_queue.extend(burst[1:])
            return burst[0]
        return self.generate_volumetric_ddos()

    def generate_distributed_ddos(
        self,
        timestamp: Optional[float] = None,
        target_ip: str = "10.24.8.10",
        target_port: int = 80,
        source_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Simulates one source in a distributed inbound SYN flood."""
        ts = timestamp if timestamp is not None else time.time()
        attacker_ip = source_ip or self._random_external_ip()
        src_port = random.randint(1024, 65535)
        return {
            "timestamp": ts,
            "flow_id": f"{attacker_ip}:{src_port}->{target_ip}:{target_port}",
            "src_ip": attacker_ip,
            "src_port": src_port,
            "dst_ip": target_ip,
            "dst_port": target_port,
            "protocol": "TCP",
            "flags": ["SYN"],
            "bytes_out": random.randint(40, 64),
            "bytes_in": 0,
            "packets_out": random.randint(0, 4),
            "packets_in": random.randint(500, 2000),
            "dns_query": None,
            "dns_query_type": None,
            "ja3_hash": None,
            "simulated_label": "Volumetric & Protocol DDoS",
            "attack_type": "distributed-ddos",
        }

    def generate_distributed_ddos_batch(
        self,
        source_count: int = 8,
        timestamp: Optional[float] = None,
        target_ip: str = "10.24.8.10",
        target_port: int = 80,
    ) -> List[Dict[str, Any]]:
        """Generates coordinated attack flows from multiple sources to one target."""
        base_timestamp = timestamp if timestamp is not None else time.time()
        sources = [f"203.0.113.{index + 1}" for index in range(max(2, source_count))]
        return [
            self.generate_distributed_ddos(
                timestamp=base_timestamp + index * 0.01,
                target_ip=target_ip,
                target_port=target_port,
                source_ip=source_ip,
            )
            for index, source_ip in enumerate(sources)
        ]

    def generate_botnet_c2(
        self,
        timestamp: Optional[float] = None,
        interval_sec: float = 15.0,
        c2_ip: str = "198.51.100.44",
        c2_port: int = 8443,
        bot_ip: str = "192.168.1.105",
    ) -> Dict[str, Any]:
        """Simulates periodic C2 heartbeats with ultra-low inter-arrival time variance."""
        last_ts = self._beacon_state.get(bot_ip, time.time() - interval_sec)
        jitter = random.gauss(0, 0.002)  # Millisecond-level jitter
        ts = timestamp if timestamp is not None else (last_ts + interval_sec + jitter)
        self._beacon_state[bot_ip] = ts

        src_port = 54321
        return {
            "timestamp": ts,
            "flow_id": f"{bot_ip}:{src_port}->{c2_ip}:{c2_port}",
            "src_ip": bot_ip,
            "src_port": src_port,
            "dst_ip": c2_ip,
            "dst_port": c2_port,
            "protocol": "TCP",
            "flags": ["ACK", "PSH"],
            "bytes_out": 128,
            "bytes_in": 64,
            "packets_out": 2,
            "packets_in": 2,
            "dns_query": None,
            "dns_query_type": None,
            "ja3_hash": "e7d705a3286e19ea42f587b344ee6865",
            "simulated_label": "Botnet C2 Beaconing",
        }

    def generate_dga_dns_tunnel(self, timestamp: Optional[float] = None) -> Dict[str, Any]:
        """Simulates DGA random domains or DNS TXT records with high-entropy payloads >60 chars."""
        ts = timestamp if timestamp is not None else time.time()
        src_ip = self._random_internal_ip()
        dst_ip = "8.8.8.8"

        # Generate either DGA query or long base64 DNS tunneling payload
        is_tunnel = random.choice([True, False])
        if is_tunnel:
            raw_payload = "".join(random.choices(string.ascii_letters + string.digits, k=64))
            b64_data = base64.b32encode(raw_payload.encode()).decode().lower()[:65]
            domain = f"{b64_data}.exfil-tun.net"
            query_type = "TXT"
        else:
            dga_str = "".join(random.choices(string.ascii_lowercase + string.digits, k=22))
            domain = f"{dga_str}.biz"
            query_type = "A"

        return {
            "timestamp": ts,
            "flow_id": f"{src_ip}:{random.randint(40000, 65000)}->{dst_ip}:53",
            "src_ip": src_ip,
            "src_port": random.randint(40000, 65000),
            "dst_ip": dst_ip,
            "dst_port": 53,
            "protocol": "UDP",
            "flags": [],
            "bytes_out": len(domain) + 40,
            "bytes_in": 120,
            "packets_out": 1,
            "packets_in": 1,
            "dns_query": domain,
            "dns_query_type": query_type,
            "ja3_hash": None,
            "simulated_label": "DGA & DNS Tunneling",
        }

    def generate_encrypted_malware(self, timestamp: Optional[float] = None) -> Dict[str, Any]:
        """Simulates malicious TLS session matching known threat actor JA3 fingerprint."""
        ts = timestamp if timestamp is not None else time.time()
        src_ip = self._random_internal_ip()
        dst_ip = self._random_external_ip()
        malware_family, ja3 = random.choice(list(KNOWN_MALICIOUS_JA3.items()))

        return {
            "timestamp": ts,
            "flow_id": f"{src_ip}:{random.randint(40000, 65000)}->{dst_ip}:443",
            "src_ip": src_ip,
            "src_port": random.randint(40000, 65000),
            "dst_ip": dst_ip,
            "dst_port": 443,
            "protocol": "TCP",
            "flags": ["ACK", "PSH"],
            "bytes_out": random.randint(1200, 4500),
            "bytes_in": random.randint(400, 1000),
            "packets_out": random.randint(8, 25),
            "packets_in": random.randint(6, 18),
            "dns_query": None,
            "dns_query_type": None,
            "ja3_hash": ja3,
            "ja4_hash": f"t13d{ja3[:12]}",
            "sni": dst_ip,
            "splt_packet_sizes": [64, 128, 512, 1024, 256],
            "splt_interarrival_times": [0.012, 0.031, 0.008, 0.044],
            "malware_family": malware_family,
            "simulated_label": "Encrypted Malware",
        }

    def generate_recon_scan(
        self,
        timestamp: Optional[float] = None,
        scanner_ip: str = "10.42.9.88",
        target_ip: Optional[str] = "10.24.12.20",
    ) -> Dict[str, Any]:
        """Simulates reconnaissance port scan with high fan-out across multiple destination ports."""
        ts = timestamp if timestamp is not None else time.time()
        dst_ip = target_ip or self._random_external_ip()
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080]
        dst_port = random.choice(scan_ports)

        return {
            "timestamp": ts,
            "flow_id": f"{scanner_ip}:{random.randint(50000, 65000)}->{dst_ip}:{dst_port}",
            "src_ip": scanner_ip,
            "src_port": random.randint(50000, 65000),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": "TCP",
            "flags": ["SYN"],
            "bytes_out": 44,
            "bytes_in": 0,
            "packets_out": 1,
            "packets_in": 0,
            "dns_query": None,
            "dns_query_type": None,
            "ja3_hash": None,
            "simulated_label": "Reconnaissance Scan",
        }

    def generate_data_exfiltration(
        self,
        timestamp: Optional[float] = None,
        compromised_ip: str = "10.24.22.150",
    ) -> Dict[str, Any]:
        """Simulates asymmetric large-scale data exfiltration outbound to untrusted destination."""
        ts = timestamp if timestamp is not None else time.time()
        dst_ip = self._random_external_ip()
        dst_port = random.choice([443, 8443, 22, 9001])
        bytes_out = random.randint(2_000_000, 25_000_000)
        bytes_in = random.randint(1_000, 20_000)

        return {
            "timestamp": ts,
            "flow_id": f"{compromised_ip}:{random.randint(40000, 60000)}->{dst_ip}:{dst_port}",
            "src_ip": compromised_ip,
            "src_port": random.randint(40000, 60000),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": "TCP",
            "flags": ["ACK", "PSH"],
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "packets_out": bytes_out // 1400,
            "packets_in": bytes_in // 500 or 1,
            "dns_query": None,
            "dns_query_type": None,
            "ja3_hash": None,
            "simulated_label": "Data Exfiltration",
        }

    def generate_event(self, anomaly_ratio: float = 0.3) -> Dict[str, Any]:
        """
        Generates a single flow event, choosing between benign traffic and anomalies.
        """
        if self._distributed_ddos_queue:
            event = self._distributed_ddos_queue.pop(0)
        elif random.random() > anomaly_ratio:
            return self.generate_benign_flow()
        else:
            chosen_generator = self._next_threat_generator()
            event = chosen_generator()

        # Keep demo confidence levels varied without changing real detector scores.
        severity_roll = random.random()
        if severity_roll < 0.15:
            confidence_range = (0.35, 0.49)
        elif severity_roll < 0.55:
            confidence_range = (0.50, 0.69)
        elif severity_roll < 0.88:
            confidence_range = (0.70, 0.84)
        else:
            confidence_range = (0.86, 0.98)
        event["simulated_confidence"] = round(random.uniform(*confidence_range), 2)
        return event


class MockEventProducer:
    """
    Producer orchestrator that pushes synthetic flows to either:
      - An in-memory queue.Queue (default, for offline testing)
      - A Redpanda/Kafka broker topic
    """

    def __init__(
        self,
        kafka_bootstrap_servers: Optional[str] = None,
        topic: str = "network-flows",
        event_queue: Optional[queue.Queue] = None,
    ):
        self.topic = topic
        self.event_queue = event_queue if event_queue is not None else queue.Queue()
        self.generator = SyntheticFlowGenerator()
        self.kafka_producer = None
        self.is_kafka_connected = False

        servers = kafka_bootstrap_servers or os.getenv("KAFKA_BOOTSTRAP_SERVERS")
        if servers:
            try:
                from kafka import KafkaProducer  # type: ignore
                self.kafka_producer = KafkaProducer(
                    bootstrap_servers=servers,
                    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                    request_timeout_ms=2000,
                )
                self.is_kafka_connected = True
                logger.info("Connected to Kafka at %s (topic=%s)", servers, topic)
            except Exception as exc:
                logger.warning("Kafka unavailable (%s). Using in-memory queue.", exc)
                self.kafka_producer = None
                self.is_kafka_connected = False

    def emit(self, event: Dict[str, Any]) -> None:
        """Publishes an event to Kafka or places it onto the internal queue."""
        if self.is_kafka_connected and self.kafka_producer is not None:
            try:
                self.kafka_producer.send(self.topic, event)
                return
            except Exception as exc:
                logger.error("Failed to send event to Kafka: %s. Pushing to queue.", exc)

        self.event_queue.put(event)

    def produce_batch(self, count: int, anomaly_ratio: float = 0.3) -> List[Dict[str, Any]]:
        """Generates and emits a batch of synthetic events."""
        batch = []
        for _ in range(count):
            event = self.generator.generate_event(anomaly_ratio=anomaly_ratio)
            self.emit(event)
            batch.append(event)
        return batch

    def run_continuous(
        self,
        rate_per_sec: float = 10.0,
        anomaly_ratio: float = 0.3,
        max_events: Optional[int] = None,
        on_event: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        """
        Runs continuous generation at a target rate until interrupted or max_events reached.
        """
        interval = 1.0 / max(rate_per_sec, 0.1)
        count = 0

        logger.info("Starting mock producer stream at %.1f events/sec...", rate_per_sec)
        try:
            while max_events is None or count < max_events:
                event = self.generator.generate_event(anomaly_ratio=anomaly_ratio)
                self.emit(event)
                if on_event:
                    on_event(event)
                count += 1
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Producer stopped by user after %d events.", count)


# =============================================================================
# CLI Entrypoint for Testing and Standalone Streaming
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="ThreatLens Synthetic Event Stream Producer")
    parser.add_argument("--count", type=int, default=20, help="Number of events to generate")
    parser.add_argument("--rate", type=float, default=5.0, help="Events per second (continuous mode)")
    parser.add_argument("--anomaly-ratio", type=float, default=0.4, help="Ratio of anomalous to benign flows")
    parser.add_argument("--kafka", type=str, default=None, help="Kafka bootstrap servers (e.g. localhost:9092)")
    parser.add_argument("--print-json", action="store_true", help="Print generated events to stdout")
    args = parser.parse_args()

    producer = MockEventProducer(kafka_bootstrap_servers=args.kafka)

    def print_event(evt):
        if args.print_json:
            print(json.dumps(evt))
        else:
            print(f"[{evt.get('simulated_label')}] {evt.get('flow_id')} | bytes_out: {evt.get('bytes_out')}")

    print(f"Generating {args.count} events (anomaly_ratio={args.anomaly_ratio})...")
    events = producer.produce_batch(args.count, anomaly_ratio=args.anomaly_ratio)
    for evt in events:
        print_event(evt)
    print(f"\nDone. Successfully generated {len(events)} events.")


if __name__ == "__main__":
    main()
