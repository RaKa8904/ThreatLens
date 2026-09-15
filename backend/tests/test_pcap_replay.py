"""
ThreatLens PCAP Replay & Zeek Ingestion Test Suite
==================================================
Milestone 6 / Phase 1 & Phase 5 Validation:
  1. Parsing and normalization of Zeek JSON logs (conn.log, dns.log, ssl.log).
  2. TCP history flag decoding and session UID cross-protocol correlation.
  3. Log shipper queue/Kafka publication and consumer batch pipeline routing.
  4. End-to-end PCAP replay detection across all 6 specialized detection engines:
     - Volumetric & Protocol DDoS (SYN flood)
     - Botnet C2 Beaconing (periodic heartbeats)
     - DGA & DNS Tunneling (high-entropy FQDNs)
     - Encrypted Malware (malicious JA3 fingerprints)
     - Reconnaissance Scan (port/IP sweeping)
     - Data Exfiltration (asymmetric outbound payload)
  5. File-based batch replay simulation from temporary disk artifacts.
"""

import json
import os
import queue
import tempfile
import time
import unittest
from typing import List

from backend.app.schemas import ThreatAlertSchema, ThreatClassEnum
from backend.app.storage import ClickHouseAlertStore
from engine.features.store import SlidingWindowStore
from engine.kafka_consumer import KafkaIngestConsumer
from engine.models.aggregator import AlertAggregator
from engine.pipeline import DetectionPipeline
from ingest.producers.zeek_kafka_shipper import (
    TOPIC_DNS,
    TOPIC_FLOWS,
    TOPIC_SSL,
    ZeekLogShipper,
    normalize_conn_record,
    normalize_dns_record,
    normalize_ssl_record,
    parse_zeek_history_flags,
    parse_zeek_timestamp,
    safe_int,
)


class TestZeekLogNormalization(unittest.TestCase):
    """Verifies parsing and standardization of structured Zeek JSON records."""

    def test_parse_zeek_timestamp(self):
        # Float epoch
        self.assertAlmostEqual(parse_zeek_timestamp(1694567890.123), 1694567890.123, places=2)
        # String float
        self.assertAlmostEqual(parse_zeek_timestamp("1694567890.123"), 1694567890.123, places=2)
        # ISO format
        parsed_iso = parse_zeek_timestamp("2026-09-12T18:30:00Z")
        self.assertGreater(parsed_iso, 1700000000.0)

    def test_parse_zeek_history_flags(self):
        self.assertEqual(parse_zeek_history_flags("S"), ["SYN"])
        self.assertEqual(parse_zeek_history_flags("ShAD"), ["SYN", "ACK", "PSH"])
        self.assertEqual(parse_zeek_history_flags("ShADF"), ["SYN", "ACK", "PSH", "FIN"])
        self.assertEqual(parse_zeek_history_flags("R"), ["RST"])
        self.assertEqual(parse_zeek_history_flags(""), [])
        self.assertEqual(parse_zeek_history_flags(None), [])

    def test_safe_int_handling(self):
        self.assertEqual(safe_int(123), 123)
        self.assertEqual(safe_int("456"), 456)
        self.assertEqual(safe_int("-"), 0)
        self.assertEqual(safe_int(None, default=80), 80)
        self.assertEqual(safe_int("invalid", default=53), 53)

    def test_normalize_conn_record(self):
        raw_conn = {
            "ts": 1726180000.5,
            "uid": "CHzpOq15jNS4uqZ9sh",
            "id.orig_h": "192.168.1.50",
            "id.orig_p": 49152,
            "id.resp_h": "10.0.0.1",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 4.5,
            "orig_bytes": 1250,
            "resp_bytes": 8420,
            "conn_state": "SF",
            "history": "ShADF",
            "orig_pkts": 10,
            "resp_pkts": 15,
        }

        norm = normalize_conn_record(raw_conn)
        self.assertEqual(norm["src_ip"], "192.168.1.50")
        self.assertEqual(norm["src_port"], 49152)
        self.assertEqual(norm["dst_ip"], "10.0.0.1")
        self.assertEqual(norm["dst_port"], 443)
        self.assertEqual(norm["flow_id"], "192.168.1.50:49152->10.0.0.1:443")
        self.assertEqual(norm["protocol"], "TCP")
        self.assertEqual(norm["bytes_out"], 1250)
        self.assertEqual(norm["bytes_in"], 8420)
        self.assertEqual(norm["packets_out"], 10)
        self.assertEqual(norm["packets_in"], 15)
        self.assertIn("SYN", norm["flags"])
        self.assertIn("ACK", norm["flags"])

    def test_normalize_one_way_syn_flood_as_inbound_target_traffic(self):
        raw_conn = {
            "ts": 1726180000.5,
            "id.orig_h": "203.0.113.88",
            "id.orig_p": 30000,
            "id.resp_h": "192.168.1.1",
            "id.resp_p": 80,
            "proto": "tcp",
            "orig_bytes": 14000,
            "resp_bytes": 0,
            "orig_pkts": 350,
            "resp_pkts": 0,
            "history": "S",
        }
        norm = normalize_conn_record(raw_conn)
        self.assertEqual(norm["packets_in"], 350)
        self.assertEqual(norm["packets_out"], 0)
        self.assertEqual(norm["bytes_in"], 14000)
        self.assertEqual(norm["bytes_out"], 0)

    def test_normalize_dns_record(self):
        raw_dns = {
            "ts": 1726180001.0,
            "uid": "Cdns12345678",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 53535,
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "query": "malicious-c2.security-research.org",
            "qtype_name": "A",
            "answers": ["198.51.100.22"],
        }

        norm = normalize_dns_record(raw_dns)
        self.assertEqual(norm["src_ip"], "192.168.1.100")
        self.assertEqual(norm["dst_ip"], "8.8.8.8")
        self.assertEqual(norm["dst_port"], 53)
        self.assertEqual(norm["dns_query"], "malicious-c2.security-research.org")
        self.assertEqual(norm["dns_query_type"], "A")

    def test_normalize_ssl_record(self):
        raw_ssl = {
            "ts": 1726180002.0,
            "uid": "Cssl98765432",
            "id.orig_h": "192.168.1.200",
            "id.orig_p": 50123,
            "id.resp_h": "203.0.113.15",
            "id.resp_p": 443,
            "server_name": "api.cloud-command.cc",
            "ja3": "72a589da586844d7f0818ce684948eea",
            "ja3s": "ec74a5c5110605f9f8eac84b7252e1fb",
            "version": "TLSv12",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        }

        norm = normalize_ssl_record(raw_ssl)
        self.assertEqual(norm["src_ip"], "192.168.1.200")
        self.assertEqual(norm["dst_ip"], "203.0.113.15")
        self.assertEqual(norm["server_name"], "api.cloud-command.cc")
        self.assertEqual(norm["ja3_hash"], "72a589da586844d7f0818ce684948eea")


class TestZeekLogShipperAndConsumer(unittest.TestCase):
    """Verifies end-to-end coordination between Log Shipper and Kafka Ingest Consumer."""

    def setUp(self):
        self.shared_queue = queue.Queue()
        # Queue-mode harness: empty bootstrap string forces the in-memory
        # event queue regardless of whether a real broker is reachable.
        self.shipper = ZeekLogShipper(event_queue=self.shared_queue, kafka_bootstrap_servers="")
        self.store = SlidingWindowStore(use_redis=False)
        self.storage = ClickHouseAlertStore(auto_connect=False)
        self.pipeline = DetectionPipeline(store=self.store, aggregator=AlertAggregator())
        self.consumer = KafkaIngestConsumer(
            pipeline=self.pipeline,
            storage=self.storage,
            event_queue=self.shared_queue,
            kafka_bootstrap_servers="",
        )

    def test_uid_cross_protocol_correlation(self):
        """Verifies ssl.log JA3 metadata is correlated with conn.log flow using shared session UID."""
        uid = "Ccorrelate123"

        ssl_line = json.dumps({
            "ts": 1726180010.0,
            "uid": uid,
            "id.orig_h": "192.168.1.15",
            "id.resp_h": "198.51.100.99",
            "server_name": "c2.stealth-ops.net",
            "ja3": "a0e9f5d64349fb13191bc781f81f42e1",
        })
        self.shipper.process_log_line("ssl", ssl_line)

        conn_line = json.dumps({
            "ts": 1726180010.5,
            "uid": uid,
            "id.orig_h": "192.168.1.15",
            "id.orig_p": 44112,
            "id.resp_h": "198.51.100.99",
            "id.resp_p": 443,
            "proto": "tcp",
            "orig_bytes": 500,
            "resp_bytes": 1200,
            "history": "ShAD",
        })
        conn_norm = self.shipper.process_log_line("conn", conn_line)

        self.assertIsNotNone(conn_norm)
        self.assertEqual(conn_norm["ja3_hash"], "a0e9f5d64349fb13191bc781f81f42e1")

    def test_shipper_queue_to_consumer_batch(self):
        """Verifies that records placed by shipper into queue are consumed and passed to pipeline."""
        line = json.dumps({
            "ts": time.time(),
            "uid": "Cbenign01",
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 50000,
            "id.resp_h": "142.250.190.46",
            "id.resp_p": 443,
            "proto": "tcp",
            "orig_bytes": 800,
            "resp_bytes": 4500,
            "history": "ShADF",
        })
        self.shipper.process_log_line("conn", line)

        self.assertEqual(self.shared_queue.qsize(), 1)
        alerts = self.consumer.consume_batch_from_queue(max_records=10)
        self.assertEqual(self.shared_queue.qsize(), 0)
        # Benign traffic produces zero false positive alerts
        self.assertEqual(len(alerts), 0)


class TestPCAPReplayAttacks(unittest.TestCase):
    """
    Simulates replay of PCAP network attack captures converted into Zeek JSON logs,
    validating automated detection across all 6 specialized detection engines.
    """

    def setUp(self):
        self.shared_queue = queue.Queue()
        # Queue-mode harness: empty bootstrap string forces the in-memory
        # event queue regardless of whether a real broker is reachable.
        self.shipper = ZeekLogShipper(event_queue=self.shared_queue, kafka_bootstrap_servers="")
        self.store = SlidingWindowStore(use_redis=False)
        self.storage = ClickHouseAlertStore(auto_connect=False)
        self.pipeline = DetectionPipeline(store=self.store, aggregator=AlertAggregator())
        self.consumer = KafkaIngestConsumer(
            pipeline=self.pipeline,
            storage=self.storage,
            event_queue=self.shared_queue,
            kafka_bootstrap_servers="",
        )

    def test_ddos_syn_flood_replay_detection(self):
        """Simulates PCAP replay of a TCP SYN flood against port 80."""
        target_ip = "192.168.1.1"
        base_time = time.time()
        attacker_ip = "203.0.113.88"

        all_alerts: List[ThreatAlertSchema] = []
        # Replay SYN flood connection records with high packet density
        for i in range(10):
            conn_entry = {
                "ts": base_time + (i * 0.1),
                "uid": f"Cddos_{i}",
                "id.orig_h": attacker_ip,
                "id.orig_p": 30000 + i,
                "id.resp_h": target_ip,
                "id.resp_p": 80,
                "proto": "tcp",
                "orig_bytes": 14000,
                "resp_bytes": 0,
                "orig_pkts": 350,
                "resp_pkts": 0,
                "history": "S",
            }
            self.shipper.process_log_line("conn", json.dumps(conn_entry))
            alerts = self.consumer.consume_batch_from_queue(max_records=1)
            all_alerts.extend(alerts)

        ddos_alerts = [a for a in all_alerts if a.threat_class == ThreatClassEnum.VOLUMETRIC_DOS]
        self.assertGreater(len(ddos_alerts), 0)
        self.assertGreaterEqual(ddos_alerts[-1].confidence_score, 0.75)
        self.assertIn("SYN", ddos_alerts[-1].evidence.details)

    def test_botnet_c2_periodic_beaconing_replay_detection(self):
        """Simulates PCAP replay of periodic C2 beaconing heartbeats over 300s window."""
        c2_ip = "198.51.100.77"
        bot_ip = "192.168.1.150"
        base_time = 1000.0

        all_alerts: List[ThreatAlertSchema] = []
        # Replay 5 periodic beacons spaced exactly 15.0s apart
        for i in range(5):
            conn_entry = {
                "ts": base_time + (i * 15.0),
                "uid": f"Cbeacon_{i}",
                "id.orig_h": bot_ip,
                "id.orig_p": 49500,
                "id.resp_h": c2_ip,
                "id.resp_p": 8443,
                "proto": "tcp",
                "orig_bytes": 128,
                "resp_bytes": 256,
                "orig_pkts": 4,
                "resp_pkts": 3,
                "history": "ShADF",
            }
            self.shipper.process_log_line("conn", json.dumps(conn_entry))
            alerts = self.consumer.consume_batch_from_queue(max_records=1)
            all_alerts.extend(alerts)

        c2_alerts = [a for a in all_alerts if a.threat_class == ThreatClassEnum.BOTNET_C2]
        self.assertGreater(len(c2_alerts), 0)
        self.assertGreaterEqual(c2_alerts[-1].confidence_score, 0.80)
        self.assertLessEqual(c2_alerts[-1].evidence.inter_arrival_variance, 0.05)

    def test_dga_dns_tunneling_replay_detection(self):
        """Simulates PCAP replay of high-entropy DGA / DNS tunneling query."""
        dga_query = "v8xq9p2m1k0z4w7y9l3n6c5b2r8t.tunnel-exfil.biz"
        dns_entry = {
            "ts": time.time(),
            "uid": "Cdga99",
            "id.orig_h": "192.168.1.75",
            "id.orig_p": 54321,
            "id.resp_h": "8.8.4.4",
            "id.resp_p": 53,
            "proto": "udp",
            "query": dga_query,
            "qtype_name": "TXT",
            "answers": ["secret_token_exfiltrated"],
        }

        self.shipper.process_log_line("dns", json.dumps(dns_entry))
        alerts = self.consumer.consume_batch_from_queue(max_records=10)

        dns_alerts = [a for a in alerts if a.threat_class == ThreatClassEnum.DGA_DNS]
        self.assertGreater(len(dns_alerts), 0)
        self.assertGreaterEqual(dns_alerts[0].confidence_score, 0.75)
        self.assertGreaterEqual(dns_alerts[0].evidence.shannon_entropy, 3.8)

    def test_encrypted_malware_tls_replay_detection(self):
        """Simulates PCAP replay of malware session matching known TrickBot JA3 hash."""
        uid = "Cmalware44"
        trickbot_ja3 = "6734f37431670b3ab4292b8f60f29984"

        # 1. SSL log containing the malicious client handshake
        ssl_entry = {
            "ts": time.time(),
            "uid": uid,
            "id.orig_h": "192.168.1.111",
            "id.orig_p": 51234,
            "id.resp_h": "198.51.100.44",
            "id.resp_p": 443,
            "server_name": "dropzone-update.cc",
            "ja3": trickbot_ja3,
            "version": "TLSv12",
        }
        self.shipper.process_log_line("ssl", json.dumps(ssl_entry))

        # 2. Connection record for the flow
        conn_entry = {
            "ts": time.time(),
            "uid": uid,
            "id.orig_h": "192.168.1.111",
            "id.orig_p": 51234,
            "id.resp_h": "198.51.100.44",
            "id.resp_p": 443,
            "proto": "tcp",
            "orig_bytes": 1024,
            "resp_bytes": 4096,
            "history": "ShADF",
        }
        self.shipper.process_log_line("conn", json.dumps(conn_entry))

        alerts = self.consumer.consume_batch_from_queue(max_records=10)
        malware_alerts = [a for a in alerts if a.threat_class == ThreatClassEnum.ENCRYPTED_MALWARE]
        self.assertGreater(len(malware_alerts), 0)
        self.assertGreaterEqual(malware_alerts[0].confidence_score, 0.90)
        self.assertEqual(malware_alerts[0].evidence.ja3_hash, trickbot_ja3)

    def test_recon_port_sweep_replay_detection(self):
        """Simulates PCAP replay of an internal reconnaissance port sweep."""
        scanner_ip = "192.168.1.99"
        victim_ip = "192.168.1.200"
        base_time = time.time()

        all_alerts: List[ThreatAlertSchema] = []
        # Replay SYN sweep to 45 unique destination ports
        for port in range(1000, 1045):
            conn_entry = {
                "ts": base_time + ((port - 1000) * 0.05),
                "uid": f"Crecon_{port}",
                "id.orig_h": scanner_ip,
                "id.orig_p": 45000,
                "id.resp_h": victim_ip,
                "id.resp_p": port,
                "proto": "tcp",
                "orig_bytes": 40,
                "resp_bytes": 0,
                "history": "S",
            }
            self.shipper.process_log_line("conn", json.dumps(conn_entry))
            alerts = self.consumer.consume_batch_from_queue(max_records=1)
            all_alerts.extend(alerts)

        recon_alerts = [a for a in all_alerts if a.threat_class == ThreatClassEnum.RECON_SCAN]
        self.assertGreater(len(recon_alerts), 0)
        self.assertGreaterEqual(recon_alerts[-1].confidence_score, 0.80)
        self.assertGreaterEqual(recon_alerts[-1].evidence.fan_out_count, 3)

    def test_data_exfiltration_replay_detection(self):
        """Simulates PCAP replay of an asymmetric outbound data exfiltration flow."""
        exfil_conn = {
            "ts": time.time(),
            "uid": "Cexfil01",
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 48123,
            "id.resp_h": "203.0.113.50",
            "id.resp_p": 8080,
            "proto": "tcp",
            "orig_bytes": 45000000,  # 45 MB sent
            "resp_bytes": 1200,      # 1.2 KB received (ratio > 30,000)
            "orig_pkts": 31000,
            "resp_pkts": 20,
            "history": "ShADF",
        }

        self.shipper.process_log_line("conn", json.dumps(exfil_conn))
        alerts = self.consumer.consume_batch_from_queue(max_records=10)

        exfil_alerts = [a for a in alerts if a.threat_class == ThreatClassEnum.DATA_EXFIL]
        self.assertGreater(len(exfil_alerts), 0)
        self.assertGreaterEqual(exfil_alerts[0].confidence_score, 0.85)
        self.assertGreater(exfil_alerts[0].evidence.byte_ratio, 100.0)


class TestFileReplayExecution(unittest.TestCase):
    """Verifies file-based replay batch processing using ZeekLogShipper.process_log_file."""

    def setUp(self):
        self.shared_queue = queue.Queue()
        # Queue-mode harness: empty bootstrap string forces the in-memory
        # event queue regardless of whether a real broker is reachable.
        self.shipper = ZeekLogShipper(event_queue=self.shared_queue, kafka_bootstrap_servers="")
        self.store = SlidingWindowStore(use_redis=False)
        self.storage = ClickHouseAlertStore(auto_connect=False)
        self.pipeline = DetectionPipeline(store=self.store, aggregator=AlertAggregator())
        self.consumer = KafkaIngestConsumer(
            pipeline=self.pipeline,
            storage=self.storage,
            event_queue=self.shared_queue,
            kafka_bootstrap_servers="",
        )

    def test_batch_file_replay(self):
        """Generates synthetic Zeek log files on disk and validates full batch replay ingestion."""
        with tempfile.TemporaryDirectory() as tmpdir:
            conn_path = os.path.join(tmpdir, "conn.log")
            dns_path = os.path.join(tmpdir, "dns.log")

            # Write DNS records
            with open(dns_path, "w", encoding="utf-8") as f:
                f.write("#separator \\x09\n")
                f.write(json.dumps({
                    "ts": time.time(),
                    "uid": "Cdns_f1",
                    "id.orig_h": "10.0.0.5",
                    "id.resp_h": "8.8.8.8",
                    "query": "kjh8712398ynad812739812y3.exfil.org",
                    "qtype_name": "TXT",
                }) + "\n")

            # Write Conn records
            with open(conn_path, "w", encoding="utf-8") as f:
                f.write("#separator \\x09\n")
                f.write(json.dumps({
                    "ts": time.time(),
                    "uid": "Cconn_f1",
                    "id.orig_h": "10.0.0.5",
                    "id.orig_p": 55123,
                    "id.resp_h": "198.51.100.12",
                    "id.resp_p": 9000,
                    "proto": "tcp",
                    "orig_bytes": 25000000,
                    "resp_bytes": 1000,
                    "history": "ShADF",
                }) + "\n")

            dns_records = self.shipper.process_log_file("dns", dns_path)
            conn_records = self.shipper.process_log_file("conn", conn_path)

            self.assertEqual(len(dns_records), 1)
            self.assertEqual(len(conn_records), 1)
            self.assertEqual(self.shared_queue.qsize(), 2)

            # Drain consumer
            alerts = self.consumer.consume_batch_from_queue(max_records=10)
            self.assertGreater(len(alerts), 0)

            # Verify persisted in storage
            persisted = self.storage.get_recent_alerts(limit=10)
            self.assertGreaterEqual(len(persisted), 1)


if __name__ == "__main__":
    unittest.main()
