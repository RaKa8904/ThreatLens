"""
ThreatLens Feature Extraction & Sliding Window Unit Tests
=========================================================
Verifies:
  1. Shannon entropy calculations for domains and IP spreads.
  2. Safe asymmetric flow byte ratio calculations.
  3. Inter-arrival time (IAT) variance across periodic vs. random events.
  4. Fan-out cardinality tracking.
  5. SlidingWindowStore multi-tier window retention, aggregation, and expiration (10s, 60s, 300s).
  6. SyntheticFlowGenerator simulation across all 6 threat classes.
"""

import math
import unittest

from engine.features.metrics import (
    calculate_fan_out,
    calculate_flow_ratio,
    calculate_inter_arrival_variance,
    calculate_shannon_entropy,
)
from engine.features.store import (
    WINDOW_10S,
    WINDOW_60S,
    WINDOW_300S,
    SlidingWindowStore,
)
from ingest.producers.mock_producer import (
    MockEventProducer,
    SyntheticFlowGenerator,
)


class TestStatisticalMetrics(unittest.TestCase):
    """Test suite for mathematical and metric calculation routines."""

    def test_shannon_entropy_empty_and_single(self):
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        self.assertEqual(calculate_shannon_entropy([]), 0.0)
        self.assertEqual(calculate_shannon_entropy("a"), 0.0)
        self.assertEqual(calculate_shannon_entropy("aaaaaaa"), 0.0)
        self.assertEqual(calculate_shannon_entropy(["10.0.0.1"]), 0.0)

    def test_shannon_entropy_diverse_strings(self):
        # A uniform 4-character string should have entropy of log2(4) = 2.0 bits
        uniform_data = "abcd"
        self.assertAlmostEqual(calculate_shannon_entropy(uniform_data), 2.0, places=3)

        # High-entropy random DGA domain should have entropy > 3.5
        dga_domain = "oxvj190famzkqlwepry7.biz"
        entropy = calculate_shannon_entropy(dga_domain)
        self.assertGreater(entropy, 3.5)

        # Legitimate domain typically has lower entropy due to repeating vowels/consonants
        legit_domain = "google.com"
        self.assertLess(calculate_shannon_entropy(legit_domain), calculate_shannon_entropy(dga_domain))

    def test_shannon_entropy_ip_distribution(self):
        # Dispersed IP spread
        diverse_ips = [f"192.168.1.{i}" for i in range(16)]
        entropy = calculate_shannon_entropy(diverse_ips)
        self.assertAlmostEqual(entropy, 4.0, places=3)  # log2(16) = 4.0

    def test_flow_ratio_normal_and_asymmetric(self):
        # Balanced flow
        self.assertEqual(calculate_flow_ratio(1000, 1000), 1.0)
        # Ingress heavy
        self.assertEqual(calculate_flow_ratio(100, 1000), 0.1)
        # Asymmetric exfiltration (high egress)
        self.assertEqual(calculate_flow_ratio(10_000_000, 50_000), 200.0)
        # Zero ingress safe handling
        self.assertEqual(calculate_flow_ratio(500, 0), 500.0)
        self.assertEqual(calculate_flow_ratio(0, 0), 0.0)

    def test_flow_ratio_negative_guard(self):
        with self.assertRaises(ValueError):
            calculate_flow_ratio(-10, 100)
        with self.assertRaises(ValueError):
            calculate_flow_ratio(100, -10)

    def test_inter_arrival_variance_periodic_vs_random(self):
        # Periodic C2 beaconing (exactly every 15.0 seconds) -> variance should be 0.0
        periodic_timestamps = [100.0, 115.0, 130.0, 145.0, 160.0]
        variance = calculate_inter_arrival_variance(periodic_timestamps)
        self.assertAlmostEqual(variance, 0.0, places=5)

        # Periodic with tiny millisecond jitter -> variance should be ultra low (< 0.001)
        jittered_timestamps = [100.0, 115.001, 130.002, 144.999, 160.001]
        jitter_var = calculate_inter_arrival_variance(jittered_timestamps)
        self.assertLess(jitter_var, 0.001)

        # Irregular / bursty timestamps -> variance should be significantly higher
        irregular_timestamps = [100.0, 102.0, 125.0, 127.0, 190.0]
        irr_var = calculate_inter_arrival_variance(irregular_timestamps)
        self.assertGreater(irr_var, 10.0)

    def test_inter_arrival_variance_edge_cases(self):
        self.assertEqual(calculate_inter_arrival_variance([]), 0.0)
        self.assertEqual(calculate_inter_arrival_variance([100.0]), 0.0)
        self.assertEqual(calculate_inter_arrival_variance([100.0, 110.0]), 0.0)

    def test_fan_out_cardinality(self):
        self.assertEqual(calculate_fan_out([]), 0)
        self.assertEqual(calculate_fan_out(set()), 0)
        endpoints = ["10.0.0.1:80", "10.0.0.2:80", "10.0.0.1:80", "10.0.0.3:443"]
        self.assertEqual(calculate_fan_out(endpoints), 3)


class TestSlidingWindowStore(unittest.TestCase):
    """Test suite for multi-tier SlidingWindowStore in-memory and retention mechanics."""

    def setUp(self):
        # Force in-memory fallback for isolated unit testing
        self.store = SlidingWindowStore(use_redis=False)

    def test_window_retention_and_expiration(self):
        key = "192.168.1.50"
        t0 = 1000.0

        # Add 3 events in 10s window: t0, t0 + 4, t0 + 8
        self.store.add_event(WINDOW_10S, key, t0, {"pkt": 1})
        self.store.add_event(WINDOW_10S, key, t0 + 4, {"pkt": 2})
        self.store.add_event(WINDOW_10S, key, t0 + 8, {"pkt": 3})

        # At t0 + 8, all 3 events are within the 10s window (cutoff is 1008 - 10 = 998)
        events_at_8 = self.store.get_events(WINDOW_10S, key, current_time=t0 + 8)
        self.assertEqual(len(events_at_8), 3)

        # Advance time to t0 + 12 (cutoff is 1012 - 10 = 1002). Event 1 (t0 = 1000) expires!
        events_at_12 = self.store.get_events(WINDOW_10S, key, current_time=t0 + 12)
        self.assertEqual(len(events_at_12), 2)
        self.assertEqual([e["pkt"] for e in events_at_12], [2, 3])

        # Advance time to t0 + 25. All events should be pruned.
        events_at_25 = self.store.get_events(WINDOW_10S, key, current_time=t0 + 25)
        self.assertEqual(len(events_at_25), 0)

    def test_10s_volumetric_and_fanout_metrics(self):
        src_ip = "192.168.1.99"
        base_t = 2000.0

        # Simulate 5 SYN packets sent to 3 distinct destination endpoints in 10s
        self.store.record_10s_packet(src_ip, base_t + 1, "10.0.0.1:80", is_syn=True, byte_count=64)
        self.store.record_10s_packet(src_ip, base_t + 2, "10.0.0.1:80", is_syn=True, byte_count=64)
        self.store.record_10s_packet(src_ip, base_t + 3, "10.0.0.2:80", is_syn=True, byte_count=64)
        self.store.record_10s_packet(src_ip, base_t + 4, "10.0.0.3:443", is_syn=False, byte_count=1200)

        metrics = self.store.get_10s_metrics(src_ip, current_time=base_t + 5)
        self.assertEqual(metrics["packet_count"], 4)
        self.assertEqual(metrics["syn_count"], 3)
        self.assertEqual(metrics["fan_out_count"], 3)
        self.assertEqual(metrics["total_bytes"], 64 * 3 + 1200)

    def test_60s_dns_and_recon_metrics(self):
        src_ip = "192.168.1.12"
        base_t = 3000.0

        # Record normal domain and high-entropy DGA domain
        self.store.record_60s_dns(src_ip, base_t + 10, "google.com")
        self.store.record_60s_dns(src_ip, base_t + 20, "x9q8m20zlwkqp10z.biz")

        dns_metrics = self.store.get_60s_dns_metrics(src_ip, current_time=base_t + 30)
        self.assertEqual(dns_metrics["query_count"], 2)
        self.assertEqual(dns_metrics["unique_domain_count"], 2)
        self.assertGreater(dns_metrics["max_entropy"], 3.5)

        # Record reconnaissance port scan sweeps
        self.store.record_60s_recon(src_ip, base_t + 5, "10.0.0.5", 22)
        self.store.record_60s_recon(src_ip, base_t + 6, "10.0.0.5", 80)
        self.store.record_60s_recon(src_ip, base_t + 7, "10.0.0.5", 443)

        recon_metrics = self.store.get_60s_recon_metrics(src_ip, current_time=base_t + 30)
        self.assertEqual(recon_metrics["probe_count"], 3)
        self.assertEqual(recon_metrics["unique_target_ips"], 1)
        self.assertEqual(recon_metrics["unique_target_ports"], 3)

    def test_300s_c2_and_exfiltration_metrics(self):
        flow_id = "192.168.1.105:54321->198.51.100.44:8443"
        base_t = 5000.0

        # Simulate 4 periodic C2 heartbeats at exact 30-second intervals
        for step in [0, 30, 60, 90]:
            self.store.record_300s_flow(
                flow_id=flow_id,
                timestamp=base_t + step,
                bytes_out=128,
                bytes_in=64,
                ja3_hash="e7d705a3286e19ea42f587b344ee6865",
            )

        metrics = self.store.get_300s_metrics(flow_id, current_time=base_t + 100)
        self.assertEqual(metrics["connection_count"], 4)
        self.assertAlmostEqual(metrics["inter_arrival_variance"], 0.0, places=4)
        self.assertEqual(metrics["total_bytes_out"], 128 * 4)
        self.assertEqual(metrics["total_bytes_in"], 64 * 4)
        self.assertEqual(metrics["byte_ratio"], 2.0)
        self.assertIn("e7d705a3286e19ea42f587b344ee6865", metrics["ja3_hashes"])


class TestSyntheticFlowGenerator(unittest.TestCase):
    """Test suite verifying synthetic flow generator produces accurate anomaly signatures."""

    def setUp(self):
        self.generator = SyntheticFlowGenerator(seed=123)

    def test_benign_flow_structure(self):
        flow = self.generator.generate_benign_flow()
        self.assertEqual(flow["simulated_label"], "Benign")
        self.assertIn("->", flow["flow_id"])
        self.assertGreater(flow["bytes_in"], 0)
        self.assertGreater(flow["bytes_out"], 0)

    def test_volumetric_ddos_characteristics(self):
        flow = self.generator.generate_volumetric_ddos(target_ip="10.0.0.1", target_port=80)
        self.assertEqual(flow["simulated_label"], "Protocol DoS")
        self.assertEqual(flow["dst_ip"], "10.0.0.1")
        self.assertEqual(flow["dst_port"], 80)
        self.assertIn("SYN", flow["flags"])
        self.assertGreaterEqual(flow["packets_in"], 500)
        self.assertLess(flow["packets_out"], flow["packets_in"])

    def test_botnet_c2_beacon_characteristics(self):
        # Generate 4 consecutive beacons
        beacons = [self.generator.generate_botnet_c2() for _ in range(4)]
        timestamps = [b["timestamp"] for b in beacons]
        for b in beacons:
            self.assertEqual(b["simulated_label"], "Botnet C2 Beaconing")
            self.assertIsNotNone(b["ja3_hash"])

        # Variance across generated beacon deltas must be very small
        var = calculate_inter_arrival_variance(timestamps)
        self.assertLess(var, 0.01)

    def test_dga_dns_tunnel_characteristics(self):
        flow = self.generator.generate_dga_dns_tunnel()
        self.assertEqual(flow["simulated_label"], "DGA & DNS Tunneling")
        self.assertIsNotNone(flow["dns_query"])
        # Either DGA domain or TXT tunnel record
        self.assertTrue(flow["dns_query_type"] in ["A", "TXT"])

    def test_encrypted_malware_characteristics(self):
        flow = self.generator.generate_encrypted_malware()
        self.assertEqual(flow["simulated_label"], "Encrypted Malware")
        self.assertIsNotNone(flow["ja3_hash"])
        self.assertEqual(len(flow["ja3_hash"]), 32)
        self.assertIn("malware_family", flow)

    def test_recon_scan_characteristics(self):
        scanner_ip = "192.168.1.88"
        flow = self.generator.generate_recon_scan(scanner_ip=scanner_ip)
        self.assertEqual(flow["simulated_label"], "Reconnaissance Scan")
        self.assertEqual(flow["src_ip"], scanner_ip)
        self.assertIn("SYN", flow["flags"])

    def test_data_exfiltration_characteristics(self):
        flow = self.generator.generate_data_exfiltration()
        self.assertEqual(flow["simulated_label"], "Data Exfiltration")
        self.assertGreater(flow["bytes_out"], 1_000_000)
        ratio = calculate_flow_ratio(flow["bytes_out"], flow["bytes_in"])
        self.assertGreater(ratio, 50.0)

    def test_mock_event_producer_batch_generation(self):
        # Queue-mode harness: empty bootstrap string forces the in-memory
        # event queue regardless of whether a real broker is reachable.
        producer = MockEventProducer(kafka_bootstrap_servers="")
        batch = producer.produce_batch(count=30, anomaly_ratio=0.5)
        self.assertEqual(len(batch), 30)
        self.assertEqual(producer.event_queue.qsize(), 30)

        labels = {b["simulated_label"] for b in batch}
        self.assertIn("Benign", labels)
        self.assertTrue(any(label != "Benign" for label in labels))

        def test_anomaly_vectors_rotate_before_repeating(self):
            generator = SyntheticFlowGenerator(seed=123)
            labels = [generator.generate_event(anomaly_ratio=1.0)["simulated_label"] for _ in range(6)]
            self.assertEqual(len(set(labels)), 6)


if __name__ == "__main__":
    unittest.main()
