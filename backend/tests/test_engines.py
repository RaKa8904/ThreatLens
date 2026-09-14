"""
ThreatLens Specialized Threat Detection Engines Test Suite
==========================================================
Verifies:
  1. Volumetric DDoS engine dynamic 3-sigma and SYN flood detection.
  2. Botnet C2 beaconing engine FFT periodicity and IAT variance detection.
  3. DGA & DNS tunneling engine Shannon entropy and payload length detection.
  4. Encrypted malware engine JA3 cryptographic fingerprint and SPLT heuristic detection.
  5. Reconnaissance scan engine cardinality dispersion and port sweep detection.
  6. Data exfiltration engine outbound byte asymmetry ratio detection.
  7. Benign traffic filtering with zero false-positive alert generation.
  8. Pydantic v2 ThreatAlertSchema serialization and contract conformance.
"""

import asyncio
import time
import unittest

from backend.app.schemas import EvidenceSchema, ThreatAlertSchema, ThreatClassEnum
from engine.features.store import SlidingWindowStore
from engine.models.aggregator import AlertAggregator
from engine.models.beaconing_engine import BeaconingEngine
from engine.models.ddos_engine import DDoSEngine
from engine.models.dns_engine import DNSEngine
from engine.models.exfiltration_engine import ExfiltrationEngine
from engine.models.malware_engine import EncryptedMalwareEngine
from engine.models.recon_engine import ReconEngine
from engine.pipeline import DetectionPipeline
from ingest.producers.mock_producer import SyntheticFlowGenerator


class TestThreatDetectionEngines(unittest.TestCase):
    """Test suite covering each modular detection engine individually."""

    def setUp(self):
        self.store = SlidingWindowStore(use_redis=False)
        self.generator = SyntheticFlowGenerator(seed=42)

    def test_ddos_engine_detection(self):
        engine = DDoSEngine()
        flow = self.generator.generate_volumetric_ddos(target_ip="10.0.0.1", target_port=80)

        # Ingest into store
        self.store.record_10s_packet(
            src_ip=flow["src_ip"],
            timestamp=flow["timestamp"],
            dst_endpoint=f"{flow['dst_ip']}:{flow['dst_port']}",
            is_syn=True,
            byte_count=flow["bytes_out"],
        )

        candidate = engine.evaluate(flow, self.store)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.threat_class, ThreatClassEnum.VOLUMETRIC_DOS)
        self.assertGreaterEqual(candidate.confidence_score, 0.75)
        self.assertIn("SYN Flood / DoS", candidate.details)
        self.assertGreater(flow["packets_in"], flow["packets_out"])

    def test_distributed_ddos_detection_uses_multiple_sources(self):
        engine = DDoSEngine()
        flows = self.generator.generate_distributed_ddos_batch(source_count=5, timestamp=2000.0)

        for flow in flows:
            self.store.record_10s_packet(
                src_ip=flow["src_ip"],
                timestamp=flow["timestamp"],
                dst_endpoint=f"{flow['dst_ip']}:{flow['dst_port']}",
                is_syn=True,
                byte_count=flow["bytes_out"],
                target_key=f"target:{flow['dst_ip']}:{flow['dst_port']}",
            )

        candidate = engine.evaluate(flows[-1], self.store)
        self.assertIsNotNone(candidate)
        self.assertIn("Distributed SYN Flood", candidate.details)
        self.assertIn("5 source(s)", candidate.details)

    def test_live_simulated_ddos_scenario_emits_distributed_burst(self):
        generator = SyntheticFlowGenerator(seed=7)
        first = generator.generate_simulated_ddos()
        self.assertEqual(first["attack_type"], "distributed-ddos")

        burst = [first]
        burst.extend(generator.generate_event(anomaly_ratio=0.0) for _ in range(4))
        self.assertEqual({flow["src_ip"] for flow in burst}, {
            "203.0.113.1",
            "203.0.113.2",
            "203.0.113.3",
            "203.0.113.4",
            "203.0.113.5",
        })

    def test_outbound_heavy_flow_is_not_ddos(self):
        engine = DDoSEngine()
        flow = self.generator.generate_volumetric_ddos()
        flow["packets_in"] = 1
        flow["packets_out"] = 2000
        flow["flags"] = ["ACK", "PSH"]
        self.assertIsNone(engine.evaluate(flow, self.store))

    def test_beaconing_engine_detection(self):
        engine = BeaconingEngine()
        c2_flow_id = "192.168.1.105:54321->198.51.100.44:8443"
        base_t = 1000.0

        # Simulate 4 consecutive periodic beacons at 15.0s intervals
        beacons = []
        for i in range(4):
            b = self.generator.generate_botnet_c2(timestamp=base_t + (i * 15.0))
            self.store.record_300s_flow(
                flow_id=c2_flow_id,
                timestamp=b["timestamp"],
                bytes_out=b["bytes_out"],
                bytes_in=b["bytes_in"],
                ja3_hash=b["ja3_hash"],
            )
            beacons.append(b)

        candidate = engine.evaluate(beacons[-1], self.store)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.threat_class, ThreatClassEnum.BOTNET_C2)
        self.assertLessEqual(candidate.inter_arrival_variance, 0.05)
        self.assertGreaterEqual(candidate.confidence_score, 0.80)
        self.assertIn("Periodic C2 beaconing detected", candidate.details)

    def test_dns_engine_detection(self):
        engine = DNSEngine()
        flow = self.generator.generate_dga_dns_tunnel()

        candidate = engine.evaluate(flow, self.store)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.threat_class, ThreatClassEnum.DGA_DNS)
        self.assertGreaterEqual(candidate.confidence_score, 0.75)
        self.assertTrue(candidate.shannon_entropy >= 3.80 or len(flow["dns_query"]) >= 60)

    def test_malware_engine_detection(self):
        engine = EncryptedMalwareEngine()
        flow = self.generator.generate_encrypted_malware()

        candidate = engine.evaluate(flow, self.store)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.threat_class, ThreatClassEnum.ENCRYPTED_MALWARE)
        self.assertGreaterEqual(candidate.confidence_score, 0.90)
        self.assertIsNotNone(candidate.ja3_hash)
        self.assertIn("fingerprint matched", candidate.details)

    def test_recon_engine_detection(self):
        engine = ReconEngine()
        scanner_ip = "192.168.1.88"
        base_t = 2000.0

        # Simulate scanning 5 distinct ports
        probes = []
        for port in [21, 22, 80, 443, 8080]:
            p = self.generator.generate_recon_scan(
                timestamp=base_t,
                scanner_ip=scanner_ip,
                target_ip="10.0.0.99",
            )
            p["dst_port"] = port
            self.store.record_60s_recon(scanner_ip, base_t, "10.0.0.99", port)
            self.store.record_10s_packet(scanner_ip, base_t, f"10.0.0.99:{port}", is_syn=True, byte_count=44)
            probes.append(p)

        candidate = engine.evaluate(probes[-1], self.store)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.threat_class, ThreatClassEnum.RECON_SCAN)
        self.assertGreaterEqual(candidate.fan_out_count, 3)
        self.assertIn("Reconnaissance", candidate.details)

    def test_exfiltration_engine_detection(self):
        engine = ExfiltrationEngine()
        flow = self.generator.generate_data_exfiltration()

        self.store.record_300s_flow(
            flow_id=flow["flow_id"],
            timestamp=flow["timestamp"],
            bytes_out=flow["bytes_out"],
            bytes_in=flow["bytes_in"],
        )

        candidate = engine.evaluate(flow, self.store)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.threat_class, ThreatClassEnum.DATA_EXFIL)
        self.assertGreaterEqual(candidate.byte_ratio, 20.0)
        self.assertGreaterEqual(candidate.confidence_score, 0.80)
        self.assertIn("Data exfiltration", candidate.details)


class TestPipelineAndAggregator(unittest.TestCase):
    """Integration test suite covering AlertAggregator and DetectionPipeline."""

    def setUp(self):
        self.store = SlidingWindowStore(use_redis=False)
        self.aggregator = AlertAggregator()
        self.pipeline = DetectionPipeline(store=self.store, aggregator=self.aggregator)
        self.generator = SyntheticFlowGenerator(seed=101)

    def test_benign_traffic_no_false_positives(self):
        # Feed 25 benign flows through the pipeline
        for _ in range(25):
            flow = self.generator.generate_benign_flow()
            alerts = self.pipeline.process_flow_event(flow)
            self.assertEqual(
                len(alerts),
                0,
                f"False positive alert triggered on benign flow: {alerts}",
            )

    def test_pipeline_all_threat_classes_produce_valid_schemas(self):
        # 1. Volumetric DDoS
        ddos = self.generator.generate_volumetric_ddos()
        alerts = self.pipeline.process_flow_event(ddos)
        self.assertTrue(len(alerts) >= 1)
        self.assertEqual(alerts[0].threat_class, ThreatClassEnum.VOLUMETRIC_DOS)

        # 2. Botnet C2 Beaconing (requires multiple pulses)
        b_alerts = []
        base_t = time.time()
        for step in [0, 15, 30, 45]:
            beacon = self.generator.generate_botnet_c2(timestamp=base_t + step)
            b_alerts = self.pipeline.process_flow_event(beacon)
        self.assertTrue(any(a.threat_class == ThreatClassEnum.BOTNET_C2 for a in b_alerts))

        # 3. DGA & DNS Tunneling
        dga = self.generator.generate_dga_dns_tunnel()
        dga_alerts = self.pipeline.process_flow_event(dga)
        self.assertTrue(any(a.threat_class == ThreatClassEnum.DGA_DNS for a in dga_alerts))

        # 4. Encrypted Malware
        malware = self.generator.generate_encrypted_malware()
        mal_alerts = self.pipeline.process_flow_event(malware)
        self.assertTrue(any(a.threat_class == ThreatClassEnum.ENCRYPTED_MALWARE for a in mal_alerts))

        # 5. Reconnaissance Scan
        scanner_ip = "192.168.1.77"
        recon_alerts = []
        for p in [22, 80, 443, 8080]:
            probe = self.generator.generate_recon_scan(scanner_ip=scanner_ip)
            probe["dst_port"] = p
            recon_alerts = self.pipeline.process_flow_event(probe)
        self.assertTrue(any(a.threat_class == ThreatClassEnum.RECON_SCAN for a in recon_alerts))

        # 6. Data Exfiltration
        exfil = self.generator.generate_data_exfiltration()
        exfil_alerts = self.pipeline.process_flow_event(exfil)
        self.assertTrue(any(a.threat_class == ThreatClassEnum.DATA_EXFIL for a in exfil_alerts))

    def test_pydantic_schema_strict_conformance(self):
        flow = self.generator.generate_volumetric_ddos()
        alerts = self.pipeline.process_flow_event(flow)
        self.assertGreaterEqual(len(alerts), 1)

        alert = alerts[0]
        self.assertIsInstance(alert, ThreatAlertSchema)
        self.assertIsInstance(alert.evidence, EvidenceSchema)
        self.assertGreaterEqual(alert.confidence_score, 0.0)
        self.assertLessEqual(alert.confidence_score, 1.0)

        # Confirm JSON serialization operates without errors
        json_data = alert.model_dump_json()
        self.assertIn("Volumetric & Protocol DDoS", json_data)
        self.assertIn("confidence_score", json_data)

    def test_async_process_flow_event(self):
        flow = self.generator.generate_volumetric_ddos()
        alerts = asyncio.run(self.pipeline.async_process_flow_event(flow))
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].threat_class, ThreatClassEnum.VOLUMETRIC_DOS)

    def test_ema_baseline_adaptation_in_ddos_engine(self):
        engine = DDoSEngine(baseline_pps_mean=50.0, baseline_pps_std=10.0)
        initial_mean = engine.baseline_mean
        engine._update_ema_baseline(120.0)
        self.assertGreater(engine.baseline_mean, initial_mean)

    def test_autocorrelation_in_beaconing_engine(self):
        engine = BeaconingEngine()
        deltas = [15.0, 15.0, 15.0, 15.0]
        mean, conc, autocorr = engine._compute_fft_periodicity(deltas)
        self.assertGreaterEqual(autocorr, 0.70)
        self.assertGreaterEqual(conc, 0.85)

    def test_trigram_and_consonant_ratio_in_dns_engine(self):
        engine = DNSEngine()
        flow = {
            "dns_query": "bcdfghjklmnpqrstvwxyz.exfil-tunnel.com",
            "dns_query_type": "TXT",
            "bytes_out": 500,
            "bytes_in": 100,
            "dst_port": 53,
        }
        candidate = engine.evaluate(flow, self.store)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.threat_class, ThreatClassEnum.DGA_DNS)
        self.assertGreaterEqual(candidate.confidence_score, 0.80)

    def test_ja4_fingerprint_matching_in_malware_engine(self):
        engine = EncryptedMalwareEngine()
        flow = {
            "ja4_hash": "t13d151600_8daaf6152771_000000000000",
            "bytes_out": 2000,
            "bytes_in": 5000,
            "dst_port": 443,
        }
        candidate = engine.evaluate(flow, self.store)
        self.assertIsNotNone(candidate)
        self.assertEqual(candidate.threat_class, ThreatClassEnum.ENCRYPTED_MALWARE)
        self.assertIn("Cobalt Strike", candidate.details)

    def test_attack_chain_correlation_bonus(self):
        src_ip = "192.168.1.188"
        # 1. Recon flow
        recon = self.generator.generate_recon_scan(scanner_ip=src_ip)
        self.pipeline.process_flow_event(recon)

        # 2. C2 flow
        c2 = self.generator.generate_botnet_c2()
        c2["src_ip"] = src_ip
        c2_alerts = self.pipeline.process_flow_event(c2)

        # 3. Exfil flow
        exfil = self.generator.generate_data_exfiltration()
        exfil["src_ip"] = src_ip
        exfil_alerts = self.pipeline.process_flow_event(exfil)

        self.assertTrue(any("Attack Chain" in a.evidence.details for a in exfil_alerts))


if __name__ == "__main__":
    unittest.main()
