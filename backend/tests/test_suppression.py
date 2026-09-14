"""
ThreatLens Allowlist & Suppression Rule Test Suite
===================================================
Verifies:
  1. Creation, retrieval, and deletion of SuppressionRule contracts.
  2. CIDR subnet allowlisting (e.g. 192.168.1.0/24).
  3. Exact source and destination IP suppression.
  4. Combined IP and threat-class specific suppression rules.
  5. Automatic expiration handling (expires_at).
  6. Enabling/disabling rules through RuntimeConfigStore.
  7. Pipeline suppression tagging (suppressed=True) with detection still executing.
"""

from datetime import datetime, timedelta, timezone
import unittest
import uuid

from backend.app.schemas import SuppressionRule, ThreatClassEnum
from engine.features.store import SlidingWindowStore
from engine.models.aggregator import AlertAggregator
from engine.pipeline import DetectionPipeline
from engine.runtime_config import RuntimeConfigStore
from ingest.producers.mock_producer import SyntheticFlowGenerator


class TestAllowlistAndSuppressionRules(unittest.TestCase):
    """Test suite covering active allowlist filtering and suppression rule mechanics."""

    def setUp(self):
        self.store = SlidingWindowStore(use_redis=False)
        self.rules = RuntimeConfigStore(use_redis=False)
        self.pipeline = DetectionPipeline(
            store=self.store,
            aggregator=AlertAggregator(),
            suppression_provider=self.rules,
        )
        self.generator = SyntheticFlowGenerator(seed=42)

    def test_create_list_and_delete_suppression_rule(self):
        rule = SuppressionRule(
            id=str(uuid.uuid4()),
            rule_type="source_ip",
            source_ip="192.168.1.0/24",
            description="Corporate VPN Allowlist Subnet",
        )
        created = self.rules.create_suppression_rule(rule)
        self.assertEqual(created.id, rule.id)

        rules = self.rules.get_suppression_rules()
        self.assertTrue(any(r.id == rule.id for r in rules))

        deleted = self.rules.delete_suppression_rule(rule.id)
        self.assertTrue(deleted)
        self.assertFalse(any(r.id == rule.id for r in self.rules.get_suppression_rules()))

    def test_cidr_source_ip_allowlist_suppression(self):
        # Create CIDR rule for 192.168.1.0/24
        rule = SuppressionRule(
            id="rule-cidr-1",
            rule_type="source_ip",
            source_ip="192.168.1.0/24",
            description="Internal trusted scanner subnet",
        )
        self.rules.create_suppression_rule(rule)

        # Flow from 192.168.1.55 (inside subnet)
        flow_inside = self.generator.generate_volumetric_ddos(target_ip="10.0.0.1")
        flow_inside["src_ip"] = "192.168.1.55"

        alerts_inside = self.pipeline.process_flow_event(flow_inside)
        self.assertGreater(len(alerts_inside), 0)
        self.assertTrue(all(a.suppressed for a in alerts_inside))
        self.assertTrue(all(a.suppression_rule_id == "rule-cidr-1" for a in alerts_inside))

        # Flow from 203.0.113.88 (outside subnet)
        flow_outside = self.generator.generate_volumetric_ddos(target_ip="10.0.0.1")
        flow_outside["src_ip"] = "203.0.113.88"

        alerts_outside = self.pipeline.process_flow_event(flow_outside)
        self.assertGreater(len(alerts_outside), 0)
        self.assertFalse(any(a.suppressed for a in alerts_outside))

    def test_destination_ip_allowlist_suppression(self):
        rule = SuppressionRule(
            id="rule-dst-1",
            rule_type="destination_ip",
            destination_ip="10.0.0.99",
            description="Whitelisted honeypot destination",
        )
        self.rules.create_suppression_rule(rule)

        flow = self.generator.generate_volumetric_ddos(target_ip="10.0.0.99")
        alerts = self.pipeline.process_flow_event(flow)
        self.assertGreater(len(alerts), 0)
        self.assertTrue(all(a.suppressed for a in alerts))

    def test_source_ip_and_threat_class_combination_suppression(self):
        rule = SuppressionRule(
            id="rule-combo-1",
            rule_type="source_ip_threat_class",
            source_ip="192.168.1.75",
            threat_class=ThreatClassEnum.DGA_DNS,
            description="Authorized DNS security crawler",
        )
        self.rules.create_suppression_rule(rule)

        # Flow matching both source IP and threat class
        dga_flow = self.generator.generate_dga_dns_tunnel()
        dga_flow["src_ip"] = "192.168.1.75"

        alerts = self.pipeline.process_flow_event(dga_flow)
        dga_alerts = [a for a in alerts if a.threat_class == ThreatClassEnum.DGA_DNS]
        self.assertGreater(len(dga_alerts), 0)
        self.assertTrue(all(a.suppressed for a in dga_alerts))

    def test_expired_suppression_rule_is_ignored(self):
        expired_rule = SuppressionRule(
            id="rule-expired-1",
            rule_type="source_ip",
            source_ip="192.168.1.100",
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=60),
            description="Temporary past maintenance window",
        )
        self.rules.create_suppression_rule(expired_rule)

        flow = self.generator.generate_volumetric_ddos()
        flow["src_ip"] = "192.168.1.100"

        alerts = self.pipeline.process_flow_event(flow)
        self.assertGreater(len(alerts), 0)
        self.assertFalse(any(a.suppressed for a in alerts))

    def test_disabled_rule_can_be_re_enabled(self):
        rule = SuppressionRule(
            id="rule-toggle-1",
            rule_type="source_ip",
            source_ip="192.168.1.150",
            description="Backup server nightly job",
        )
        self.rules.create_suppression_rule(rule)

        flow = self.generator.generate_volumetric_ddos()
        flow["src_ip"] = "192.168.1.150"

        suppressed_alerts = self.pipeline.process_flow_event(flow)
        self.assertGreater(len(suppressed_alerts), 0)
        self.assertTrue(all(a.suppressed for a in suppressed_alerts))

        # Disable through the store: detection still runs, delivery resumes.
        updated = self.rules.update_suppression_rule(rule.id, enabled=False)
        self.assertIsNotNone(updated)
        self.assertFalse(updated.enabled)

        flow_again = self.generator.generate_volumetric_ddos()
        flow_again["src_ip"] = "192.168.1.150"

        alerts_after_disable = self.pipeline.process_flow_event(flow_again)
        self.assertGreater(len(alerts_after_disable), 0)
        self.assertFalse(any(a.suppressed for a in alerts_after_disable))

        # Re-enable: suppression applies again.
        re_enabled = self.rules.update_suppression_rule(rule.id, enabled=True)
        self.assertTrue(re_enabled.enabled)

        flow_third = self.generator.generate_volumetric_ddos()
        flow_third["src_ip"] = "192.168.1.150"

        alerts_after_enable = self.pipeline.process_flow_event(flow_third)
        self.assertGreater(len(alerts_after_enable), 0)
        self.assertTrue(all(a.suppressed for a in alerts_after_enable))

    def test_update_unknown_rule_returns_none(self):
        self.assertIsNone(self.rules.update_suppression_rule("missing-id", enabled=False))


if __name__ == "__main__":
    unittest.main()
