/**
 * ThreatLens Core Data Contracts & Types
 * =====================================
 * Standardized TypeScript definitions aligned with backend Pydantic v2 schemas.
 */

export enum ThreatClassEnum {
  VOLUMETRIC_DOS = "Volumetric & Protocol DDoS",
  BOTNET_C2 = "Botnet C2 Beaconing",
  DGA_DNS = "DGA & DNS Tunneling",
  ENCRYPTED_MALWARE = "Encrypted Malware",
  RECON_SCAN = "Reconnaissance Scan",
  DATA_EXFIL = "Data Exfiltration",
}

export type ThreatClass = `${ThreatClassEnum}`;

export function normalizeThreatClass(raw: any): string {
  if (!raw) return "";
  if (typeof raw === "string") return raw;
  if (typeof raw === "object" && raw !== null) {
    if (typeof raw.value === "string") return raw.value;
    if (typeof raw.name === "string") return raw.name;
    if (typeof raw.threat_class === "string") return raw.threat_class;
  }
  return String(raw);
}

export function matchesThreatClass(alertClassRaw: any, selectedClass: string): boolean {
  if (!selectedClass || selectedClass === "ALL") return true;
  const alertStr = normalizeThreatClass(alertClassRaw).toLowerCase().trim();
  const targetStr = normalizeThreatClass(selectedClass).toLowerCase().trim();
  if (alertStr === targetStr) return true;

  const aliases: Record<string, string[]> = {
    "volumetric & protocol ddos": ["volumetric & protocol ddos", "volumetric_dos", "protocol dos", "syn flood", "ddos", "dos"],
    "botnet c2 beaconing": ["botnet c2 beaconing", "botnet_c2", "c2 beaconing", "botnet c2", "beaconing"],
    "dga & dns tunneling": ["dga & dns tunneling", "dga_dns", "dns tunneling", "dga"],
    "encrypted malware": ["encrypted malware", "encrypted_malware", "malware"],
    "reconnaissance scan": ["reconnaissance scan", "recon_scan", "recon sweep", "port scan", "subnet sweep", "reconnaissance"],
    "data exfiltration": ["data exfiltration", "data_exfil", "exfiltration", "exfil"],
  };

  const targetAliases = aliases[targetStr] || [targetStr];
  return targetAliases.some((alias) => alertStr.includes(alias) || alias.includes(alertStr));
}

/**
 * Analyst triage priority assigned by the backend's centralized severity
 * calibration. Severity is distinct from confidence_score and must never be
 * re-derived in the UI.
 */
export type SeverityLevel = "critical" | "high" | "moderate" | "low";

export enum AlertStatusEnum {
  NEW = "new",
  ACKNOWLEDGED = "acknowledged",
  INVESTIGATING = "investigating",
  RESOLVED = "resolved",
  FALSE_POSITIVE = "false_positive",
}

export interface EvidenceSchema {
  inter_arrival_variance: number;
  shannon_entropy: number;
  byte_ratio: number;
  fan_out_count: number;
  ja3_hash?: string | null;
  ja4_hash?: string | null;
  sni?: string | null;
  splt_packet_sizes?: number[] | null;
  splt_interarrival_times?: number[] | null;
  fft_concentration?: number | null;
  beacon_period_seconds?: number | null;
  inter_arrival_stddev?: number | null;
  dns_query?: string | null;
  dns_query_length?: number | null;
  dns_query_type?: string | null;
  ngram_score?: number | null;
  packets_per_second?: number | null;
  z_score?: number | null;
  source_ip_entropy?: number | null;
  unique_destination_hosts?: number | null;
  unique_destination_ports?: number | null;
  window_10s_fan_out?: number | null;
  window_60s_fan_out?: number | null;
  unique_source_count?: number | null;
  total_uploaded_bytes?: number | null;
  detectors_fired?: string[];
  detector_count?: number;
  confidence_basis?: string | null;
  details: string;
  packets_in?: number | null;
  packets_out?: number | null;
  inbound_connections?: number | null;
  outbound_connections?: number | null;
  port_connections?: number | null;
  inbound_bytes?: number | null;
  outbound_bytes?: number | null;
  source_ip?: string | null;
  source_port?: number | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  protocol?: string | null;
  observation_window_seconds?: number | null;
}

export interface ThreatAlertSchema {
  timestamp: string; // ISO 8601 UTC timestamp string
  alert_id?: string | null; // server-generated canonical identity; legacy rows may lack it
  flow_id: string;
  source_ip?: string | null;
  source_port?: number | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  protocol?: string | null;
  threat_class: ThreatClassEnum | ThreatClass;
  confidence_score: number;
  severity: SeverityLevel;
  status: AlertStatusEnum;
  incident_id?: string | null;
  suppressed: boolean;
  suppression_rule_id?: string | null;
  source: "live" | "replay";
  ingest_latency_ms?: number | null;
  processing_latency_ms?: number | null;
  evidence: EvidenceSchema;
}

export interface AnalystNote {
  flow_id: string;
  text: string;
  created_at: string;
}

export interface SuppressionRule {
  id: string;
  rule_type: "source_ip" | "destination_ip" | "source_ip_threat_class";
  description?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  threat_class?: ThreatClassEnum | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  expires_at?: string | null;
}

export interface SuppressionRuleCreate {
  rule_type: SuppressionRule["rule_type"];
  description?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  threat_class?: ThreatClassEnum | null;
  enabled?: boolean;
  expires_at?: string | null;
}

/** One analyst-configurable detector threshold, with its valid range and consumer. */
export interface ThresholdEntry {
  rule: string;
  rule_label: string;
  parameter: string;
  label: string;
  description: string;
  kind: "int" | "float" | "int_list";
  min: number | null;
  max: number | null;
  value: number | number[];
  default: number | number[];
  modified: boolean;
  consumed_by: string;
  active: boolean;
}

export interface ThresholdConfigResponse {
  /** "memory" means changes apply at runtime but are lost on restart. */
  storage_mode: "redis" | "memory";
  persistent: boolean;
  thresholds: ThresholdEntry[];
}

// Aliases for convenience in dashboard components
export type ThreatAlert = ThreatAlertSchema;
export type Evidence = EvidenceSchema;

/**
 * Canonical identity of one logical alert. Prefer the server-generated
 * alert_id; fall back to flow_id + timestamp + threat_class for legacy rows
 * persisted before alert_id existed. flow_id alone is never sufficient:
 * multiple detectors legitimately emit distinct alerts for the same flow,
 * and the synthetic generator reuses flow_ids across events.
 */
export function getAlertIdentity(alert: ThreatAlertSchema): string {
  return alert.alert_id ?? `${alert.flow_id}|${alert.timestamp}|${alert.threat_class}`;
}
