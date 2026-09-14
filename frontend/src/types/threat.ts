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
  flow_id: string;
  source_ip?: string | null;
  source_port?: number | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  protocol?: string | null;
  threat_class: ThreatClassEnum | ThreatClass;
  confidence_score: number;
  status: AlertStatusEnum;
  incident_id?: string | null;
  suppressed: boolean;
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
  source_ip?: string | null;
  destination_ip?: string | null;
  threat_class?: ThreatClassEnum | null;
  created_at: string;
  expires_at?: string | null;
}

// Aliases for convenience in dashboard components
export type ThreatAlert = ThreatAlertSchema;
export type Evidence = EvidenceSchema;
