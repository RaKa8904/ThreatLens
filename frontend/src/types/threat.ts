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

export interface EvidenceSchema {
  inter_arrival_variance: number;
  shannon_entropy: number;
  byte_ratio: number;
  fan_out_count: number;
  ja3_hash?: string | null;
  details: string;
  packets_in?: number | null;
  packets_out?: number | null;
  inbound_connections?: number | null;
  outbound_connections?: number | null;
  port_connections?: number | null;
  inbound_bytes?: number | null;
  outbound_bytes?: number | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  destination_port?: number | null;
  protocol?: string | null;
  observation_window_seconds?: number | null;
}

export interface ThreatAlertSchema {
  timestamp: string; // ISO 8601 UTC timestamp string
  flow_id: string;
  threat_class: ThreatClassEnum | ThreatClass;
  confidence_score: number;
  evidence: EvidenceSchema;
}

// Aliases for convenience in dashboard components
export type ThreatAlert = ThreatAlertSchema;
export type Evidence = EvidenceSchema;
