export const THREAT_DISPLAY_NAMES: Record<string, string> = {
  "Volumetric & Protocol DDoS": "Volumetric DDoS",
  "Botnet C2 Beaconing": "Botnet C2",
  "DGA & DNS Tunneling": "DGA / DNS",
  "Encrypted Malware": "Encrypted Malware",
  "Reconnaissance Scan": "Recon Scan",
  "Data Exfiltration": "Data Exfil",
};

export function getShortThreatName(threatClass: string): string {
  return THREAT_DISPLAY_NAMES[threatClass] || threatClass;
}
