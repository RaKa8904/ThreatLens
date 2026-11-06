import { type ReactNode, useEffect, useState } from "react";
import { motion } from "motion/react";
import { FingerPrintIcon as Fingerprint, Alert02Icon as Alert02 } from "hugeicons-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet, SheetClose, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { AnalystNote, SeverityLevel, ThreatAlertSchema, ThreatClassEnum, matchesThreatClass } from "@/types/threat";
import { formatTimestamp } from "@/lib/utils";

interface ForensicDrawerProps {
  alert: ThreatAlertSchema | null;
  onClose: () => void;
}

type MetricTone = "cyan" | "emerald" | "amber" | "rose" | "purple";

type EvidenceVisibility = {
  ddos?: boolean;
  beaconing?: boolean;
  dns?: boolean;
  malware?: boolean;
  reconnaissance?: boolean;
  exfiltration?: boolean;
};

function getEvidenceVisibility(rawThreatClass: string): EvidenceVisibility {
  if (matchesThreatClass(rawThreatClass, ThreatClassEnum.VOLUMETRIC_DOS)) return { ddos: true };
  if (matchesThreatClass(rawThreatClass, ThreatClassEnum.BOTNET_C2)) return { beaconing: true };
  if (matchesThreatClass(rawThreatClass, ThreatClassEnum.DGA_DNS)) return { dns: true };
  if (matchesThreatClass(rawThreatClass, ThreatClassEnum.ENCRYPTED_MALWARE)) return { malware: true };
  if (matchesThreatClass(rawThreatClass, ThreatClassEnum.RECON_SCAN)) return { reconnaissance: true };
  if (matchesThreatClass(rawThreatClass, ThreatClassEnum.DATA_EXFIL)) return { exfiltration: true };
  return {};
}

const toneClasses: Record<MetricTone, string> = {
  cyan: "text-sky-300",
  emerald: "text-emerald-400",
  amber: "text-amber-400",
  rose: "text-rose-400",
  purple: "text-purple-300",
};

function MetricTile({
  label,
  value,
  unit,
  tone = "cyan",
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  tone?: MetricTone;
}) {
  const isUnobserved =
    value === null ||
    value === undefined ||
    value === "UNAVAILABLE" ||
    value === "NOT CAPTURED" ||
    value === "";

  return (
    <div className="rounded border border-[var(--hairline)] bg-[var(--bg-surface)] p-2.5 transition-colors">
      <div className="text-[length:var(--text-label)] uppercase font-mono text-[var(--text-secondary)]">
        {label}
      </div>
      <div
        className={`mt-1 text-[length:var(--text-body)] font-mono ${
          isUnobserved
            ? "text-[var(--text-muted)] italic font-normal text-xs"
            : `font-semibold ${toneClasses[tone]}`
        }`}
      >
        {isUnobserved ? "— Not observed" : value}
        {!isUnobserved && unit && (
          <span className="ml-1 text-[10px] text-[var(--text-secondary)] font-normal">
            {unit}
          </span>
        )}
      </div>
    </div>
  );
}

function formatBytes(bytes: number | null | undefined) {
  if (bytes === null || bytes === undefined) return null;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(2)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes} B`;
}

function getLatencyState(value: number | null | undefined) {
  if (value === null || value === undefined) {
    return { label: "UNAVAILABLE", className: "text-[var(--text-muted)] border-[var(--hairline)]" };
  }
  if (value <= 10) {
    return { label: "WITHIN NORMAL", className: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10" };
  }
  if (value <= 100) {
    return { label: "ELEVATED", className: "text-amber-400 border-amber-500/30 bg-amber-500/10" };
  }
  return { label: "DEGRADED", className: "text-rose-400 border-rose-500/30 bg-rose-500/10" };
}

export function ForensicDrawer({ alert, onClose }: ForensicDrawerProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [notes, setNotes] = useState<AnalystNote[]>([]);
  const [noteText, setNoteText] = useState("");
  const [notesLoading, setNotesLoading] = useState(false);

  useEffect(() => {
    if (!alert) return;
    setNotesLoading(true);
    fetch(`/api/alerts/${encodeURIComponent(alert.flow_id)}/notes`)
      .then((response) => (response.ok ? response.json() : Promise.reject(new Error("notes request failed"))))
      .then((data: AnalystNote[]) => setNotes(data))
      .catch(() => setNotes([]))
      .finally(() => setNotesLoading(false));
  }, [alert?.flow_id]);

  if (!alert) return null;

  const { evidence } = alert;
  const threatClass = String(alert.threat_class);
  const visibility = getEvidenceVisibility(threatClass);
  const directionalRatio =
    evidence.inbound_bytes !== null &&
    evidence.inbound_bytes !== undefined &&
    evidence.outbound_bytes !== null &&
    evidence.outbound_bytes !== undefined
      ? `1:${(evidence.outbound_bytes / Math.max(evidence.inbound_bytes, 1)).toFixed(1)}`
      : null;

  const handleCopy = (key: string, text: string) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => {
      setCopiedKey((curr) => (curr === key ? null : curr));
    }, 1200);
  };

  const renderCopyButton = (key: string, text: string | undefined | null, title?: string) => {
    if (!text) return null;
    const isCopied = copiedKey === key;
    return (
      <button
        type="button"
        onClick={() => handleCopy(key, text)}
        title={title || `Copy ${text}`}
        className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-mono border border-[var(--hairline)] hover:border-zinc-500 bg-[var(--bg-surface)] hover:bg-[var(--bg-surface-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-all select-none"
      >
        {isCopied ? <span className="text-emerald-400 font-bold">COPIED</span> : "COPY"}
      </button>
    );
  };

  const getSeverityBadge = (severity: SeverityLevel, score: number) => {
    const label = `${severity.toUpperCase()} (${Math.round(score * 100)}%)`;
    const badgeVariant: Record<SeverityLevel, "critical" | "high" | "medium" | "low"> = {
      critical: "critical",
      high: "high",
      moderate: "medium",
      low: "low",
    };
    return <Badge variant={badgeVariant[severity]}>{label}</Badge>;
  };

  const processingState = getLatencyState(alert.processing_latency_ms);
  const ingestState = getLatencyState(alert.ingest_latency_ms);
  const detectorCount = evidence.detector_count ?? (evidence.detectors_fired?.length ?? 1);
  const detectorsFired = evidence.detectors_fired?.length ? evidence.detectors_fired : [threatClass];

  const submitNote = async () => {
    const text = noteText.trim();
    if (!text) return;
    const response = await fetch(`/api/alerts/${encodeURIComponent(alert.flow_id)}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!response.ok) return;
    const note = (await response.json()) as AnalystNote;
    setNotes((current) => [...current, note]);
    setNoteText("");
  };

  const sourceIp = alert.source_ip ?? evidence.source_ip;
  const destIp = alert.destination_ip ?? evidence.destination_ip;

  return (
    <Sheet open={Boolean(alert)} onOpenChange={(open) => !open && onClose()}>
      <SheetContent
        side="right"
        className="w-full border-l border-[var(--hairline)] bg-[var(--bg-base)] text-[var(--text-primary)] p-5 font-sans sm:w-[60vw] sm:max-w-[60vw] sm:p-6 lg:w-[60vw] lg:max-w-[60vw] lg:p-8 overflow-y-auto"
      >
        <SheetClose />
        <SheetHeader className="border-b border-[var(--hairline)] pb-4">
          <div className="flex items-center space-x-2">
            <Alert02 className="h-4 w-4 text-sky-400" />
            <SheetTitle className="text-[length:var(--text-heading)] font-bold uppercase tracking-wider text-[var(--text-primary)] font-mono">
              Forensic Evidence Dossier
            </SheetTitle>
          </div>
          <div className="flex items-center gap-2 mt-1">
            <SheetDescription className="text-[length:var(--text-label)] font-mono text-[var(--text-secondary)]">
              INCIDENT ID: {alert.flow_id}
            </SheetDescription>
            {renderCopyButton("flow-id", alert.flow_id, "Copy Incident ID")}
          </div>
        </SheetHeader>

        <motion.div
          className="space-y-5 pt-5 text-xs"
          initial="hidden"
          animate="visible"
          variants={{ visible: { transition: { staggerChildren: 0.05 } } }}
        >
          {/* Top Classification & Identifiers Grid */}
          <motion.div
            variants={{ hidden: { opacity: 0, x: 20 }, visible: { opacity: 1, x: 0 } }}
            className="grid gap-4 lg:grid-cols-[3fr_2fr]"
          >
            {/* Classified Threat Info */}
            <div className="rounded-lg border border-[var(--hairline)] bg-[var(--bg-surface)] p-4 space-y-3 lg:p-5">
              <div className="flex items-center justify-between">
                <span className="text-[var(--text-secondary)] text-[length:var(--text-label)] font-mono uppercase">
                  Classified Threat
                </span>
                <div className="flex items-center gap-2">
                  <span className="text-[length:var(--text-label)] font-mono text-[var(--text-muted)]">
                    ({detectorCount} of 6 detectors triggered)
                  </span>
                  {getSeverityBadge(alert.severity, alert.confidence_score)}
                </div>
              </div>
              <div className="text-[length:var(--text-display)] leading-tight font-bold text-[var(--text-primary)] font-mono tracking-tight">
                {threatClass}
              </div>
              <div className="text-[11px] text-[var(--text-secondary)] bg-[var(--bg-base)] p-3 rounded border border-[var(--hairline)] font-mono leading-relaxed">
                {evidence.details || "— Not observed"}
              </div>
            </div>

            {/* Flow Identifiers */}
            <div className="rounded-lg border border-[var(--hairline)] bg-[var(--bg-surface)] p-4 space-y-3 font-mono text-[11px] lg:p-5 flex flex-col justify-between">
              <div>
                <div className="text-[length:var(--text-label)] uppercase font-mono tracking-wider text-sky-400 mb-3">
                  Flow Identifiers
                </div>
                <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2.5 items-center">
                  <span className="text-[var(--text-secondary)] text-[length:var(--text-label)]">SOURCE</span>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[var(--text-primary)] break-all font-semibold">
                      {sourceIp ?? "—"}:{alert.source_port ?? evidence.source_port ?? "—"}
                    </span>
                    {sourceIp && renderCopyButton("src-ip", sourceIp, "Copy Source IP")}
                  </div>

                  <span className="text-[var(--text-secondary)] text-[length:var(--text-label)]">DESTINATION</span>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[var(--text-primary)] break-all">
                      {destIp ?? "—"}:{alert.destination_port ?? evidence.destination_port ?? "—"}
                    </span>
                    {destIp && renderCopyButton("dest-ip", destIp, "Copy Destination IP")}
                  </div>

                  <span className="text-[var(--text-secondary)] text-[length:var(--text-label)]">PROTOCOL</span>
                  <span className="text-[var(--text-primary)]">
                    {alert.protocol ?? evidence.protocol ?? "—"}
                  </span>
                </div>
              </div>

              <div className="pt-2 border-t border-[var(--hairline)] flex justify-between items-center text-[10px] text-[var(--text-muted)]">
                <span>BUFFER STATUS: ACTIVE</span>
                <span>TELEMETRY PASSIVE</span>
              </div>
            </div>
          </motion.div>

          {/* DDoS Evidence */}
          {visibility.ddos && (
            <motion.div variants={{ hidden: { opacity: 0, x: 20 }, visible: { opacity: 1, x: 0 } }} className="space-y-2">
              <div className="text-[length:var(--text-label)] uppercase font-mono tracking-wider text-rose-400">
                DDoS Telemetry Evidence
              </div>
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                <MetricTile label="Packets / Second" value={evidence.packets_per_second !== undefined && evidence.packets_per_second !== null ? evidence.packets_per_second.toFixed(1) : null} unit="pps" tone="rose" />
                <MetricTile label="Anomaly Z-Score" value={evidence.z_score !== undefined && evidence.z_score !== null ? evidence.z_score.toFixed(2) : null} tone="rose" />
                <MetricTile label="Flow Asymmetry Ratio" value={evidence.byte_ratio ? `${evidence.byte_ratio.toFixed(2)}x` : directionalRatio} tone="rose" />
                <MetricTile label="Observation Window" value={evidence.observation_window_seconds ?? 10} unit="s" tone="rose" />
                <MetricTile label="Inbound Packets" value={evidence.packets_in} tone="rose" />
                <MetricTile label="Outbound Packets" value={evidence.packets_out} tone="rose" />
                <MetricTile label="Inbound Bytes" value={formatBytes(evidence.inbound_bytes)} tone="rose" />
                <MetricTile label="Outbound Bytes" value={formatBytes(evidence.outbound_bytes)} tone="rose" />
              </div>
            </motion.div>
          )}

          {/* C2 Beaconing Evidence */}
          {visibility.beaconing && (
            <motion.div variants={{ hidden: { opacity: 0, x: 20 }, visible: { opacity: 1, x: 0 } }} className="space-y-2">
              <div className="text-[length:var(--text-label)] uppercase font-mono tracking-wider text-emerald-400">
                C2 Beaconing Evidence
              </div>
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                <MetricTile label="Beacon Period" value={evidence.beacon_period_seconds !== undefined && evidence.beacon_period_seconds !== null ? evidence.beacon_period_seconds.toFixed(2) : null} unit="s" tone="emerald" />
                <MetricTile label="IAT Stddev" value={evidence.inter_arrival_stddev !== undefined && evidence.inter_arrival_stddev !== null ? evidence.inter_arrival_stddev.toFixed(6) : null} unit="s" tone="emerald" />
                <MetricTile label="IAT Variance" value={evidence.inter_arrival_variance !== undefined && evidence.inter_arrival_variance !== null ? evidence.inter_arrival_variance.toFixed(6) : null} unit="s2" tone="emerald" />
                <MetricTile label="FFT Concentration" value={evidence.fft_concentration !== undefined && evidence.fft_concentration !== null ? evidence.fft_concentration.toFixed(3) : null} tone="emerald" />
              </div>
              {(evidence.ja3_hash || evidence.ja4_hash) && (
                <div className="rounded border border-[var(--hairline)] bg-[var(--bg-surface)] p-3 font-mono text-[11px] break-all text-[var(--text-primary)] mt-2 space-y-2">
                  <div className="text-[length:var(--text-label)] uppercase tracking-wider text-emerald-400">
                    C2 Cryptographic Hashes
                  </div>
                  {evidence.ja3_hash && (
                    <div className="flex items-center justify-between gap-2">
                      <div className="truncate"><span className="text-[var(--text-secondary)] mr-2">JA3:</span>{evidence.ja3_hash}</div>
                      {renderCopyButton("c2-ja3", evidence.ja3_hash, "Copy JA3 Hash")}
                    </div>
                  )}
                  {evidence.ja4_hash && (
                    <div className="flex items-center justify-between gap-2">
                      <div className="truncate"><span className="text-[var(--text-secondary)] mr-2">JA4:</span>{evidence.ja4_hash}</div>
                      {renderCopyButton("c2-ja4", evidence.ja4_hash, "Copy JA4 Hash")}
                    </div>
                  )}
                </div>
              )}
            </motion.div>
          )}

          {/* DNS / DGA Evidence */}
          {visibility.dns && (
            <motion.div variants={{ hidden: { opacity: 0, x: 20 }, visible: { opacity: 1, x: 0 } }} className="space-y-2">
              <div className="text-[length:var(--text-label)] uppercase font-mono tracking-wider text-sky-400">
                DNS / DGA Evidence
              </div>
              <div className="rounded-lg border border-[var(--hairline)] bg-[var(--bg-surface)] p-4 font-mono lg:p-5">
                <div className="grid grid-cols-2 gap-x-5 gap-y-3 lg:grid-cols-4">
                  <div>
                    <span className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase">Shannon Entropy</span>
                    <div className="mt-1 text-sky-300 font-semibold">{evidence.shannon_entropy !== undefined && evidence.shannon_entropy !== null ? evidence.shannon_entropy.toFixed(3) : "— Not observed"} <span className="text-[10px] text-[var(--text-muted)] font-normal">bits</span></div>
                  </div>
                  <div>
                    <span className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase">N-Gram Score</span>
                    <div className="mt-1 text-sky-300 font-semibold">{evidence.ngram_score !== undefined && evidence.ngram_score !== null ? evidence.ngram_score.toFixed(3) : "— Not observed"}</div>
                  </div>
                  <div>
                    <span className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase">Query Length</span>
                    <div className="mt-1 text-sky-300 font-semibold">{evidence.dns_query_length ?? "— Not observed"} <span className="text-[10px] text-[var(--text-muted)] font-normal">chars</span></div>
                  </div>
                  <div>
                    <span className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase">Record Type</span>
                    <div className="mt-1 text-sky-300 font-semibold">{evidence.dns_query_type ?? "— Not observed"}</div>
                  </div>
                </div>
                <div className="mt-4 border-t border-[var(--hairline)] pt-3 text-[11px] text-[var(--text-primary)] break-all flex items-center justify-between gap-2">
                  <span><span className="text-[var(--text-secondary)] mr-2">QUERY:</span>{evidence.dns_query ?? "— Not observed"}</span>
                  {evidence.dns_query && renderCopyButton("dns-query", evidence.dns_query, "Copy DNS Query")}
                </div>
              </div>
            </motion.div>
          )}

          {/* Encrypted Malware Evidence */}
          {visibility.malware && (
            <motion.div variants={{ hidden: { opacity: 0, x: 20 }, visible: { opacity: 1, x: 0 } }} className="space-y-2">
              <div className="flex items-center justify-between text-[length:var(--text-label)] uppercase font-mono tracking-wider text-purple-300">
                <span className="flex items-center gap-1.5"><Fingerprint className="h-3.5 w-3.5" /> Encrypted Malware Telemetry</span>
                {evidence.ja3_hash && renderCopyButton("malware-ja3", evidence.ja3_hash, "Copy JA3 Hash")}
              </div>
              <div className="rounded border border-[var(--hairline)] bg-[var(--bg-surface)] p-3 font-mono text-[11px] break-all text-[var(--text-primary)] space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div><span className="text-[var(--text-secondary)] text-[length:var(--text-label)] mr-2">JA3:</span>{evidence.ja3_hash ?? <span className="text-[var(--text-muted)] italic">— Not observed</span>}</div>
                  {evidence.ja3_hash && renderCopyButton("mw-ja3-inline", evidence.ja3_hash, "Copy JA3")}
                </div>
                <div className="flex items-center justify-between gap-2">
                  <div><span className="text-[var(--text-secondary)] text-[length:var(--text-label)] mr-2">JA4:</span>{evidence.ja4_hash ?? <span className="text-[var(--text-muted)] italic">— Not observed</span>}</div>
                  {evidence.ja4_hash && renderCopyButton("mw-ja4-inline", evidence.ja4_hash, "Copy JA4")}
                </div>
                <div><span className="text-[var(--text-secondary)] text-[length:var(--text-label)] mr-2">SNI:</span>{evidence.sni ?? <span className="text-[var(--text-muted)] italic">— Not observed</span>}</div>
              </div>
              {(evidence.splt_packet_sizes || evidence.splt_interarrival_times) && (
                <div className="rounded border border-[var(--hairline)] bg-[var(--bg-surface)] p-2.5 font-mono text-[10px] text-[var(--text-secondary)] break-all space-y-1">
                  <div>SPLT sizes: {JSON.stringify(evidence.splt_packet_sizes ?? [])}</div>
                  <div>SPLT IAT: {JSON.stringify(evidence.splt_interarrival_times ?? [])}</div>
                </div>
              )}
              {evidence.fft_concentration !== null && evidence.fft_concentration !== undefined && (
                <div className="grid grid-cols-2 gap-3 mt-2">
                  <MetricTile label="FFT Concentration" value={evidence.fft_concentration.toFixed(3)} tone="purple" />
                </div>
              )}
            </motion.div>
          )}

          {/* Reconnaissance Evidence */}
          {visibility.reconnaissance && (
            <motion.div variants={{ hidden: { opacity: 0, x: 20 }, visible: { opacity: 1, x: 0 } }} className="space-y-2">
              <div className="text-[length:var(--text-label)] uppercase font-mono tracking-wider text-amber-400">
                Reconnaissance Evidence
              </div>
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                <MetricTile label="Fan-Out 10s" value={evidence.window_10s_fan_out} unit="targets" tone="amber" />
                <MetricTile label="Fan-Out 60s" value={evidence.window_60s_fan_out} unit="targets" tone="amber" />
                <MetricTile label="Unique Hosts" value={evidence.unique_destination_hosts} tone="amber" />
                <MetricTile label="Unique Ports" value={evidence.unique_destination_ports} tone="amber" />
                <MetricTile label="Source-IP Entropy" value={evidence.source_ip_entropy !== undefined && evidence.source_ip_entropy !== null ? evidence.source_ip_entropy.toFixed(3) : null} tone="amber" />
              </div>
            </motion.div>
          )}

          {/* Exfiltration Evidence */}
          {visibility.exfiltration && (
            <motion.div variants={{ hidden: { opacity: 0, x: 20 }, visible: { opacity: 1, x: 0 } }} className="space-y-2">
              <div className="text-[length:var(--text-label)] uppercase font-mono tracking-wider text-amber-400">
                Exfiltration Evidence
              </div>
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                <MetricTile label="Flow Asymmetry Ratio" value={evidence.byte_ratio ? `${evidence.byte_ratio.toFixed(2)}x` : null} tone="amber" />
                <MetricTile label="Total Uploaded" value={formatBytes(evidence.total_uploaded_bytes)} tone="amber" />
                <MetricTile label="Inbound Bytes" value={formatBytes(evidence.inbound_bytes)} tone="amber" />
                <MetricTile label="Outbound Bytes" value={formatBytes(evidence.outbound_bytes)} tone="amber" />
              </div>
              {directionalRatio && (
                <div className="font-mono text-[11px] text-amber-400 bg-[var(--bg-surface)] p-2 rounded border border-[var(--hairline)]">
                  INBOUND : OUTBOUND RATIO = {directionalRatio}
                </div>
              )}
            </motion.div>
          )}

          {/* Confidence Basis & Processing Telemetry */}
          <motion.div
            variants={{ hidden: { opacity: 0, x: 20 }, visible: { opacity: 1, x: 0 } }}
            className="grid gap-3 xl:grid-cols-2"
          >
            <div className="rounded-lg border border-[var(--hairline)] bg-[var(--bg-surface)] p-4 space-y-3 font-mono text-[11px] lg:p-5">
              <div className="text-[length:var(--text-label)] uppercase font-mono tracking-wider text-sky-400">
                Confidence Basis
              </div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
                <span className="text-[var(--text-secondary)] text-[length:var(--text-label)]">NORMALIZED SCORE</span>
                <span className="text-emerald-400 font-semibold">{alert.confidence_score.toFixed(2)} / 1.00</span>
                <span className="text-[var(--text-secondary)] text-[length:var(--text-label)]">DETECTORS FIRED</span>
                <span className="text-[var(--text-primary)]">{detectorCount}</span>
                <span className="text-[var(--text-secondary)] text-[length:var(--text-label)]">CORROBORATION</span>
                <span className="text-[var(--text-primary)]">{detectorCount > 1 ? "YES" : "NONE"}</span>
              </div>
              <div className="border-t border-[var(--hairline)] pt-2 text-[var(--text-secondary)]">
                {evidence.confidence_basis ?? "Confidence basis metadata unavailable for this alert."}
              </div>
              <div className="flex flex-wrap gap-1 pt-1">
                {detectorsFired.map((detector) => (
                  <span
                    key={detector}
                    className="rounded border border-sky-500/20 bg-sky-500/10 px-1.5 py-0.5 text-[10px] text-sky-300 font-mono"
                  >
                    {detector}
                  </span>
                ))}
              </div>
            </div>

            <div className="rounded-lg border border-[var(--hairline)] bg-[var(--bg-surface)] p-4 space-y-2 font-mono text-[11px] lg:p-5 flex flex-col justify-between">
              <div className="space-y-2">
                <div className="text-[length:var(--text-label)] uppercase font-mono tracking-wider text-[var(--text-secondary)] mb-2">
                  Pipeline Latency
                </div>
                <div className="flex justify-between py-1 border-b border-[var(--hairline)]">
                  <span className="text-[var(--text-secondary)] text-[length:var(--text-label)]">TIMESTAMP (UTC):</span>
                  <span className="text-[var(--text-primary)]">{formatTimestamp(alert.timestamp)}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-[var(--hairline)]">
                  <span className="text-[var(--text-secondary)] text-[length:var(--text-label)]">PROCESSING:</span>
                  <span className="text-[var(--text-primary)]">
                    {alert.processing_latency_ms !== null && alert.processing_latency_ms !== undefined ? `${alert.processing_latency_ms.toFixed(2)} ms` : "—"}{" "}
                    <span className={`ml-1 rounded border px-1 py-0.5 text-[9px] ${processingState.className}`}>
                      {processingState.label}
                    </span>
                  </span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-[var(--text-secondary)] text-[length:var(--text-label)]">INGEST:</span>
                  <span className="text-[var(--text-primary)]">
                    {alert.ingest_latency_ms !== null && alert.ingest_latency_ms !== undefined ? `${alert.ingest_latency_ms.toFixed(2)} ms` : "—"}{" "}
                    <span className={`ml-1 rounded border px-1 py-0.5 text-[9px] ${ingestState.className}`}>
                      {ingestState.label}
                    </span>
                  </span>
                </div>
              </div>
            </div>
          </motion.div>

          {/* Raw Forensics JSON Payload with copy */}
          <motion.details
            variants={{ hidden: { opacity: 0, x: 20 }, visible: { opacity: 1, x: 0 } }}
            className="space-y-1 pt-1"
          >
            <summary className="cursor-pointer text-[length:var(--text-label)] font-mono text-[var(--text-secondary)] uppercase hover:text-[var(--text-primary)] flex items-center justify-between">
              <span>Expand Raw Forensics Payload (JSON)</span>
            </summary>
            <div className="relative mt-2">
              <div className="absolute right-3 top-3 z-10">
                {renderCopyButton("raw-json", JSON.stringify(alert, null, 2), "Copy Full JSON Payload")}
              </div>
              <pre className="max-h-80 overflow-y-auto whitespace-pre-wrap break-words rounded bg-[var(--bg-surface)] p-3 text-[10px] font-mono text-[var(--text-secondary)] border border-[var(--hairline)] leading-normal select-text">
                {JSON.stringify(alert, null, 2)}
              </pre>
            </div>
          </motion.details>

          {/* Analyst Commentary */}
          <motion.div
            variants={{ hidden: { opacity: 0, x: 20 }, visible: { opacity: 1, x: 0 } }}
            className="rounded-lg border border-[var(--hairline)] bg-[var(--bg-surface)] p-4 space-y-3 font-mono text-[11px] lg:p-5"
          >
            <div className="text-[length:var(--text-label)] uppercase font-mono tracking-wider text-[var(--text-secondary)]">
              Analyst Notes &amp; Investigation Log
            </div>
            <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
              {notesLoading && <div className="text-[var(--text-muted)]">Loading notes...</div>}
              {!notesLoading && notes.length === 0 && (
                <div className="text-[var(--text-muted)] italic">No analyst notes recorded yet.</div>
              )}
              {notes.map((note) => (
                <div key={`${note.created_at}-${note.text}`} className="border-l-2 border-[var(--hairline)] pl-3 py-0.5">
                  <div className="text-[var(--text-primary)] whitespace-pre-wrap break-words">{note.text}</div>
                  <div className="mt-1 text-[10px] text-[var(--text-muted)]">{formatTimestamp(note.created_at)}</div>
                </div>
              ))}
            </div>
            <div className="flex gap-2 pt-2 border-t border-[var(--hairline)]">
              <textarea
                value={noteText}
                onChange={(event) => setNoteText(event.target.value)}
                placeholder="Add investigator commentary..."
                className="min-h-16 flex-1 resize-y rounded border border-[var(--hairline)] bg-[var(--bg-base)] p-2 text-[11px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:ring-1 focus:ring-zinc-600"
              />
              <Button
                variant="outline"
                size="sm"
                onClick={submitNote}
                disabled={!noteText.trim()}
                className="self-end h-8 text-[10px] font-mono border-[var(--hairline)] bg-[var(--bg-surface)] hover:bg-[var(--bg-surface-hover)]"
              >
                ADD NOTE
              </Button>
            </div>
          </motion.div>
        </motion.div>
      </SheetContent>
    </Sheet>
  );
}

