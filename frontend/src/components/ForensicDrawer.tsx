import { type ReactNode, useEffect, useState } from "react";
import { FingerPrintIcon as Fingerprint, Alert02Icon as Alert02 } from "hugeicons-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet, SheetClose, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { AnalystNote, SeverityLevel, ThreatAlertSchema } from "@/types/threat";
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

const evidenceVisibilityByThreat: Record<string, EvidenceVisibility> = {
  "Volumetric & Protocol DDoS": { ddos: true },
  "Botnet C2 Beaconing": { beaconing: true },
  "DGA & DNS Tunneling": { dns: true },
  "Encrypted Malware": { malware: true },
  "Reconnaissance Scan": { reconnaissance: true },
  "Data Exfiltration": { exfiltration: true },
};

const toneClasses: Record<MetricTone, string> = {
  cyan: "text-cyan-300",
  emerald: "text-emerald-300",
  amber: "text-amber-300",
  rose: "text-rose-300",
  purple: "text-purple-300",
};

function MetricTile({ label, value, unit, tone = "cyan" }: { label: string; value: ReactNode; unit?: string; tone?: MetricTone }) {
  return (
    <div className="rounded border border-slate-800/80 bg-slate-900/40 p-2.5">
      <div className="text-[10px] uppercase font-mono text-slate-400">{label}</div>
      <div className={`mt-1 text-sm font-semibold font-mono ${toneClasses[tone]}`}>
        {value}
        {unit && <span className="ml-1 text-[10px] text-slate-500 font-normal">{unit}</span>}
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
  if (value === null || value === undefined) return { label: "UNAVAILABLE", className: "text-slate-500 border-slate-700" };
  if (value <= 10) return { label: "WITHIN NORMAL", className: "text-emerald-300 border-emerald-500/30" };
  if (value <= 100) return { label: "ELEVATED", className: "text-amber-300 border-amber-500/30" };
  return { label: "DEGRADED", className: "text-rose-300 border-rose-500/30" };
}

export function ForensicDrawer({ alert, onClose }: ForensicDrawerProps) {
  const [copied, setCopied] = useState(false);
  const [notes, setNotes] = useState<AnalystNote[]>([]);
  const [noteText, setNoteText] = useState("");
  const [notesLoading, setNotesLoading] = useState(false);

  useEffect(() => {
    if (!alert) return;
    setNotesLoading(true);
    fetch(`/api/alerts/${encodeURIComponent(alert.flow_id)}/notes`)
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("notes request failed")))
      .then((data: AnalystNote[]) => setNotes(data))
      .catch(() => setNotes([]))
      .finally(() => setNotesLoading(false));
  }, [alert?.flow_id]);

  if (!alert) return null;

  const { evidence } = alert;
  const threatClass = String(alert.threat_class);
  const visibility = evidenceVisibilityByThreat[threatClass] ?? {};
  const directionalRatio = evidence.inbound_bytes !== null && evidence.inbound_bytes !== undefined && evidence.outbound_bytes !== null && evidence.outbound_bytes !== undefined
    ? `1:${(evidence.outbound_bytes / Math.max(evidence.inbound_bytes, 1)).toFixed(1)}`
    : null;

  const handleCopyJA3 = () => {
    if (!evidence.ja3_hash) return;
    navigator.clipboard.writeText(evidence.ja3_hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Severity band comes from the backend's centralized calibration; the
  // confidence percentage is displayed alongside but never used to derive it.
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
  const detectorCount = evidence.detector_count ?? 1;
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
    const note = await response.json() as AnalystNote;
    setNotes((current) => [...current, note]);
    setNoteText("");
  };

  return (
    <Sheet open={Boolean(alert)} onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="w-full border-l border-slate-800 bg-slate-950 p-5 font-sans sm:w-[60vw] sm:max-w-[60vw] sm:p-6 lg:w-[60vw] lg:max-w-[60vw] lg:p-8">
        <SheetClose />
        <SheetHeader>
          <div className="flex items-center space-x-2">
            <Alert02 className="h-4 w-4 text-cyan-400" />
            <SheetTitle className="text-[length:var(--text-heading)] font-bold uppercase tracking-wider text-slate-100 font-mono">Forensic Evidence Dossier</SheetTitle>
          </div>
          <SheetDescription className="text-xs font-mono text-slate-400">INCIDENT ID: {alert.flow_id}</SheetDescription>
        </SheetHeader>

        <div className="space-y-5 pt-5 text-xs">
          <div className="grid gap-3 lg:grid-cols-[3fr_2fr]">
            <div className="rounded-lg border border-slate-800/80 bg-slate-900/60 p-4 space-y-3 lg:p-5">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 text-[11px] font-mono uppercase">Classified Threat</span>
                {getSeverityBadge(alert.severity, alert.confidence_score)}
              </div>
              <div className="text-[length:var(--text-display)] leading-tight font-bold text-slate-100 font-mono">{threatClass}</div>
              <div className="text-[11px] text-slate-300 bg-slate-950/70 p-3 rounded border border-slate-800/60 font-mono leading-relaxed">{evidence.details}</div>
            </div>

            <div className="rounded-lg border border-slate-800/80 bg-slate-900/40 p-4 space-y-3 font-mono text-[11px] lg:p-5">
              <div className="text-[10px] uppercase tracking-wider text-cyan-300">Flow Identifiers</div>
              <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2">
                <span className="text-slate-400">SOURCE</span><span className="text-slate-100 break-all">{alert.source_ip ?? evidence.source_ip ?? "N/A"}:{alert.source_port ?? evidence.source_port ?? "N/A"}</span>
                <span className="text-slate-400">DESTINATION</span><span className="text-slate-100 break-all">{alert.destination_ip ?? evidence.destination_ip ?? "N/A"}:{alert.destination_port ?? evidence.destination_port ?? "N/A"}</span>
                <span className="text-slate-400">PROTOCOL</span><span className="text-slate-100">{alert.protocol ?? evidence.protocol ?? "N/A"}</span>
              </div>
            </div>
          </div>

          {visibility.ddos && (
            <div className="space-y-2">
              <div className="text-[10px] uppercase font-mono tracking-wider text-rose-300">DDoS Evidence</div>
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
                <MetricTile label="Packets / Second" value={evidence.packets_per_second?.toFixed(1) ?? "UNAVAILABLE"} unit="pps" tone="rose" />
                <MetricTile label="Anomaly Z-Score" value={evidence.z_score?.toFixed(2) ?? "UNAVAILABLE"} tone="rose" />
                <MetricTile label="Source-IP Entropy" value={evidence.source_ip_entropy?.toFixed(3) ?? "UNAVAILABLE"} tone="rose" />
                <MetricTile label="Unique Sources" value={evidence.unique_source_count ?? "UNAVAILABLE"} unit="attackers" tone="rose" />
                <MetricTile label="Inbound Attempts" value={evidence.inbound_connections ?? "UNAVAILABLE"} tone="rose" />
                <MetricTile label="Inbound Packets" value={evidence.packets_in ?? "UNAVAILABLE"} tone="rose" />
                <MetricTile label="Outbound Packets" value={evidence.packets_out ?? "UNAVAILABLE"} tone="rose" />
              </div>
            </div>
          )}

          {visibility.beaconing && (
            <div className="space-y-2">
              <div className="text-[10px] uppercase font-mono tracking-wider text-emerald-300">C2 Beaconing Evidence</div>
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                <MetricTile label="IAT Variance" value={evidence.inter_arrival_variance.toFixed(6)} unit="s2" tone="emerald" />
                <MetricTile label="IAT Stddev" value={evidence.inter_arrival_stddev?.toFixed(6) ?? "UNAVAILABLE"} unit="s" tone="emerald" />
                <MetricTile label="Beacon Period" value={evidence.beacon_period_seconds?.toFixed(2) ?? "UNAVAILABLE"} unit="s" tone="emerald" />
                <MetricTile label="FFT Concentration" value={evidence.fft_concentration?.toFixed(3) ?? "UNAVAILABLE"} tone="emerald" />
              </div>
            </div>
          )}

          {visibility.dns && (
            <div className="space-y-2">
              <div className="text-[10px] uppercase font-mono tracking-wider text-cyan-300">DNS / DGA Evidence</div>
              <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/[0.04] p-4 font-mono lg:p-5">
                <div className="grid grid-cols-2 gap-x-5 gap-y-3 lg:grid-cols-4">
                  <div><span className="text-[10px] text-slate-400">SHANNON ENTROPY</span><div className="mt-1 text-cyan-300">{evidence.shannon_entropy.toFixed(3)} <span className="text-[10px] text-slate-500">bits</span></div></div>
                  <div><span className="text-[10px] text-slate-400">N-GRAM SCORE</span><div className="mt-1 text-cyan-300">{evidence.ngram_score?.toFixed(3) ?? "UNAVAILABLE"}</div></div>
                  <div><span className="text-[10px] text-slate-400">QUERY LENGTH</span><div className="mt-1 text-cyan-300">{evidence.dns_query_length ?? "UNAVAILABLE"} <span className="text-[10px] text-slate-500">chars</span></div></div>
                  <div><span className="text-[10px] text-slate-400">RECORD TYPE</span><div className="mt-1 text-cyan-300">{evidence.dns_query_type ?? "UNAVAILABLE"}</div></div>
                </div>
                <div className="mt-4 border-t border-cyan-500/15 pt-3 text-[11px] text-cyan-200 break-all">QUERY: {evidence.dns_query ?? "UNAVAILABLE"}</div>
              </div>
            </div>
          )}

          {visibility.malware && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-[10px] uppercase font-mono tracking-wider text-purple-300">
                <span className="flex items-center gap-1.5"><Fingerprint className="h-3.5 w-3.5" /> Encrypted Malware Evidence</span>
                {evidence.ja3_hash && <Button variant="outline" size="sm" onClick={handleCopyJA3} className="h-6 text-[10px] px-2 font-mono border-slate-700">{copied ? "COPIED" : "COPY JA3"}</Button>}
              </div>
              <div className="rounded border border-purple-500/20 bg-purple-500/[0.04] p-2 font-mono text-[11px] break-all text-purple-200">
                JA3: {evidence.ja3_hash ?? "NOT CAPTURED"}<br />
                JA4: {evidence.ja4_hash ?? "NOT CAPTURED"}<br />
                SNI: {evidence.sni ?? "NOT CAPTURED"}
              </div>
              {(evidence.splt_packet_sizes || evidence.splt_interarrival_times) && <div className="rounded border border-purple-500/20 bg-purple-500/[0.04] p-2 font-mono text-[10px] text-purple-200 break-all">SPLT sizes: {JSON.stringify(evidence.splt_packet_sizes ?? [])}<br />SPLT IAT: {JSON.stringify(evidence.splt_interarrival_times ?? [])}</div>}
            </div>
          )}

          {visibility.reconnaissance && (
            <div className="space-y-2">
              <div className="text-[10px] uppercase font-mono tracking-wider text-amber-300">Reconnaissance Evidence</div>
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-3">
                <MetricTile label="Fan-Out 10s" value={evidence.window_10s_fan_out ?? "UNAVAILABLE"} unit="targets" tone="amber" />
                <MetricTile label="Fan-Out 60s" value={evidence.window_60s_fan_out ?? "UNAVAILABLE"} unit="targets" tone="amber" />
                <MetricTile label="Unique Hosts" value={evidence.unique_destination_hosts ?? "UNAVAILABLE"} tone="amber" />
                <MetricTile label="Unique Ports" value={evidence.unique_destination_ports ?? "UNAVAILABLE"} tone="amber" />
              </div>
            </div>
          )}

          {visibility.exfiltration && (
            <div className="space-y-2">
              <div className="text-[10px] uppercase font-mono tracking-wider text-amber-300">Exfiltration Evidence</div>
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                <MetricTile label="Egress Ratio" value={evidence.byte_ratio.toFixed(2)} unit="x" tone="amber" />
                <MetricTile label="Total Uploaded" value={formatBytes(evidence.total_uploaded_bytes) ?? "UNAVAILABLE"} tone="amber" />
                <MetricTile label="Inbound Bytes" value={formatBytes(evidence.inbound_bytes) ?? "UNAVAILABLE"} tone="amber" />
                <MetricTile label="Outbound Bytes" value={formatBytes(evidence.outbound_bytes) ?? "UNAVAILABLE"} tone="amber" />
              </div>
              {directionalRatio && <div className="font-mono text-[11px] text-amber-300">INBOUND:OUTBOUND: {directionalRatio}</div>}
            </div>
          )}

          <div className="grid gap-3 xl:grid-cols-2">
            <div className="rounded-lg border border-slate-800/80 bg-slate-900/40 p-4 space-y-3 font-mono text-[11px] lg:p-5">
              <div className="text-[10px] uppercase tracking-wider text-cyan-300">Confidence Basis</div>
              <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
                <span className="text-slate-400">NORMALIZED SCORE</span><span className="text-emerald-300">{alert.confidence_score.toFixed(2)} / 1.00</span>
                <span className="text-slate-400">DETECTORS FIRED</span><span className="text-slate-100">{detectorCount}</span>
                <span className="text-slate-400">CORROBORATION</span><span className="text-slate-100">{detectorCount > 1 ? "YES" : "NONE"}</span>
              </div>
              <div className="border-t border-slate-800/60 pt-2 text-slate-300">{evidence.confidence_basis ?? "Confidence basis metadata unavailable for this archived alert."}</div>
              <div className="flex flex-wrap gap-1">{detectorsFired.map((detector) => <span key={detector} className="rounded border border-cyan-500/20 bg-cyan-500/[0.06] px-1.5 py-0.5 text-[10px] text-cyan-300">{detector}</span>)}</div>
            </div>

            <div className="rounded-lg border border-slate-800/80 bg-slate-900/40 p-4 space-y-2 font-mono text-[11px] lg:p-5">
              <div className="flex justify-between py-0.5 border-b border-slate-800/40"><span className="text-slate-400">TIMESTAMP (UTC):</span><span className="text-slate-200">{formatTimestamp(alert.timestamp)}</span></div>
              <div className="flex justify-between py-0.5 border-b border-slate-800/40"><span className="text-slate-400">PROCESSING:</span><span className="text-slate-200">{alert.processing_latency_ms?.toFixed(2) ?? "N/A"} ms <span className={`ml-1 rounded border px-1 py-0.5 text-[9px] ${processingState.className}`}>{processingState.label}</span></span></div>
              <div className="flex justify-between py-0.5"><span className="text-slate-400">INGEST:</span><span className="text-slate-200">{alert.ingest_latency_ms?.toFixed(2) ?? "N/A"} ms <span className={`ml-1 rounded border px-1 py-0.5 text-[9px] ${ingestState.className}`}>{ingestState.label}</span></span></div>
            </div>
          </div>

          <details className="space-y-1 pt-1">
            <summary className="cursor-pointer text-[10px] font-mono text-slate-400 uppercase hover:text-slate-200">Expand Raw Forensics Payload (JSON)</summary>
            <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded bg-slate-950 p-2.5 text-[10px] font-mono text-slate-300 border border-slate-800 leading-normal">{JSON.stringify(alert, null, 2)}</pre>
          </details>

          <div className="rounded-lg border border-slate-800/80 bg-slate-900/30 p-4 space-y-3 font-mono text-[11px] lg:p-5">
            <div className="text-[10px] uppercase tracking-wider text-slate-400">Analyst Notes</div>
            <div className="space-y-2 max-h-40 overflow-y-auto">
              {notesLoading && <div className="text-slate-500">Loading notes...</div>}
              {!notesLoading && notes.length === 0 && <div className="text-slate-600">No analyst notes.</div>}
              {notes.map((note) => <div key={`${note.created_at}-${note.text}`} className="border-l border-slate-700 pl-2"><div className="text-slate-300 whitespace-pre-wrap break-words">{note.text}</div><div className="mt-1 text-[10px] text-slate-600">{formatTimestamp(note.created_at)}</div></div>)}
            </div>
            <div className="flex gap-2">
              <textarea value={noteText} onChange={(event) => setNoteText(event.target.value)} placeholder="Add investigator commentary..." className="min-h-16 flex-1 resize-y rounded border border-slate-800 bg-slate-950 p-2 text-[11px] text-slate-200 placeholder:text-slate-600" />
              <Button variant="outline" size="sm" onClick={submitNote} disabled={!noteText.trim()} className="self-end h-7 text-[10px] font-mono">ADD NOTE</Button>
            </div>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
