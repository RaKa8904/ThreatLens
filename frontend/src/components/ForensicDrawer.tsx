import { useState } from "react";
import {
  FingerPrintIcon as Fingerprint,
  Alert02Icon as Alert02,
} from "hugeicons-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { ThreatAlertSchema } from "@/types/threat";
import { formatTimestamp } from "@/lib/utils";

interface ForensicDrawerProps {
  alert: ThreatAlertSchema | null;
  onClose: () => void;
}

export function ForensicDrawer({ alert, onClose }: ForensicDrawerProps) {
  const [copied, setCopied] = useState<boolean>(false);

  if (!alert) return null;

  const { evidence } = alert;
  const isReconnaissance = String(alert.threat_class) === "Reconnaissance Scan";
  const portConnectionCount = evidence.port_connections ?? evidence.fan_out_count;

  const formatBytes = (bytes: number | null | undefined) => {
    if (bytes === null || bytes === undefined) return "N/A";
    if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(2)} MB`;
    if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
    return `${bytes} B`;
  };

  const directionalRatio = evidence.inbound_bytes && evidence.outbound_bytes !== null && evidence.outbound_bytes !== undefined
    ? `1:${(evidence.outbound_bytes / Math.max(evidence.inbound_bytes, 1)).toFixed(1)}`
    : "N/A";

  const handleCopyJA3 = () => {
    if (evidence.ja3_hash) {
      navigator.clipboard.writeText(evidence.ja3_hash);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getSeverityBadge = (score: number) => {
    if (score >= 0.85) return <Badge variant="critical">CRITICAL ({Math.round(score * 100)}%)</Badge>;
    if (score >= 0.70) return <Badge variant="high">HIGH ({Math.round(score * 100)}%)</Badge>;
    if (score >= 0.50) return <Badge variant="medium">MODERATE ({Math.round(score * 100)}%)</Badge>;
    return <Badge variant="low">LOW ({Math.round(score * 100)}%)</Badge>;
  };

  return (
    <Sheet open={Boolean(alert)} onOpenChange={(open) => !open && onClose()}>
      <SheetContent side="right" className="w-full sm:max-w-lg border-l border-slate-800 bg-slate-950 p-5 font-sans">
        <SheetClose />

        <SheetHeader>
          <div className="flex items-center space-x-2">
            <Alert02 className="h-4 w-4 text-cyan-400" />
            <SheetTitle className="text-sm font-bold uppercase tracking-wider text-slate-100 font-mono">
              Forensic Evidence Dossier
            </SheetTitle>
          </div>
          <SheetDescription className="text-xs font-mono text-slate-400">
            INCIDENT ID: {alert.flow_id}
          </SheetDescription>
        </SheetHeader>

        <div className="space-y-4 pt-4 text-xs">
          {/* Top Threat Classification Card */}
          <div className="rounded-lg border border-slate-800/80 bg-slate-900/60 p-3 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 text-[11px] font-mono uppercase">Classified Threat</span>
              {getSeverityBadge(alert.confidence_score)}
            </div>
            <div className="text-sm font-semibold text-slate-100 font-mono">
              {alert.threat_class}
            </div>
            <div className="text-[11px] text-slate-300 bg-slate-950/70 p-2 rounded border border-slate-800/60 font-mono leading-relaxed">
              {evidence.details}
            </div>
          </div>

          {/* Core Telemetry Metrics Grid */}
          <div className="grid grid-cols-2 gap-2">
            <div className="rounded border border-slate-800/80 bg-slate-900/40 p-2.5">
              <div className="text-[10px] uppercase font-mono text-slate-400">
                Shannon Entropy (H)
              </div>
              <div className="mt-1 text-sm font-semibold font-mono text-cyan-300">
                {evidence.shannon_entropy.toFixed(3)}{" "}
                <span className="text-[10px] text-slate-500 font-normal">bits</span>
              </div>
            </div>

            <div className="rounded border border-slate-800/80 bg-slate-900/40 p-2.5">
              <div className="text-[10px] uppercase font-mono text-slate-400">
                IAT Variance (Δt)
              </div>
              <div className="mt-1 text-sm font-semibold font-mono text-emerald-300">
                {evidence.inter_arrival_variance.toFixed(6)}{" "}
                <span className="text-[10px] text-slate-500 font-normal">s²</span>
              </div>
            </div>

            <div className="rounded border border-slate-800/80 bg-slate-900/40 p-2.5">
              <div className="text-[10px] uppercase font-mono text-slate-400">
                Flow Asymmetry Ratio
              </div>
              <div className="mt-1 text-sm font-semibold font-mono text-purple-300">
                {evidence.byte_ratio.toFixed(2)}x
              </div>
            </div>

            <div className="rounded border border-slate-800/80 bg-slate-900/40 p-2.5">
              <div className="text-[10px] uppercase font-mono text-slate-400">
                Fan-Out Cardinality
              </div>
              <div className="mt-1 text-sm font-semibold font-mono text-amber-300">
                {evidence.fan_out_count}{" "}
                <span className="text-[10px] text-slate-500 font-normal">targets</span>
              </div>
            </div>

            {isReconnaissance && (
              <div className="rounded border border-amber-500/30 bg-amber-500/[0.04] p-2.5">
                <div className="text-[10px] uppercase font-mono text-slate-400">
                  Unique Port Connections
                </div>
                <div className="mt-1 text-sm font-semibold font-mono text-amber-300">
                  {portConnectionCount}
                  <span className="text-[10px] text-slate-500 font-normal"> ports / 60s</span>
                </div>
              </div>
            )}
          </div>

          {/* Threat-specific operational insights */}
          <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/[0.04] p-3 space-y-2">
            <div className="text-[10px] uppercase font-mono tracking-wider text-cyan-300">
              Operational Insights
            </div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-2 font-mono text-[11px]">
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">PROTOCOL:</span>
                <span className="text-slate-100">{evidence.protocol || "N/A"}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">DEST PORT:</span>
                <span className="text-slate-100">{evidence.destination_port ?? "N/A"}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">INBOUND PKTS:</span>
                <span className="text-cyan-200">{evidence.packets_in ?? "N/A"}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">OUTBOUND PKTS:</span>
                <span className="text-cyan-200">{evidence.packets_out ?? "N/A"}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">INBOUND BYTES:</span>
                <span className="text-slate-100">{formatBytes(evidence.inbound_bytes)}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-slate-400">OUTBOUND BYTES:</span>
                <span className="text-slate-100">{formatBytes(evidence.outbound_bytes)}</span>
              </div>
              {alert.threat_class === "Volumetric & Protocol DDoS" && (
                <div className="col-span-2 flex justify-between gap-2 border-t border-cyan-500/10 pt-2">
                  <span className="text-slate-400">INBOUND CONNECTION ATTEMPTS:</span>
                  <span className="font-semibold text-rose-300">{evidence.inbound_connections ?? "N/A"}</span>
                </div>
              )}
              {alert.threat_class === "Data Exfiltration" && (
                <div className="col-span-2 flex justify-between gap-2 border-t border-cyan-500/10 pt-2">
                  <span className="text-slate-400">INBOUND:OUTBOUND:</span>
                  <span className="font-semibold text-amber-300">{directionalRatio}</span>
                </div>
              )}
              {isReconnaissance && (
                <div className="col-span-2 flex justify-between gap-2 border-t border-cyan-500/10 pt-2">
                  <span className="text-slate-400">UNIQUE PORT CONNECTIONS:</span>
                  <span className="font-semibold text-amber-300">
                    {portConnectionCount}
                  </span>
                </div>
              )}
              {evidence.observation_window_seconds !== null && evidence.observation_window_seconds !== undefined && (
                <div className="col-span-2 flex justify-between gap-2 border-t border-cyan-500/10 pt-2">
                  <span className="text-slate-400">OBSERVATION WINDOW:</span>
                  <span className="text-slate-100">{evidence.observation_window_seconds}s</span>
                </div>
              )}
            </div>
          </div>

          {/* Cryptographic JA3/JA4 Fingerprint */}
          <div className="rounded-lg border border-slate-800/80 bg-slate-900/60 p-3 space-y-1.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-1.5 text-[11px] font-mono text-slate-400">
                <Fingerprint className="h-3.5 w-3.5 text-cyan-400" />
                <span>CRYPTOGRAPHIC JA3 HASH</span>
              </div>
              {evidence.ja3_hash && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCopyJA3}
                  className="h-6 text-[10px] px-2 font-mono border-slate-700"
                >
                  {copied ? "COPIED" : "COPY HASH"}
                </Button>
              )}
            </div>

            <div className="p-2 rounded bg-slate-950/80 border border-slate-800 font-mono text-[11px] break-all text-cyan-200">
              {evidence.ja3_hash ? evidence.ja3_hash : "No TLS ClientHello captured (cleartext or UDP flow)"}
            </div>
          </div>

          {/* Session Metadata */}
          <div className="rounded-lg border border-slate-800/80 bg-slate-900/40 p-3 space-y-1 font-mono text-[11px]">
            <div className="flex justify-between py-0.5 border-b border-slate-800/40">
              <span className="text-slate-400">TIMESTAMP:</span>
              <span className="text-slate-200">{formatTimestamp(alert.timestamp)}</span>
            </div>
            <div className="flex justify-between py-0.5 border-b border-slate-800/40">
              <span className="text-slate-400">CANONICAL FLOW:</span>
              <span className="text-slate-200 break-all">{alert.flow_id}</span>
            </div>
            <div className="flex justify-between py-0.5">
              <span className="text-slate-400">CONFIDENCE:</span>
              <span className="text-emerald-400 font-semibold">{alert.confidence_score.toFixed(2)} / 1.00</span>
            </div>
          </div>

          {/* Raw Evidence JSON Viewer */}
          <div className="space-y-1 pt-1">
            <div className="text-[10px] font-mono text-slate-400 uppercase">
              Raw Forensics Payload (JSON)
            </div>
            <pre className="max-h-44 overflow-y-auto rounded bg-slate-950 p-2.5 text-[10px] font-mono text-slate-300 border border-slate-800 leading-normal">
              {JSON.stringify(alert, null, 2)}
            </pre>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
