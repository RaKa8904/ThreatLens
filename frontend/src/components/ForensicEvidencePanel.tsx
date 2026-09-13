import { useState } from "react";
import { ThreatAlertSchema } from "@/types/threat";
import { Copy01Icon as Copy, Tick01Icon as Check } from "hugeicons-react";
import { ResponsiveContainer, AreaChart, Area } from "recharts";

interface ForensicEvidencePanelProps {
  selectedAlert?: ThreatAlertSchema | null;
}

export function ForensicEvidencePanel({ selectedAlert }: ForensicEvidencePanelProps) {
  const [copied, setCopied] = useState(false);

  // Extract or default evidence values
  const entropy = selectedAlert?.evidence?.shannon_entropy ?? 4.82;
  const ja3 = selectedAlert?.evidence?.ja3_hash || "771486d56e2c7f8b4a00192a8c3d";
  const iatVar = selectedAlert?.evidence?.inter_arrival_variance ?? 0.082;
  const byteRatio = selectedAlert?.evidence?.byte_ratio ?? 1.0;

  const handleCopy = () => {
    navigator.clipboard.writeText(ja3);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Sparkline data for Inter-Arrival Time
  const sparkData = [
    { v: 12 }, { v: 15 }, { v: 14 }, { v: 15 }, { v: 80 }, { v: 15 }, { v: 14 },
    { v: 15 }, { v: 15 }, { v: 95 }, { v: 14 }, { v: 15 }, { v: 15 }, { v: 14 },
  ];

  return (
    <div className="bg-[#090d16] border border-zinc-800/60 rounded-xl p-4 flex flex-col justify-between h-full">
      {/* Title Bar */}
      <div className="flex items-center justify-between border-b border-zinc-800/60 pb-2.5 mb-3">
        <div>
          <h3 className="text-sm font-semibold text-zinc-100 font-sans">Forensic Evidence</h3>
          <p className="text-[10px] font-mono text-zinc-400 mt-0.5">
            {selectedAlert ? `Flow: ${selectedAlert.flow_id}` : "Evidence over assumptions"}
          </p>
        </div>
        <span className="text-[10px] font-mono text-zinc-400 bg-zinc-900 border border-zinc-800 px-2 py-0.5 rounded">
          {selectedAlert ? selectedAlert.threat_class : "Live Evidence Stream"}
        </span>
      </div>

      {/* Main 2x2 Grid inside Evidence Panel */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 my-auto">
        {/* 1. Domain Entropy */}
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-3">
          <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400 mb-1">
            <span>Domain Entropy</span>
            <span className="text-emerald-400 font-bold">{entropy.toFixed(2)} / 5.0</span>
          </div>
          {/* Progress Meter Bar */}
          <div className="w-full bg-zinc-800 h-2 rounded-full overflow-hidden mt-2">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                entropy > 3.8 ? "bg-gradient-to-r from-emerald-500 to-amber-500" : "bg-emerald-500"
              }`}
              style={{ width: `${Math.min(100, (entropy / 5.0) * 100)}%` }}
            />
          </div>
          <p className="text-[9px] font-mono text-zinc-400 mt-2">
            {entropy > 3.8 ? "High entropy - possible DGA / Tunneling" : "Normal lexical distribution"}
          </p>
        </div>

        {/* 2. JA3 Fingerprint */}
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-3">
          <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400 mb-1">
            <span>JA3 Fingerprint</span>
            <button
              onClick={handleCopy}
              className="text-zinc-400 hover:text-zinc-200 transition-colors p-0.5"
              title="Copy JA3 Hash"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            </button>
          </div>
          <p className="text-xs font-mono font-medium text-emerald-400 truncate mt-1 bg-zinc-950 px-2 py-1 rounded border border-zinc-800">
            {ja3}
          </p>
          <div className="flex items-center justify-between text-[9px] font-mono text-zinc-400 mt-1.5">
            <span>TLS 1.2 / TLS 1.3</span>
            <span>Ratio: {byteRatio.toFixed(1)}</span>
          </div>
        </div>

        {/* 3. Outbound Ratio (One-Way) */}
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-3 flex items-center space-x-3">
          <div className="relative h-12 w-12 flex items-center justify-center shrink-0">
            <svg className="h-12 w-12 transform -rotate-90" viewBox="0 0 36 36">
              <path
                className="text-zinc-800"
                strokeWidth="3.5"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path
                className="text-emerald-400"
                strokeDasharray="100, 100"
                strokeWidth="3.5"
                strokeLinecap="round"
                stroke="currentColor"
                fill="none"
                d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
              />
            </svg>
            <span className="absolute text-[10px] font-mono font-bold text-zinc-200">100%</span>
          </div>
          <div>
            <h4 className="text-[11px] font-mono font-semibold text-zinc-200">Outbound Ratio</h4>
            <p className="text-[9px] font-mono text-zinc-400 mt-0.5">100% Outbound (to monitor)</p>
            <p className="text-[9px] font-mono text-emerald-400 mt-0.5">0% Inbound (No Egress)</p>
          </div>
        </div>

        {/* 4. Inter-Arrival Time (Flow Analysis) */}
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-3">
          <div className="flex items-center justify-between text-[11px] font-mono text-zinc-400 mb-1">
            <span>Inter-Arrival Time</span>
            <span className="text-zinc-300 font-bold">Var: {iatVar.toFixed(3)}</span>
          </div>
          <div className="h-10 w-full mt-1">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={sparkData}>
                <Area
                  type="monotone"
                  dataKey="v"
                  stroke="#10b981"
                  fill="#10b981"
                  fillOpacity={0.15}
                  strokeWidth={1.5}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Evidence Footer */}
      <div className="border-t border-zinc-800/60 pt-2.5 flex items-center justify-between text-[10px] font-mono text-zinc-400 mt-2">
        <span>Cross-Protocol UID Correlated</span>
        <span className="text-zinc-300">Confidence: {selectedAlert ? `${(selectedAlert.confidence_score * 100).toFixed(0)}%` : "92%"}</span>
      </div>
    </div>
  );
}
