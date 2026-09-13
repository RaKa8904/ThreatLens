import { useState } from "react";
import { ThreatAlertSchema, ThreatClassEnum } from "@/types/threat";
import { formatTimestamp } from "@/lib/utils";
import { ArrowRight01Icon as ArrowRight } from "hugeicons-react";

interface ThreatTableProps {
  alerts: ThreatAlertSchema[];
  onSelectAlert: (alert: ThreatAlertSchema) => void;
  selectedAlert: ThreatAlertSchema | null;
}

export function ThreatTable({
  alerts,
  onSelectAlert,
  selectedAlert,
}: ThreatTableProps) {
  const [selectedClass, setSelectedClass] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");

  const getSeverityPill = (score: number) => {
    if (score >= 0.85) {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
          Critical
        </span>
      );
    }
    if (score >= 0.70) {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
          High
        </span>
      );
    }
    if (score >= 0.50) {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
          Medium
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
        Low
      </span>
    );
  };

  // Filter alerts
  const filteredAlerts = alerts.filter((alert) => {
    if (selectedClass !== "ALL" && alert.threat_class !== selectedClass) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchFlow = alert.flow_id.toLowerCase().includes(q);
      const matchClass = alert.threat_class.toLowerCase().includes(q);
      const matchDetails = alert.evidence.details.toLowerCase().includes(q);
      if (!matchFlow && !matchClass && !matchDetails) return false;
    }
    return true;
  });

  return (
    <div className="bg-[#090d16] border border-zinc-800/60 rounded-xl p-4 flex flex-col justify-between h-full">
      {/* Title & Filter Header */}
      <div className="flex items-center justify-between border-b border-zinc-800/60 pb-2.5 mb-2">
        <div>
          <h3 className="text-sm font-semibold text-zinc-100 font-sans">Threat Feed</h3>
          <p className="text-[10px] font-mono text-zinc-400 mt-0.5">
            Live from passive sensors • {alerts.length} detections
          </p>
        </div>

        {/* Quick Filter controls */}
        <div className="flex items-center space-x-2 text-xs">
          <input
            type="text"
            placeholder="Search flow or details..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-7 px-2 rounded bg-zinc-900 border border-zinc-800 text-zinc-200 placeholder:text-zinc-500 font-mono text-[11px] focus:outline-none focus:border-zinc-700 w-36"
          />

          <select
            value={selectedClass}
            onChange={(e) => setSelectedClass(e.target.value)}
            className="h-7 px-2 rounded bg-zinc-900 border border-zinc-800 text-zinc-200 font-mono text-[11px] focus:outline-none focus:border-zinc-700"
          >
            <option value="ALL">All Threat Vectors</option>
            {Object.values(ThreatClassEnum).map((cls) => (
              <option key={cls} value={cls}>
                {cls}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Threat Stream List Table */}
      <div className="overflow-y-auto max-h-[220px] my-auto">
        {filteredAlerts.length === 0 ? (
          <div className="py-8 text-center text-xs font-mono text-zinc-500">
            {alerts.length === 0 ? "Awaiting passive network threat stream..." : "No alerts match active filter."}
          </div>
        ) : (
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="text-[10px] text-zinc-400 border-b border-zinc-800/60 uppercase">
                <th className="py-1.5 px-2 font-normal">Severity</th>
                <th className="py-1.5 px-2 font-normal">Threat</th>
                <th className="py-1.5 px-2 font-normal">Confidence</th>
                <th className="py-1.5 px-2 font-normal">Time</th>
                <th className="py-1.5 px-2 font-normal">Details</th>
                <th className="py-1.5 px-2 text-right font-normal">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/40">
              {filteredAlerts.slice(0, 15).map((alert, idx) => {
                const isSelected = selectedAlert?.flow_id === alert.flow_id && selectedAlert?.timestamp === alert.timestamp;
                return (
                  <tr
                    key={`${alert.flow_id}-${alert.timestamp}-${idx}`}
                    onClick={() => onSelectAlert(alert)}
                    className={`cursor-pointer transition-colors ${
                      isSelected ? "bg-zinc-800/80" : "hover:bg-zinc-900/60"
                    }`}
                  >
                    <td className="py-2 px-2 whitespace-nowrap">{getSeverityPill(alert.confidence_score)}</td>
                    <td className="py-2 px-2 font-semibold text-zinc-200 whitespace-nowrap">{alert.threat_class}</td>
                    <td className="py-2 px-2 text-zinc-300 font-bold">{(alert.confidence_score * 100).toFixed(0)}%</td>
                    <td className="py-2 px-2 text-zinc-400 whitespace-nowrap">{formatTimestamp(alert.timestamp).substring(11, 19)}</td>
                    <td className="py-2 px-2 text-zinc-400 truncate max-w-[200px]">{alert.evidence.details}</td>
                    <td className="py-2 px-2 text-right text-zinc-400 hover:text-zinc-100">
                      <ArrowRight className="h-3.5 w-3.5 inline-block" />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
