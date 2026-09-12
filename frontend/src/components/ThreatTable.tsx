import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ThreatAlertSchema, ThreatClassEnum } from "@/types/threat";
import { formatTimestamp } from "@/lib/utils";

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
  const [minConfidence, setMinConfidence] = useState<number>(0.0);
  const [searchQuery, setSearchQuery] = useState<string>("");

  const getSeverityBadge = (score: number) => {
    if (score >= 0.85) {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-red-500/10 text-red-400 border border-red-500/30">
          CRITICAL ({(score * 100).toFixed(0)}%)
        </span>
      );
    }
    if (score >= 0.70) {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/30">
          HIGH ({(score * 100).toFixed(0)}%)
        </span>
      );
    }
    if (score >= 0.50) {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-yellow-500/10 text-yellow-400 border border-yellow-500/30">
          MEDIUM ({(score * 100).toFixed(0)}%)
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/30">
        LOW ({(score * 100).toFixed(0)}%)
      </span>
    );
  };

  const getConfidenceProgressBar = (score: number) => {
    const width = Math.min(100, Math.max(5, Math.round(score * 100)));
    let barColor = "bg-blue-500";
    if (score >= 0.85) barColor = "bg-rose-500";
    else if (score >= 0.70) barColor = "bg-amber-500";
    else if (score >= 0.50) barColor = "bg-yellow-500";

    return (
      <div className="w-24 bg-slate-800 rounded-full h-1.5 overflow-hidden">
        <div
          className={`h-full ${barColor} transition-all duration-300`}
          style={{ width: `${width}%` }}
        />
      </div>
    );
  };

  // Filter alerts
  const filteredAlerts = alerts.filter((alert) => {
    if (selectedClass !== "ALL") {
      const clsStr =
        typeof alert.threat_class === "string"
          ? alert.threat_class
          : alert.threat_class;
      if (clsStr !== selectedClass) return false;
    }

    if (alert.confidence_score < minConfidence) return false;

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
    <div className="rounded-lg border border-slate-800/80 bg-slate-900/40 backdrop-blur-xl overflow-hidden flex flex-col">
      {/* Table Filter Controls Header */}
      <div className="p-3 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/60">
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
            Live Stream
          </span>
          <Badge variant="outline" className="font-mono text-[10px] text-slate-400 border-slate-700">
            {filteredAlerts.length} / {alerts.length} Displayed
          </Badge>
        </div>

        {/* Filter controls */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Search box */}
          <input
            type="text"
            placeholder="Filter IP or keywords..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-7 px-2.5 rounded bg-slate-900 border border-slate-800 text-slate-200 placeholder:text-slate-500 font-mono text-xs focus:outline-none focus:border-cyan-500/70 w-44"
          />

          {/* Class Filter Dropdown */}
          <select
            value={selectedClass}
            onChange={(e) => setSelectedClass(e.target.value)}
            className="h-7 px-2 rounded bg-slate-900 border border-slate-800 text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500/70"
          >
            <option value="ALL">All Threat Vectors</option>
            {Object.values(ThreatClassEnum).map((cls) => (
              <option key={cls} value={cls}>
                {cls}
              </option>
            ))}
          </select>

          {/* Confidence Slider Filter */}
          <div className="flex items-center space-x-1.5 px-2 py-1 rounded bg-slate-900 border border-slate-800 font-mono text-[11px] text-slate-400">
            <span>Min Conf:</span>
            <span className="text-cyan-400 font-semibold">{minConfidence.toFixed(2)}</span>
            <input
              type="range"
              min="0.0"
              max="0.95"
              step="0.05"
              value={minConfidence}
              onChange={(e) => setMinConfidence(parseFloat(e.target.value))}
              className="w-16 accent-cyan-400 cursor-pointer"
            />
          </div>
        </div>
      </div>

      {/* Main Table */}
      <div className="overflow-y-auto max-h-[520px]">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="w-36">TIMESTAMP (UTC)</TableHead>
              <TableHead className="min-w-[220px]">CANONICAL FLOW (SRC → DST)</TableHead>
              <TableHead className="w-48">THREAT CLASS</TableHead>
              <TableHead className="w-40">SEVERITY / CONFIDENCE</TableHead>
              <TableHead className="text-right w-24">ACTIONS</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredAlerts.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={5} className="h-32 text-center text-slate-500 font-mono">
                  {alerts.length === 0
                    ? "Awaiting network flow telemetry stream..."
                    : "No alerts match active filters."}
                </TableCell>
              </TableRow>
            ) : (
              filteredAlerts.map((alert, idx) => {
                const isSelected = selectedAlert?.flow_id === alert.flow_id && selectedAlert?.timestamp === alert.timestamp;
                return (
                  <TableRow
                    key={`${alert.flow_id}-${alert.timestamp}-${idx}`}
                    onClick={() => onSelectAlert(alert)}
                    className={`transition-colors ${
                      isSelected
                        ? "bg-slate-800/80 border-cyan-500/40"
                        : "hover:bg-slate-850/40"
                    }`}
                  >
                    {/* Timestamp */}
                    <TableCell className="font-mono text-slate-400 text-[11px] whitespace-nowrap">
                      {formatTimestamp(alert.timestamp).substring(11, 19)}
                    </TableCell>

                    {/* Canonical Flow */}
                    <TableCell className="font-mono text-slate-200 text-xs">
                      <div className="flex items-center space-x-1.5">
                        <span className="text-cyan-300 font-medium">
                          {alert.flow_id.split("->")[0] || alert.flow_id}
                        </span>
                        <span className="text-slate-500">→</span>
                        <span className="text-slate-300">
                          {alert.flow_id.split("->")[1] || ""}
                        </span>
                      </div>
                    </TableCell>

                    {/* Threat Class */}
                    <TableCell className="font-medium text-slate-200">
                      {alert.threat_class}
                    </TableCell>

                    {/* Confidence & Severity */}
                    <TableCell>
                      <div className="flex items-center space-x-2">
                        {getSeverityBadge(alert.confidence_score)}
                        {getConfidenceProgressBar(alert.confidence_score)}
                      </div>
                    </TableCell>

                    {/* Action */}
                    <TableCell className="text-right">
                      <Button
                        variant="subtle"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(alert);
                        }}
                        className="h-6 text-[10px] px-2 font-mono hover:text-cyan-400 hover:border-cyan-500/40"
                      >
                        INSPECT
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
