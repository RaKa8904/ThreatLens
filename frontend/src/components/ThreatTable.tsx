import { useEffect, useRef, useState } from "react";
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
import { AlertStatusEnum, ThreatAlertSchema, ThreatClassEnum } from "@/types/threat";
import { formatTimestamp } from "@/lib/utils";

interface ThreatTableProps {
  alerts: ThreatAlertSchema[];
  onSelectAlert: (alert: ThreatAlertSchema) => void;
  selectedAlert: ThreatAlertSchema | null;
  severityFilter?: "critical" | "high" | null;
  timeWindowTimestamp?: number | null;
  onClearTimeWindow?: () => void;
  viewMode?: "live" | "archive";
  onViewModeChange?: (mode: "live" | "archive") => void;
  archivePage?: number;
  archiveHasNext?: boolean;
  onArchivePageChange?: (page: number) => void;
  onAlertStatusChange?: (flowId: string, status: AlertStatusEnum) => Promise<void>;
}

export function ThreatTable({
  alerts,
  onSelectAlert,
  selectedAlert,
  severityFilter = null,
  timeWindowTimestamp = null,
  onClearTimeWindow,
  viewMode = "live",
  onViewModeChange,
  archivePage = 0,
  archiveHasNext = false,
  onArchivePageChange,
  onAlertStatusChange,
}: ThreatTableProps) {
  const [selectedClass, setSelectedClass] = useState<string>("ALL");
  const [minConfidence, setMinConfidence] = useState<number>(0.0);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [statusUpdating, setStatusUpdating] = useState<string | null>(null);
  const [freshAlerts, setFreshAlerts] = useState<Set<string>>(new Set());
  const knownAlertsRef = useRef<Set<string> | null>(null);
  const freshTimeoutsRef = useRef<Map<string, number>>(new Map());

  const getAlertKey = (alert: ThreatAlertSchema) => `${alert.flow_id}-${alert.timestamp}`;

  useEffect(() => {
    const currentKeys = new Set(alerts.map(getAlertKey));
    if (knownAlertsRef.current === null) {
      knownAlertsRef.current = currentKeys;
      return;
    }
    const newKeys = [...currentKeys].filter((key) => !knownAlertsRef.current?.has(key));
    if (newKeys.length) {
      setFreshAlerts((current) => new Set([...current, ...newKeys]));
      newKeys.forEach((key) => {
        const timeout = window.setTimeout(() => {
          setFreshAlerts((current) => {
            const next = new Set(current);
            next.delete(key);
            return next;
          });
          freshTimeoutsRef.current.delete(key);
        }, 950);
        freshTimeoutsRef.current.set(key, timeout);
      });
    }
    knownAlertsRef.current = currentKeys;
  }, [alerts]);

  useEffect(() => () => {
    freshTimeoutsRef.current.forEach((timeout) => window.clearTimeout(timeout));
  }, []);

  const getSeverityBadge = (score: number) => {
    if (score >= 0.85) {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
          CRITICAL ({(score * 100).toFixed(0)}%)
        </span>
      );
    }
    if (score >= 0.70) {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
          HIGH ({(score * 100).toFixed(0)}%)
        </span>
      );
    }
    if (score >= 0.50) {
      return (
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
          MODERATE ({(score * 100).toFixed(0)}%)
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-zinc-700/30 text-zinc-400 border border-zinc-700/40">
        LOW ({(score * 100).toFixed(0)}%)
      </span>
    );
  };

  const getConfidenceProgressBar = (score: number) => {
    const width = Math.min(100, Math.max(5, Math.round(score * 100)));
    let barColor = "bg-zinc-500";
    if (score >= 0.85) barColor = "bg-rose-500";
    else if (score >= 0.70) barColor = "bg-amber-500";
    else if (score >= 0.50) barColor = "bg-yellow-500";

    return (
      <div className="w-[70px] bg-zinc-800 rounded-full h-1 overflow-hidden">
        <div
          className={`h-full ${barColor} transition-all duration-300`}
          style={{ width: `${width}%` }}
        />
      </div>
    );
  };

  const getEvidenceTags = (alert: ThreatAlertSchema) => {
    const tags: string[] = [];
    const evidence = alert.evidence;
    if (evidence.ja3_hash || evidence.ja4_hash || evidence.sni) tags.push("TLS");
    if (evidence.splt_packet_sizes || evidence.splt_interarrival_times) tags.push("SPLT");
    if (evidence.fft_concentration !== null && evidence.fft_concentration !== undefined) tags.push("FFT");
    if (evidence.dns_query || evidence.ngram_score !== null && evidence.ngram_score !== undefined) tags.push("DNS");
    if (evidence.z_score !== null && evidence.z_score !== undefined) tags.push("Z-SCORE");
    if (evidence.unique_destination_hosts !== null && evidence.unique_destination_hosts !== undefined) tags.push("FAN-OUT");
    if (evidence.total_uploaded_bytes !== null && evidence.total_uploaded_bytes !== undefined) tags.push("EGRESS");
    return tags;
  };

  // Filter alerts
  const filteredAlerts = alerts.filter((alert) => {
    if (timeWindowTimestamp !== null) {
      const alertTimestamp = new Date(alert.timestamp).getTime();
      if (Math.abs(alertTimestamp - timeWindowTimestamp) > 5000) return false;
    }

    if (severityFilter === "critical" && alert.confidence_score < 0.85) return false;
    if (severityFilter === "high" && (alert.confidence_score < 0.70 || alert.confidence_score >= 0.85)) return false;

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
    <div className="rounded-xl border border-zinc-800/80 bg-[#090d16]/80 backdrop-blur-xl overflow-hidden flex flex-col">
      {/* Table Filter Controls Header */}
      <div className="p-3 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-3 bg-[#090d16]">
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono font-semibold text-zinc-300 uppercase tracking-wider">
            {viewMode === "live" ? "Live Stream" : "Archive REST"}
          </span>
          <Badge variant="outline" className="font-mono text-[10px] text-zinc-400 border-zinc-700">
            {filteredAlerts.length} / {alerts.length} {viewMode === "live" ? "Live Buffer" : "Archive Page"}
          </Badge>
          <div className="flex items-center gap-1">
            <Button
              variant="outline"
              size="sm"
              onClick={() => onViewModeChange?.("live")}
              className={`h-6 px-2 text-[10px] font-mono ${viewMode === "live" ? "border-emerald-500/50 text-emerald-300" : "border-zinc-800 text-zinc-500"}`}
            >
              LIVE WS
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => onViewModeChange?.("archive")}
              className={`h-6 px-2 text-[10px] font-mono ${viewMode === "archive" ? "border-cyan-500/50 text-cyan-300" : "border-zinc-800 text-zinc-500"}`}
            >
              ARCHIVE REST
            </Button>
          </div>
          {viewMode === "archive" && (
            <div className="flex items-center gap-1 font-mono text-[10px] text-zinc-500">
              <Button variant="outline" size="sm" disabled={archivePage === 0} onClick={() => onArchivePageChange?.(Math.max(0, archivePage - 1))} className="h-6 px-2 text-[10px]">PREV</Button>
              <span>PAGE {archivePage + 1}</span>
              <Button variant="outline" size="sm" disabled={!archiveHasNext} onClick={() => onArchivePageChange?.(archivePage + 1)} className="h-6 px-2 text-[10px]">NEXT</Button>
            </div>
          )}
          {timeWindowTimestamp !== null && (
            <Button
              variant="outline"
              size="sm"
              onClick={onClearTimeWindow}
              className="h-6 px-2 text-[10px] font-mono border-cyan-500/40 text-cyan-300"
            >
              WINDOW {new Date(timeWindowTimestamp).toISOString().substring(11, 19)} ×
            </Button>
          )}
        </div>

        {/* Filter controls */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Search box */}
          <input
            type="text"
            placeholder="Filter IP or keywords..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-7 px-2.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-200 placeholder:text-zinc-500 font-mono text-xs focus:outline-none focus:border-zinc-700 w-44"
          />

          {/* Class Filter Dropdown */}
          <select
            value={selectedClass}
            onChange={(e) => setSelectedClass(e.target.value)}
            className="h-7 px-2 rounded bg-zinc-900 border border-zinc-800 text-zinc-200 font-mono text-xs focus:outline-none focus:border-zinc-700"
          >
            <option value="ALL">All Threat Vectors</option>
            {Object.values(ThreatClassEnum).map((cls) => (
              <option key={cls} value={cls}>
                {cls}
              </option>
            ))}
          </select>

          {/* Confidence Slider Filter */}
          <div className="flex items-center space-x-1.5 px-2 py-1 rounded bg-zinc-900 border border-zinc-800 font-mono text-[11px] text-zinc-400">
            <span>Min Conf:</span>
            <span className="text-emerald-400 font-semibold">{minConfidence.toFixed(2)}</span>
            <input
              type="range"
              min="0.0"
              max="0.95"
              step="0.05"
              value={minConfidence}
              onChange={(e) => setMinConfidence(parseFloat(e.target.value))}
              className="w-16 accent-emerald-400 cursor-pointer"
            />
          </div>
        </div>
      </div>

      {/* Main Table */}
      <div className="overflow-y-auto max-h-[520px]">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent border-b border-zinc-800/80">
              <TableHead className="w-36 text-zinc-500 font-mono text-[length:var(--text-label)]">TIMESTAMP (UTC)</TableHead>
              <TableHead className="min-w-[220px] text-zinc-500 font-mono text-[length:var(--text-label)]">CANONICAL FLOW (SRC → DST)</TableHead>
              <TableHead className="w-48 text-zinc-500 font-mono text-[length:var(--text-label)]">THREAT CLASS</TableHead>
              <TableHead className="w-40 text-zinc-500 font-mono text-[length:var(--text-label)]">SEVERITY / CONFIDENCE</TableHead>
              <TableHead className="w-32 text-zinc-500 font-mono text-[length:var(--text-label)]">STATUS</TableHead>
              <TableHead className="text-right w-24 text-zinc-500 font-mono text-[length:var(--text-label)]">ACTIONS</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredAlerts.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6} className="h-32 text-center text-zinc-500 font-mono">
                  {alerts.length === 0
                    ? "Awaiting network flow telemetry stream..."
                    : "No alerts match active filters."}
                </TableCell>
              </TableRow>
            ) : (
              filteredAlerts.map((alert, idx) => {
                const isSelected = selectedAlert?.flow_id === alert.flow_id && selectedAlert?.timestamp === alert.timestamp;
                const alertKey = getAlertKey(alert);
                return (
                  <TableRow
                    key={`${alert.flow_id}-${alert.timestamp}-${idx}`}
                    onClick={() => onSelectAlert(alert)}
                    className={`transition-colors duration-1000 border-b border-zinc-800/40 cursor-pointer ${freshAlerts.has(alertKey) && viewMode === "live" ? "bg-emerald-500/[0.12]" : ""} ${
                      isSelected
                        ? "bg-zinc-800/90 border-emerald-500/40"
                        : "hover:bg-zinc-900/60"
                    }`}
                  >
                    {/* Timestamp */}
                    <TableCell title={formatTimestamp(alert.timestamp)} className="font-mono text-zinc-400 text-[11px] whitespace-nowrap">
                      {formatTimestamp(alert.timestamp).substring(11, 23)}
                    </TableCell>

                    {/* Canonical Flow */}
                    <TableCell className="font-mono text-zinc-200 text-xs">
                      <div className="flex items-center space-x-1.5">
                        <span className="text-emerald-400 font-medium">
                          {alert.flow_id.split("->")[0] || alert.flow_id}
                        </span>
                        <span className="text-zinc-500">→</span>
                        <span className="text-zinc-300">
                          {alert.flow_id.split("->")[1] || ""}
                        </span>
                      </div>
                    </TableCell>

                    {/* Threat Class */}
                    <TableCell className="font-medium text-zinc-200 font-sans text-xs">
                      <div>{alert.threat_class}</div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {getEvidenceTags(alert).map((tag) => (
                          <span key={tag} className="rounded border border-cyan-500/20 bg-cyan-500/[0.06] px-1 py-0.5 text-[9px] font-mono text-cyan-300">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </TableCell>

                    {/* Confidence & Severity */}
                    <TableCell>
                      <div className="flex items-center space-x-2">
                        {getSeverityBadge(alert.confidence_score)}
                        {getConfidenceProgressBar(alert.confidence_score)}
                      </div>
                    </TableCell>

                    <TableCell>
                      <select
                        value={alert.status ?? AlertStatusEnum.NEW}
                        disabled={!onAlertStatusChange || statusUpdating === getAlertKey(alert)}
                        onChange={async (event) => {
                          if (!onAlertStatusChange) return;
                          setStatusUpdating(getAlertKey(alert));
                          try {
                            await onAlertStatusChange(alert.flow_id, event.target.value as AlertStatusEnum);
                          } finally {
                            setStatusUpdating(null);
                          }
                        }}
                        className="h-7 max-w-32 rounded border border-zinc-800 bg-zinc-900 px-1.5 text-[10px] font-mono text-zinc-300"
                        aria-label={`Status for ${alert.flow_id}`}
                      >
                        {Object.values(AlertStatusEnum).map((statusOption) => <option key={statusOption} value={statusOption}>{statusOption.replace("_", " ")}</option>)}
                      </select>
                    </TableCell>

                    {/* Action */}
                    <TableCell className="text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(alert);
                        }}
                        className="h-6 text-[10px] px-2 font-mono border-zinc-800 bg-zinc-900 hover:bg-zinc-800 hover:text-zinc-100"
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
