import { type CSSProperties, type KeyboardEvent, useEffect, useState } from "react";
import { Navbar } from "@/components/Navbar";
import { ThroughputGauge, TrafficWindow } from "@/components/ThroughputGauge";
import { SystemHealthPanel } from "@/components/SystemHealthPanel";
import { IncidentsPanel } from "@/components/IncidentsPanel";
import { ThreatTrends } from "@/components/ThreatTrends";
import { ThreatTable } from "@/components/ThreatTable";
import { ForensicDrawer } from "@/components/ForensicDrawer";
import { useThreatSocket } from "@/hooks/useThreatSocket";
import { ThreatAlertSchema } from "@/types/threat";

type SeverityFilter = "critical" | "high" | null;
type AlertViewMode = "live" | "archive";

export function App() {
  const { alerts, status, totalReceived, updateAlertStatus } = useThreatSocket();
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlertSchema | null>(null);
  const [alertViewMode, setAlertViewMode] = useState<AlertViewMode>("live");
  const [archiveAlerts, setArchiveAlerts] = useState<ThreatAlertSchema[]>([]);
  const [archivePage, setArchivePage] = useState(0);
  const [archiveHasNext, setArchiveHasNext] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>(null);
  const [selectedTrafficWindow, setSelectedTrafficWindow] = useState<TrafficWindow | null>(null);

  useEffect(() => {
    if (alertViewMode !== "archive") return;

    let mounted = true;
    fetch(`/api/alerts?limit=51&offset=${archivePage * 50}`)
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("archive request failed")))
      .then((data: ThreatAlertSchema[]) => {
        if (!mounted) return;
        setArchiveAlerts(data.slice(0, 50));
        setArchiveHasNext(data.length > 50);
      })
      .catch(() => {
        if (!mounted) return;
        setArchiveAlerts([]);
        setArchiveHasNext(false);
      });

    return () => { mounted = false; };
  }, [alertViewMode, archivePage]);

  const setAlertMode = (mode: AlertViewMode) => {
    setAlertViewMode(mode);
    if (mode === "archive") setArchivePage(0);
  };

  const toggleSeverityFilter = (filter: Exclude<SeverityFilter, null>) => {
    setSeverityFilter((current) => (current === filter ? null : filter));
  };

  const handleSeverityCardKeyDown = (
    event: KeyboardEvent<HTMLDivElement>,
    filter: Exclude<SeverityFilter, null>,
  ) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggleSeverityFilter(filter);
    }
  };

  const handleTrafficWindowSelect = (window: TrafficWindow) => {
    setSelectedTrafficWindow((current) => (current?.timestamp === window.timestamp ? null : window));
  };

  const openDominantVector = () => {
    if (!topVectorEntry) return;
    const dominantAlert = alerts.find((alert) => alert.threat_class === topVector);
    if (dominantAlert) setSelectedAlert(dominantAlert);
  };

  const handleDominantVectorKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openDominantVector();
    }
  };

  // Compute summary stats from buffered alerts
  const criticalCount = alerts.filter((a) => a.confidence_score >= 0.85).length;
  const highCount = alerts.filter((a) => a.confidence_score >= 0.70 && a.confidence_score < 0.85).length;
  const avgConfidence = alerts.length > 0
    ? (alerts.reduce((sum, a) => sum + a.confidence_score, 0) / alerts.length) * 100
    : 0;

  // Identify top threat category
  const classCounts = alerts.reduce<Record<string, number>>((acc, a) => {
    acc[a.threat_class] = (acc[a.threat_class] || 0) + 1;
    return acc;
  }, {});
  const topVectorEntry = Object.entries(classCounts).sort((a, b) => b[1] - a[1])[0];
  const topVector = topVectorEntry ? topVectorEntry[0] : "None Detected";
  const typeScale = {
    "--text-display": "1.5rem",
    "--text-heading": "0.75rem",
    "--text-body": "0.75rem",
    "--text-label": "0.625rem",
  } as CSSProperties;

  return (
    <div style={typeScale} className="min-h-screen bg-[#070a14] text-zinc-100 flex flex-col font-sans selection:bg-emerald-500/20 selection:text-emerald-300">
      {/* Top SOC Navbar */}
      <Navbar
        status={status}
        totalAlerts={totalReceived}
      />

      {/* Main SOC Dashboard Viewport */}
      <main className="flex-1 p-4 md:p-6 space-y-4 max-w-[1600px] w-full mx-auto">
        {/* KPI Alert Summary Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 divide-x divide-zinc-800/70">
          {/* Card 1: Critical Threats */}
          <div
            role="button"
            tabIndex={0}
            aria-pressed={severityFilter === "critical"}
            onClick={() => toggleSeverityFilter("critical")}
            onKeyDown={(event) => handleSeverityCardKeyDown(event, "critical")}
            className={`cursor-pointer px-3 py-1 transition-colors hover:bg-rose-500/[0.04] ${severityFilter === "critical" ? "bg-rose-500/[0.06]" : ""}`}
          >
            <p className="text-[length:var(--text-label)] font-mono uppercase text-zinc-500">Critical / Live Buffer</p>
            <div className={`text-[length:var(--text-display)] font-bold font-mono tabular-nums ${criticalCount > 0 ? "text-rose-400" : "text-zinc-600"}`}>{criticalCount}</div>
            <p className="text-[length:var(--text-label)] font-mono text-zinc-600">of {alerts.length} total alerts</p>
          </div>

          {/* Card 2: High Severity */}
          <div
            role="button"
            tabIndex={0}
            aria-pressed={severityFilter === "high"}
            onClick={() => toggleSeverityFilter("high")}
            onKeyDown={(event) => handleSeverityCardKeyDown(event, "high")}
            className={`cursor-pointer px-3 py-1 transition-colors hover:bg-amber-500/[0.04] ${severityFilter === "high" ? "bg-amber-500/[0.06]" : ""}`}
          >
            <p className="text-[length:var(--text-label)] font-mono uppercase text-zinc-500">High / Live Buffer</p>
            <div className="text-[length:var(--text-display)] font-bold font-mono tabular-nums text-amber-400">{highCount}</div>
            <p className="text-[length:var(--text-label)] font-mono text-zinc-600">of {alerts.length} total alerts</p>
          </div>

          {/* Card 3: Avg Confidence */}
          <div className="px-3 py-1">
            <p className="text-[length:var(--text-label)] font-mono uppercase text-zinc-500">Mean Confidence</p>
            <div className="text-[length:var(--text-display)] font-bold font-mono tabular-nums text-emerald-300">{avgConfidence.toFixed(1)}%</div>
            <p className="text-[length:var(--text-label)] font-mono text-zinc-600">across {alerts.length ? 6 : 0} detectors</p>
          </div>

          {/* Card 4: Top Vector */}
          <div
            role="button"
            tabIndex={topVectorEntry ? 0 : -1}
            aria-label={topVectorEntry ? `Inspect dominant vector ${topVector}` : "No dominant vector available"}
            aria-disabled={!topVectorEntry}
            onClick={openDominantVector}
            onKeyDown={handleDominantVectorKeyDown}
            className={`px-3 py-1 ${topVectorEntry ? "cursor-pointer transition-colors hover:bg-violet-500/[0.04]" : ""}`}
          >
            <p className="text-[length:var(--text-label)] font-mono uppercase text-zinc-500">Dominant Vector</p>
            <div className="text-[length:var(--text-body)] font-semibold font-mono text-zinc-200 mt-1 truncate">{topVector}</div>
            <p className="text-[length:var(--text-label)] font-mono text-zinc-600">{topVectorEntry ? `${topVectorEntry[1]} live detections` : "awaiting telemetry"}</p>
          </div>
        </div>

        {/* Real-time Throughput and Telemetry Gauge */}
        <ThroughputGauge
          totalAlerts={totalReceived}
          selectedWindow={selectedTrafficWindow}
          onWindowSelect={handleTrafficWindowSelect}
        />

        <SystemHealthPanel />

        <ThreatTrends alerts={alerts} />

        <IncidentsPanel />

        {/* Live Threat Alert Stream Table */}
        <ThreatTable
          alerts={alertViewMode === "live" ? alerts : archiveAlerts}
          onSelectAlert={(alert) => setSelectedAlert(alert)}
          selectedAlert={selectedAlert}
          severityFilter={severityFilter}
          viewMode={alertViewMode}
          onViewModeChange={setAlertMode}
          archivePage={archivePage}
          archiveHasNext={archiveHasNext}
          onArchivePageChange={setArchivePage}
          onAlertStatusChange={async (flowId, nextStatus) => {
            const response = await fetch(`/api/alerts/${encodeURIComponent(flowId)}/status?status=${nextStatus}`, { method: "PATCH" });
            if (!response.ok) throw new Error("status update failed");
            updateAlertStatus(flowId, nextStatus);
          }}
          timeWindowTimestamp={selectedTrafficWindow?.timestamp ?? null}
          onClearTimeWindow={() => setSelectedTrafficWindow(null)}
        />
      </main>

      {/* Slide-over Forensic Dossier Drawer */}
      <ForensicDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />

      {/* Global Footer */}
      <footer className="border-t border-zinc-800/80 bg-[#090d16] px-6 py-2.5 text-center text-[10px] font-mono text-zinc-400">
        THREATLENS ENCLAVE v1.0.0 — ZERO-TRANSMIT PASSIVE NETWORK FORENSICS &amp; STREAMING PIPELINE
      </footer>
    </div>
  );
}

export default App;
