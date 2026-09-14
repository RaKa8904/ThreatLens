import { type KeyboardEvent, useState } from "react";
import {
  Alert02Icon as Alert02,
  Shield01Icon as ShieldSecurity,
  FingerPrintIcon as Fingerprint,
} from "hugeicons-react";
import { Navbar } from "@/components/Navbar";
import { ThroughputGauge, TrafficWindow } from "@/components/ThroughputGauge";
import { SystemHealthPanel } from "@/components/SystemHealthPanel";
import { ThreatTrends } from "@/components/ThreatTrends";
import { ThreatTable } from "@/components/ThreatTable";
import { ForensicDrawer } from "@/components/ForensicDrawer";
import { Card, CardContent } from "@/components/ui/card";
import { useThreatSocket } from "@/hooks/useThreatSocket";
import { ThreatAlertSchema } from "@/types/threat";

type SeverityFilter = "critical" | "high" | null;

export function App() {
  const { alerts, status, totalReceived } = useThreatSocket();
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlertSchema | null>(null);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>(null);
  const [selectedTrafficWindow, setSelectedTrafficWindow] = useState<TrafficWindow | null>(null);

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

  return (
    <div className="min-h-screen bg-[#070a14] text-zinc-100 flex flex-col font-sans selection:bg-emerald-500/20 selection:text-emerald-300">
      {/* Top SOC Navbar */}
      <Navbar
        status={status}
        totalAlerts={totalReceived}
      />

      {/* Main SOC Dashboard Viewport */}
      <main className="flex-1 p-4 md:p-6 space-y-4 max-w-[1600px] w-full mx-auto">
        {/* KPI Alert Summary Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Card 1: Critical Threats */}
          <Card
            role="button"
            tabIndex={0}
            aria-pressed={severityFilter === "critical"}
            onClick={() => toggleSeverityFilter("critical")}
            onKeyDown={(event) => handleSeverityCardKeyDown(event, "critical")}
            className={`cursor-pointer border-zinc-800/80 bg-[#090d16]/80 backdrop-blur-xl transition-colors hover:border-rose-500/50 ${
              severityFilter === "critical" ? "border-rose-500/70 bg-rose-950/20" : ""
            }`}
          >
            <CardContent className="p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase text-zinc-400">Critical Threats</p>
                <div className="text-xl font-bold font-mono text-rose-400 mt-0.5">
                  {criticalCount}
                </div>
              </div>
              <div className="h-8 w-8 rounded-md bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
                <Alert02 className="h-4 w-4" />
              </div>
            </CardContent>
          </Card>

          {/* Card 2: High Severity */}
          <Card
            role="button"
            tabIndex={0}
            aria-pressed={severityFilter === "high"}
            onClick={() => toggleSeverityFilter("high")}
            onKeyDown={(event) => handleSeverityCardKeyDown(event, "high")}
            className={`cursor-pointer border-zinc-800/80 bg-[#090d16]/80 backdrop-blur-xl transition-colors hover:border-amber-500/50 ${
              severityFilter === "high" ? "border-amber-500/70 bg-amber-950/20" : ""
            }`}
          >
            <CardContent className="p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase text-zinc-400">High Severity</p>
                <div className="text-xl font-bold font-mono text-amber-400 mt-0.5">
                  {highCount}
                </div>
              </div>
              <div className="h-8 w-8 rounded-md bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
                <ShieldSecurity className="h-4 w-4" />
              </div>
            </CardContent>
          </Card>

          {/* Card 3: Avg Confidence */}
          <Card className="border-zinc-800/80 bg-[#090d16]/80 backdrop-blur-xl">
            <CardContent className="p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase text-zinc-400">Mean Confidence</p>
                <div className="text-xl font-bold font-mono text-emerald-300 mt-0.5">
                  {avgConfidence.toFixed(1)}%
                </div>
              </div>
              <div className="h-8 w-8 rounded-md bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                <Fingerprint className="h-4 w-4" />
              </div>
            </CardContent>
          </Card>

          {/* Card 4: Top Vector */}
          <Card
            role="button"
            tabIndex={topVectorEntry ? 0 : -1}
            aria-label={topVectorEntry ? `Inspect dominant vector ${topVector}` : "No dominant vector available"}
            aria-disabled={!topVectorEntry}
            onClick={openDominantVector}
            onKeyDown={handleDominantVectorKeyDown}
            className={`border-zinc-800/80 bg-[#090d16]/80 backdrop-blur-xl ${
              topVectorEntry ? "cursor-pointer transition-colors hover:border-purple-500/50" : ""
            }`}
          >
            <CardContent className="p-3.5 flex items-center justify-between">
              <div className="overflow-hidden pr-1">
                <p className="text-[10px] font-mono uppercase text-zinc-400">Dominant Vector</p>
                <div className="text-xs font-semibold font-mono text-zinc-200 mt-1 truncate">
                  {topVector}
                </div>
              </div>
              <div className="h-8 w-8 rounded-md bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 shrink-0">
                <span className="font-mono text-xs font-bold">TOP</span>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Real-time Throughput and Telemetry Gauge */}
        <ThroughputGauge
          totalAlerts={totalReceived}
          selectedWindow={selectedTrafficWindow}
          onWindowSelect={handleTrafficWindowSelect}
        />

        <SystemHealthPanel />

        <ThreatTrends />

        {/* Live Threat Alert Stream Table */}
        <ThreatTable
          alerts={alerts}
          onSelectAlert={(alert) => setSelectedAlert(alert)}
          selectedAlert={selectedAlert}
          severityFilter={severityFilter}
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
