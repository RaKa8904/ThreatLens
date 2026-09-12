import { useState } from "react";
import {
  Alert02Icon as Alert02,
  Shield01Icon as ShieldSecurity,
  FingerPrintIcon as Fingerprint,
} from "hugeicons-react";
import { Navbar } from "@/components/Navbar";
import { ThroughputGauge } from "@/components/ThroughputGauge";
import { ThreatTable } from "@/components/ThreatTable";
import { ForensicDrawer } from "@/components/ForensicDrawer";
import { Card, CardContent } from "@/components/ui/card";
import { useThreatSocket } from "@/hooks/useThreatSocket";
import { ThreatAlertSchema } from "@/types/threat";

export function App() {
  const { alerts, status, isPaused, togglePause, totalReceived } = useThreatSocket();
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlertSchema | null>(null);

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
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Top SOC Navbar */}
      <Navbar
        status={status}
        isPaused={isPaused}
        onTogglePause={togglePause}
        totalAlerts={totalReceived}
      />

      {/* Main SOC Dashboard Viewport */}
      <main className="flex-1 p-4 md:p-6 space-y-4 max-w-[1600px] w-full mx-auto">
        {/* KPI Alert Summary Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Card 1: Critical Threats */}
          <Card className="border-slate-850 bg-slate-900/50 backdrop-blur">
            <CardContent className="p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase text-slate-400">Critical Threats</p>
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
          <Card className="border-slate-850 bg-slate-900/50 backdrop-blur">
            <CardContent className="p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase text-slate-400">High Severity</p>
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
          <Card className="border-slate-850 bg-slate-900/50 backdrop-blur">
            <CardContent className="p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase text-slate-400">Mean Confidence</p>
                <div className="text-xl font-bold font-mono text-cyan-300 mt-0.5">
                  {avgConfidence.toFixed(1)}%
                </div>
              </div>
              <div className="h-8 w-8 rounded-md bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                <Fingerprint className="h-4 w-4" />
              </div>
            </CardContent>
          </Card>

          {/* Card 4: Top Vector */}
          <Card className="border-slate-850 bg-slate-900/50 backdrop-blur">
            <CardContent className="p-3.5 flex items-center justify-between">
              <div className="overflow-hidden pr-1">
                <p className="text-[10px] font-mono uppercase text-slate-400">Dominant Vector</p>
                <div className="text-xs font-semibold font-mono text-slate-200 mt-1 truncate">
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
        <ThroughputGauge totalAlerts={totalReceived} />

        {/* Live Threat Alert Stream Table */}
        <ThreatTable
          alerts={alerts}
          onSelectAlert={(alert) => setSelectedAlert(alert)}
          selectedAlert={selectedAlert}
        />
      </main>

      {/* Slide-over Forensic Dossier Drawer */}
      <ForensicDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />

      {/* Global Footer */}
      <footer className="border-t border-slate-850/80 bg-slate-950 px-6 py-2.5 text-center text-[10px] font-mono text-slate-400">
        THREATLENS ENCLAVE v1.0.0 — ZERO-TRANSMIT PASSIVE NETWORK FORENSICS &amp; STREAMING PIPELINE
      </footer>
    </div>
  );
}

export default App;
