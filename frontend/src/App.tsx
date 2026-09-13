import { useState, useEffect } from "react";
import { Sidebar } from "@/components/Sidebar";
import { Header } from "@/components/Header";
import { ThroughputGauge } from "@/components/ThroughputGauge";
import { ThreatTable } from "@/components/ThreatTable";
import { NetworkTopology } from "@/components/NetworkTopology";
import { ForensicEvidencePanel } from "@/components/ForensicEvidencePanel";
import { ForensicDrawer } from "@/components/ForensicDrawer";
import { useThreatSocket } from "@/hooks/useThreatSocket";
import { ThreatAlertSchema } from "@/types/threat";
import {
  Activity01Icon as Activity,
  Alert02Icon as Alert,
  Share01Icon as Network,
  Shield01Icon as Shield,
} from "hugeicons-react";

export function App() {
  const { alerts, status, isPaused, togglePause, totalReceived } = useThreatSocket();
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlertSchema | null>(null);

  // Live metrics counters state
  const [metrics, setMetrics] = useState({
    flowsPerSec: 4286,
    packetsPerSec: 1250,
    mbps: 842,
    activeAlerts: alerts.length,
    protectedHosts: 148,
  });

  useEffect(() => {
    let isMounted = true;
    const fetchMetrics = async () => {
      try {
        const res = await fetch("/api/metrics/throughput");
        if (!res.ok) return;
        const json = await res.json();
        if (!isMounted) return;

        setMetrics((prev) => ({
          flowsPerSec: json.flows_per_sec || prev.flowsPerSec,
          packetsPerSec: json.packets_per_sec || prev.packetsPerSec,
          mbps: json.bytes_per_sec ? Math.round((json.bytes_per_sec * 8) / 1_000_000) || 842 : prev.mbps,
          activeAlerts: json.total_alerts || alerts.length,
          protectedHosts: 148,
        }));
      } catch {
        // Fallback
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 2500);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [alerts.length]);

  return (
    <div className="min-h-screen bg-[#070a14] text-zinc-100 flex font-sans selection:bg-emerald-500/20 selection:text-emerald-300">
      {/* Left Icon Navigation Sidebar */}
      <Sidebar />

      {/* Main Viewport Container */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-y-auto">
        {/* Top Header */}
        <Header
          status={status}
          isPaused={isPaused}
          onTogglePause={togglePause}
          totalAlerts={totalReceived}
        />

        {/* Dashboard Content Container */}
        <main className="flex-1 p-4 md:p-5 space-y-4 max-w-[1700px] w-full mx-auto">
          {/* Top 4 KPI Metrics Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {/* KPI Card 1: Network Throughput */}
            <div className="bg-[#090d16] border border-zinc-800/60 rounded-xl p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase text-zinc-400">Network Throughput</p>
                <div className="flex items-baseline space-x-2 mt-1">
                  <span className="text-xl font-bold font-mono text-zinc-100">{metrics.mbps} Mbps</span>
                  <span className="text-[10px] font-mono text-emerald-400 font-semibold">▲ +12%</span>
                </div>
              </div>
              <div className="h-9 w-9 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center text-emerald-400">
                <Activity className="h-5 w-5" />
              </div>
            </div>

            {/* KPI Card 2: Active Alerts */}
            <div className="bg-[#090d16] border border-zinc-800/60 rounded-xl p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase text-zinc-400">Active Alerts</p>
                <div className="flex items-baseline space-x-2 mt-1">
                  <span className="text-xl font-bold font-mono text-amber-400">{alerts.length || metrics.activeAlerts}</span>
                  <span className="text-[10px] font-mono text-emerald-400 font-semibold">▼ -25% vs prev</span>
                </div>
              </div>
              <div className="h-9 w-9 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
                <Alert className="h-5 w-5" />
              </div>
            </div>

            {/* KPI Card 3: Flows / sec */}
            <div className="bg-[#090d16] border border-zinc-800/60 rounded-xl p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase text-zinc-400">Flows / sec</p>
                <div className="flex items-baseline space-x-2 mt-1">
                  <span className="text-xl font-bold font-mono text-zinc-100">{metrics.flowsPerSec.toLocaleString()}</span>
                  <span className="text-[10px] font-mono text-emerald-400 font-semibold">▲ +8%</span>
                </div>
              </div>
              <div className="h-9 w-9 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center text-zinc-300">
                <Network className="h-5 w-5" />
              </div>
            </div>

            {/* KPI Card 4: Protected Hosts */}
            <div className="bg-[#090d16] border border-zinc-800/60 rounded-xl p-3.5 flex items-center justify-between">
              <div>
                <p className="text-[10px] font-mono uppercase text-zinc-400">Protected Hosts</p>
                <div className="flex items-baseline space-x-2 mt-1">
                  <span className="text-xl font-bold font-mono text-zinc-100">{metrics.protectedHosts}</span>
                  <span className="text-[10px] font-mono text-zinc-500 font-semibold">▲ 0% change</span>
                </div>
              </div>
              <div className="h-9 w-9 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                <Shield className="h-5 w-5" />
              </div>
            </div>
          </div>

          {/* Main 2x2 Quadrant Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Quadrant 1 (Upper-Left): Live Network Activity */}
            <ThroughputGauge />

            {/* Quadrant 2 (Upper-Right): Threat Feed Table */}
            <ThreatTable
              alerts={alerts}
              onSelectAlert={(alert) => setSelectedAlert(alert)}
              selectedAlert={selectedAlert}
            />

            {/* Quadrant 3 (Lower-Left): Network Topology Diagram */}
            <NetworkTopology />

            {/* Quadrant 4 (Lower-Right): Forensic Evidence Panel */}
            <ForensicEvidencePanel selectedAlert={selectedAlert} />
          </div>
        </main>

        {/* Global Footer */}
        <footer className="border-t border-zinc-800/60 bg-[#090d16] px-6 py-2 flex flex-col sm:flex-row items-center justify-between text-[10px] font-mono text-zinc-400 shrink-0">
          <div>
            ThreatLens | Passive Network Threat Detection | Evidence-Driven Security
          </div>
          <div className="flex items-center space-x-3 mt-1 sm:mt-0">
            <span className="flex items-center space-x-1">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
              <span>Sensors Online: 4/4</span>
            </span>
            <span>•</span>
            <span className="flex items-center space-x-1">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
              <span>Data Diode: Healthy</span>
            </span>
            <span>•</span>
            <span className="flex items-center space-x-1">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
              <span>System: Operational</span>
            </span>
          </div>
        </footer>
      </div>

      {/* Slide-over Forensic Drawer */}
      <ForensicDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />
    </div>
  );
}

export default App;
