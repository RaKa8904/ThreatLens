import { type CSSProperties, type KeyboardEvent, useEffect, useState } from "react";
import { Navbar } from "@/components/Navbar";
import { ThroughputGauge, TrafficWindow } from "@/components/ThroughputGauge";
import { SystemHealthPanel } from "@/components/SystemHealthPanel";
import { IncidentsPanel } from "@/components/IncidentsPanel";
import { ThreatTrends } from "@/components/ThreatTrends";
import { ThreatTable } from "@/components/ThreatTable";
import { ForensicDrawer } from "@/components/ForensicDrawer";
import { DetectionConfig } from "@/components/DetectionConfig";
import { ReplayModal } from "@/components/ReplayModal";
import { LoginPage, UserProfile } from "@/components/LoginPage";
import { useThreatSocket } from "@/hooks/useThreatSocket";
import { ThreatAlertSchema } from "@/types/threat";
import { getShortThreatName } from "@/lib/threatMapping";
import { AnimatedNumber } from "@/components/AnimatedNumber";
import { motion, AnimatePresence } from "motion/react";
import { useMotionEnabled, motionTokens } from "@/lib/motion";
import { getDevStateOverride } from "@/lib/devState";
import { DashboardSkeleton } from "@/components/DashboardSkeleton";

type SeverityFilter = "critical" | "high" | null;
type AlertViewMode = "live" | "archive";

export function App() {
  const { alerts, status, totalReceived, sessionReceived, formattedArchiveTotal, updateAlertStatus, clearAllAlerts } = useThreatSocket();
  const motionEnabled = useMotionEnabled();
  const devState = getDevStateOverride();
  const effectiveAlerts = devState === "empty" ? [] : alerts;
  const effectiveStatus = devState === "offline" ? "DISCONNECTED" : status;

  const [isInitialLoading, setIsInitialLoading] = useState(true);
  useEffect(() => {
    const timer = setTimeout(() => setIsInitialLoading(false), 300);
    return () => clearTimeout(timer);
  }, []);

  const [lastSeenUtc, setLastSeenUtc] = useState<string>(() => {
    return new Date().toISOString().substring(11, 19) + " UTC";
  });
  useEffect(() => {
    if (effectiveStatus === "CONNECTED" && alerts.length > 0) {
      setLastSeenUtc(new Date().toISOString().substring(11, 19) + " UTC");
    }
  }, [effectiveStatus, alerts.length]);

  const showSkeleton = devState === "loading" || (isInitialLoading && alerts.length === 0);

  const [hasBooted, setHasBooted] = useState(() => {
    try {
      return sessionStorage.getItem("threatlens_booted") === "true";
    } catch {
      return false;
    }
  });
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlertSchema | null>(null);
  const [alertViewMode, setAlertViewMode] = useState<AlertViewMode>("live");
  const [archiveAlerts, setArchiveAlerts] = useState<ThreatAlertSchema[]>([]);
  const [archivePage, setArchivePage] = useState(0);
  const [archiveHasNext, setArchiveHasNext] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>(null);
  const [selectedTrafficWindow, setSelectedTrafficWindow] = useState<TrafficWindow | null>(null);
  const [configOpen, setConfigOpen] = useState(false);
  const [replayOpen, setReplayOpen] = useState(false);
  const [user, setUser] = useState<UserProfile | null>(() => {
    try {
      // Require explicit session login on new tab / browser window open so login page renders first
      const savedUser = sessionStorage.getItem("threatlens_user");
      const token = sessionStorage.getItem("threatlens_token");
      return savedUser && token ? JSON.parse(savedUser) : null;
    } catch {
      return null;
    }
  });

  useEffect(() => {
    if (alertViewMode !== "archive") return;

    if (devState === "archive-error") {
      setArchiveAlerts([]);
      setArchiveHasNext(false);
      return;
    }

    let mounted = true;
    fetch(`/api/alerts?limit=51&offset=${archivePage * 50}`)
      .then((response) => (response.ok ? response.json() : Promise.reject(new Error("archive request failed"))))
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

    return () => {
      mounted = false;
    };
  }, [alertViewMode, archivePage, devState]);

  // Compute summary stats from buffered alerts
  const criticalCount = effectiveAlerts.filter((a) => a.severity === "critical").length;
  const highCount = effectiveAlerts.filter((a) => a.severity === "high").length;
  const avgConfidence =
    effectiveAlerts.length > 0
      ? (effectiveAlerts.reduce((sum, a) => sum + a.confidence_score, 0) / effectiveAlerts.length) * 100
      : 0;

  const [prevCriticalCount, setPrevCriticalCount] = useState(criticalCount);
  const [showCriticalPulse, setShowCriticalPulse] = useState(false);

  useEffect(() => {
    if (!hasBooted && user) {
      sessionStorage.setItem("threatlens_booted", "true");
      setHasBooted(true);
    }
  }, [user, hasBooted]);

  useEffect(() => {
    if (criticalCount > prevCriticalCount) {
      setShowCriticalPulse(true);
      const timer = setTimeout(() => setShowCriticalPulse(false), 600);
      setPrevCriticalCount(criticalCount);
      return () => clearTimeout(timer);
    }
    setPrevCriticalCount(criticalCount);
  }, [criticalCount, prevCriticalCount]);

  const handleLogout = () => {
    sessionStorage.removeItem("threatlens_token");
    sessionStorage.removeItem("threatlens_user");
    localStorage.removeItem("threatlens_token");
    localStorage.removeItem("threatlens_user");
    sessionStorage.removeItem("threatlens_booted");
    setUser(null);
  };

  // If user is not authenticated in this session, render dedicated full-screen SOC Login Page!
  // Placed AFTER all hooks are called so React's Hook rules are never violated.
  if (!user || devState === "session-expired") {
    return (
      <LoginPage
        onLoginSuccess={(_token, userProfile) => {
          setUser(userProfile);
        }}
      />
    );
  }

  const bootVariants = {
    hidden: { opacity: 0, y: 8 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.4, ease: motionTokens.easing.standard } },
  };

  const isBooting = motionEnabled && !hasBooted;

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
    const dominantAlert = effectiveAlerts.find((alert) => alert.threat_class === topVector);
    if (dominantAlert) setSelectedAlert(dominantAlert);
  };

  const handleDominantVectorKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openDominantVector();
    }
  };

  // Identify top threat category
  const classCounts = effectiveAlerts.reduce<Record<string, number>>((acc, a) => {
    acc[a.threat_class] = (acc[a.threat_class] || 0) + 1;
    return acc;
  }, {});
  const topVectorEntry = Object.entries(classCounts).sort((a, b) => b[1] - a[1])[0];
  const topVector = topVectorEntry ? topVectorEntry[0] : "None Detected";
  const typeScale = {
    "--text-display": "2.5rem",
    "--text-heading": "1.25rem",
    "--text-body": "0.875rem",
    "--text-label": "0.6875rem",
    "--text-mono": "0.875rem",
  } as CSSProperties;

  return (
    <div style={typeScale} className="min-h-screen bg-[var(--bg-base)] text-zinc-100 flex flex-col font-sans selection:bg-emerald-500/20 selection:text-emerald-300">
      {/* Top SOC Navbar */}
      <Navbar
        status={effectiveStatus}
        totalAlerts={totalReceived}
        sessionReceived={sessionReceived}
        formattedArchiveTotal={formattedArchiveTotal}
        user={user}
        onLogout={handleLogout}
        onOpenConfig={user?.role === "SOC_ADMIN" ? () => setConfigOpen(true) : undefined}
        onOpenReplay={user?.role === "SOC_ADMIN" ? () => setReplayOpen(true) : undefined}
        onClearDB={user?.role === "SOC_ADMIN" ? clearAllAlerts : undefined}
      />

      {/* Inline Connection Degradation Warning Band */}
      {effectiveStatus !== "CONNECTED" && (
        <div
          role="status"
          aria-live="polite"
          className="w-full bg-amber-500/10 border-b border-amber-500/30 px-6 py-1.5 flex items-center justify-between text-xs font-mono text-amber-300"
        >
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="motion-safe:animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500"></span>
            </span>
            <span>Connection lost. Showing data as of {lastSeenUtc}. Reconnecting…</span>
          </div>
          <span className="text-[10px] text-amber-400/80 uppercase tracking-wider font-semibold">
            Passive Buffer Active
          </span>
        </div>
      )}

      {/* Main SOC Dashboard Viewport */}
      {showSkeleton ? (
        <main className="flex-1 px-6 py-4 xl:px-8 xl:py-4 max-w-[2000px] mx-auto w-full flex flex-col gap-4 [&>*]:min-w-0">
          <DashboardSkeleton />
        </main>
      ) : (
        <motion.main 
          initial={isBooting ? "hidden" : "visible"}
          animate="visible"
          variants={{
            visible: { transition: { staggerChildren: 0.15, delayChildren: 0.1 } }
          }}
          className="flex-1 px-6 py-4 xl:px-8 xl:py-4 max-w-[2000px] mx-auto w-full flex flex-col gap-4 [&>*]:min-w-0"
        >
          <motion.div variants={bootVariants} className="grid grid-cols-1 lg:grid-cols-[1.4fr_1fr_1fr_1.2fr] border-b border-[var(--hairline)] py-4 gap-0">
            {/* Card 1: Critical Threats (Dominant) */}
            <div
              role="button"
              tabIndex={0}
              aria-pressed={severityFilter === "critical"}
              onClick={() => toggleSeverityFilter("critical")}
              onKeyDown={(event) => handleSeverityCardKeyDown(event, "critical")}
              className={`flex flex-col cursor-pointer transition-opacity pr-6 lg:pr-8 border-r border-transparent lg:border-[var(--hairline)] ${severityFilter === "critical" ? "opacity-100" : "opacity-90 hover:opacity-100"}`}
            >
              <p className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-widest mb-2 opacity-80 h-[16px]">Critical / Live Buffer</p>
              <div className={`relative text-[length:var(--text-display)] font-bold tabular-nums leading-none tracking-tight h-[40px] flex items-end ${criticalCount > 0 ? "text-[var(--severity-critical)]" : "text-[var(--text-muted)]"}`}>
                <AnimatedNumber value={criticalCount} />
                <AnimatePresence>
                  {showCriticalPulse && motionEnabled && (
                    <motion.div
                      initial={{ opacity: 1 }}
                      animate={{ opacity: 0 }}
                      exit={{ opacity: 0 }}
                      transition={{ duration: 0.6, ease: "easeOut" }}
                      className="absolute bottom-0 left-0 right-0 h-[2px] bg-[var(--severity-critical)]"
                    />
                  )}
                </AnimatePresence>
              </div>
              <p className="text-[length:var(--text-label)] text-[var(--text-secondary)] tracking-wider opacity-60 mt-2 h-[16px]">of <AnimatedNumber value={effectiveAlerts.length} /> total alerts</p>
            </div>

            {/* Card 2: High Severity */}
            <div
              role="button"
              tabIndex={0}
              aria-pressed={severityFilter === "high"}
              onClick={() => toggleSeverityFilter("high")}
              onKeyDown={(event) => handleSeverityCardKeyDown(event, "high")}
              className={`flex flex-col cursor-pointer transition-opacity px-6 lg:px-8 border-r border-transparent lg:border-[var(--hairline)] ${severityFilter === "high" ? "opacity-100" : "opacity-90 hover:opacity-100"}`}
            >
              <p className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-widest mb-2 opacity-80 h-[16px]">High / Live Buffer</p>
              <div className={`text-[length:var(--text-display)] font-bold tabular-nums leading-none tracking-tight h-[40px] flex items-end ${highCount > 0 ? "text-[var(--severity-high)]" : "text-[var(--text-muted)]"}`}><AnimatedNumber value={highCount} /></div>
              <p className="text-[length:var(--text-label)] text-[var(--text-secondary)] tracking-wider opacity-60 mt-2 h-[16px]">of <AnimatedNumber value={effectiveAlerts.length} /> total alerts</p>
            </div>

            {/* Card 3: Avg Confidence */}
            <div className="flex flex-col px-6 lg:px-8 border-r border-transparent lg:border-[var(--hairline)]">
              <p className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-widest mb-2 opacity-80 h-[16px]">Mean Confidence</p>
              <div className="text-[length:var(--text-display)] font-bold tabular-nums leading-none tracking-tight text-[var(--text-primary)] h-[40px] flex items-end"><AnimatedNumber value={avgConfidence} format={(v) => v.toFixed(1) + "%"} /></div>
              <p className="text-[length:var(--text-label)] text-[var(--text-secondary)] tracking-wider opacity-60 mt-2 h-[16px]">across {effectiveAlerts.length ? 6 : 0} detectors</p>
            </div>

            {/* Card 4: Top Vector */}
            <div
              role="button"
              tabIndex={topVectorEntry ? 0 : -1}
              aria-label={topVectorEntry ? `Inspect dominant vector ${topVector}` : "No dominant vector available"}
              aria-disabled={!topVectorEntry}
              onClick={openDominantVector}
              onKeyDown={handleDominantVectorKeyDown}
              title={topVectorEntry ? topVector : undefined}
              className={`flex flex-col pl-6 lg:pl-8 ${topVectorEntry ? "cursor-pointer transition-opacity opacity-90 hover:opacity-100" : ""}`}
            >
              <p className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-widest mb-2 opacity-80 h-[16px]">Dominant Vector</p>
              <div className="text-[length:var(--text-heading)] font-bold text-[var(--text-primary)] leading-none truncate h-[40px] flex items-end">{topVectorEntry ? getShortThreatName(topVector) : "None Detected"}</div>
              <p className="text-[length:var(--text-label)] text-[var(--text-secondary)] tracking-wider opacity-60 mt-2 h-[16px]">{topVectorEntry ? `${topVectorEntry[1]} live detections` : "awaiting telemetry"}</p>
            </div>
          </motion.div>

          <motion.div variants={bootVariants} className="border border-[var(--hairline)] rounded-md flex flex-col xl:grid xl:grid-cols-[5fr_7fr]">
            <div className="min-w-0 p-5 border-b xl:border-b-0 xl:border-r border-[var(--hairline)]">
              <ThroughputGauge
                onWindowSelect={handleTrafficWindowSelect}
              />
            </div>
            <div className="min-w-0 p-5">
              <SystemHealthPanel />
            </div>
          </motion.div>

          <motion.div variants={bootVariants} className="flex flex-col xl:grid xl:grid-cols-[7fr_5fr] gap-4 xl:h-[220px]">
            <div className="min-w-0 h-[220px] xl:h-full flex flex-col">
              <ThreatTrends alerts={effectiveAlerts} />
            </div>
            <div className="min-w-0 h-[220px] xl:h-full flex flex-col overflow-hidden">
              <IncidentsPanel />
            </div>
          </motion.div>

          {/* Live Threat Alert Stream Table */}
          <motion.div variants={bootVariants} className="mt-2 flex flex-col flex-1 min-h-0">
            <ThreatTable
              alerts={alertViewMode === "live" ? effectiveAlerts : archiveAlerts}
              onSelectAlert={(alert) => setSelectedAlert(alert)}
              selectedAlert={selectedAlert}
              severityFilter={severityFilter}
              viewMode={alertViewMode}
              onViewModeChange={setAlertMode}
              archivePage={archivePage}
              archiveHasNext={archiveHasNext}
              onArchivePageChange={setArchivePage}
              onAlertStatusChange={user?.role === "SOC_ADMIN" ? async (flowId, nextStatus) => {
                const response = await fetch(`/api/alerts/${encodeURIComponent(flowId)}/status?status=${nextStatus}`, { method: "PATCH" });
                if (!response.ok) throw new Error("status update failed");
                updateAlertStatus(flowId, nextStatus);
              } : undefined}
              timeWindowTimestamp={selectedTrafficWindow?.timestamp ?? null}
              onClearTimeWindow={() => setSelectedTrafficWindow(null)}
              onClearSeverityFilter={() => setSeverityFilter(null)}
            />
          </motion.div>
        </motion.main>
      )}

      {/* Slide-over Forensic Dossier Drawer */}
      <ForensicDrawer
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />

      {/* Slide-over Detection Configuration & Rule Management */}
      <DetectionConfig open={configOpen} onOpenChange={setConfigOpen} />

      {/* Automated PCAP Replay & On-Demand Forensics Modal */}
      <ReplayModal open={replayOpen} onOpenChange={setReplayOpen} />

      {/* Global Footer */}
      <footer className="border-t border-[var(--hairline)] bg-[var(--bg-base)] px-6 py-2.5 text-center text-[10px] font-mono text-[var(--text-secondary)]">
        THREATLENS ENCLAVE v1.0.0 — ZERO-TRANSMIT PASSIVE NETWORK FORENSICS &amp; STREAMING PIPELINE
      </footer>
    </div>
  );
}

export default App;
