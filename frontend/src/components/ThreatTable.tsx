import { useEffect, useRef, useState } from "react";
import { motion, animate } from "motion/react";
import { useMotionEnabled, motionTokens } from "@/lib/motion";
import { getDevStateOverride } from "@/lib/devState";
import { getShortThreatName } from "@/lib/threatMapping";
import {
  AlertStatusEnum,
  ThreatAlertSchema,
  ThreatClassEnum,
  getAlertIdentity,
  matchesThreatClass,
  normalizeThreatClass,
} from "@/types/threat";
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
  onClearSeverityFilter?: () => void;
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
  onClearSeverityFilter,
}: ThreatTableProps) {
  const [selectedClass, setSelectedClass] = useState<string>("ALL");
  const [minConfidence, setMinConfidence] = useState<number>(0.0);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [statusUpdating, setStatusUpdating] = useState<string | null>(null);
  const [freshAlerts, setFreshAlerts] = useState<Set<string>>(new Set());
  const [animatedFreshAlerts, setAnimatedFreshAlerts] = useState<Set<string>>(new Set());
  const knownAlertsRef = useRef<Set<string> | null>(null);
  const freshTimeoutsRef = useRef<Map<string, number>>(new Map());
  
  const motionEnabled = useMotionEnabled();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const tableBodyRef = useRef<HTMLDivElement>(null);
  const rowRefs = useRef<Array<HTMLDivElement | null>>([]);
  const [isScrolled, setIsScrolled] = useState(false);

  // Stream hover-pause state
  const [isHoveringTable, setIsHoveringTable] = useState(false);
  const [isRowFocused, setIsRowFocused] = useState(false);
  const [ariaAnnouncement, setAriaAnnouncement] = useState<string>("");
  const unpauseTimerRef = useRef<number | null>(null);
  const [pausedSnapshot, setPausedSnapshot] = useState<ThreatAlertSchema[]>(alerts);

  const getAlertKey = (alert: ThreatAlertSchema) => getAlertIdentity(alert);

  const isDrawerOpen = selectedAlert !== null;
  const isDocHidden = typeof document !== "undefined" && document.hidden;
  const isPaused = viewMode === "live" && (isHoveringTable || isRowFocused || dropdownOpen || isDrawerOpen);
  const wasPausedRef = useRef(false);

  // Maintain paused snapshot vs live alerts
  useEffect(() => {
    if (isPaused) {
      if (!wasPausedRef.current) {
        setPausedSnapshot(alerts);
        setAriaAnnouncement("Stream paused");
      }
      wasPausedRef.current = true;
    } else {
      if (wasPausedRef.current) {
        setPausedSnapshot(alerts);
      }
      wasPausedRef.current = false;
    }
  }, [isPaused, alerts]);

  // Count pending new alerts while paused
  const snapshotKeys = new Set(pausedSnapshot.map(getAlertKey));
  const pendingCount = isPaused ? alerts.filter((a) => !snapshotKeys.has(getAlertKey(a))).length : 0;

  const handleResume = () => {
    setIsHoveringTable(false);
    setIsRowFocused(false);
    setPausedSnapshot(alerts);
    setAriaAnnouncement("Stream resumed");
  };

  const handleTableMouseEnter = () => {
    if (unpauseTimerRef.current) {
      window.clearTimeout(unpauseTimerRef.current);
      unpauseTimerRef.current = null;
    }
    setIsHoveringTable(true);
  };

  const handleTableMouseLeave = () => {
    if (unpauseTimerRef.current) {
      window.clearTimeout(unpauseTimerRef.current);
    }
    // 300ms debounce before flushing buffer
    unpauseTimerRef.current = window.setTimeout(() => {
      setIsHoveringTable(false);
      unpauseTimerRef.current = null;
    }, 300);
  };

  const alertsToDisplay = isPaused ? pausedSnapshot : alerts;
  const skipAnimation = !motionEnabled || isScrolled || isDrawerOpen || dropdownOpen || isDocHidden || isPaused;

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
          setAnimatedFreshAlerts((current) => {
            const next = new Set(current);
            next.delete(key);
            return next;
          });
          freshTimeoutsRef.current.delete(key);
        }, 900);
        freshTimeoutsRef.current.set(key, timeout);
      });

      if (!skipAnimation && viewMode === "live") {
        const k = Math.min(newKeys.length, 5);
        const animatedKeys = newKeys.slice(0, k);
        setAnimatedFreshAlerts((current) => new Set([...current, ...animatedKeys]));

        if (tableBodyRef.current) {
          animate(tableBodyRef.current, { y: [-k * 44, 0] }, { duration: 0.2, ease: motionTokens.easing.standard as any });
        }
      }
    }
    knownAlertsRef.current = currentKeys;
  }, [alerts, skipAnimation, viewMode]);

  useEffect(() => () => {
    freshTimeoutsRef.current.forEach((timeout) => window.clearTimeout(timeout));
    if (unpauseTimerRef.current) window.clearTimeout(unpauseTimerRef.current);
  }, []);



  const getEvidenceTags = (alert: ThreatAlertSchema) => {
    const tags: string[] = [];
    const evidence = alert.evidence;
    if (!evidence) return tags;
    if (evidence.ja3_hash || evidence.ja4_hash || evidence.sni) tags.push("TLS");
    if (evidence.splt_packet_sizes || evidence.splt_interarrival_times) tags.push("SPLT");
    if (evidence.fft_concentration !== null && evidence.fft_concentration !== undefined) tags.push("FFT");
    if (evidence.dns_query || (evidence.ngram_score !== null && evidence.ngram_score !== undefined)) tags.push("DNS");
    if (evidence.z_score !== null && evidence.z_score !== undefined) tags.push("Z-SCORE");
    if (evidence.unique_destination_hosts !== null && evidence.unique_destination_hosts !== undefined) tags.push("FAN-OUT");
    if (evidence.total_uploaded_bytes !== null && evidence.total_uploaded_bytes !== undefined) tags.push("EGRESS");
    return tags;
  };

  // Filter alerts
  const devState = getDevStateOverride();
  const filteredAlerts = devState === "filtered-empty" ? [] : alertsToDisplay.filter((alert) => {
    if (timeWindowTimestamp !== null) {
      const alertTimestamp = new Date(alert.timestamp).getTime();
      if (isNaN(alertTimestamp) || Math.abs(alertTimestamp - timeWindowTimestamp) > 5000) return false;
    }

    if (severityFilter === "critical" && String(alert.severity).toLowerCase() !== "critical") return false;
    if (severityFilter === "high" && String(alert.severity).toLowerCase() !== "high") return false;

    if (selectedClass !== "ALL" && !matchesThreatClass(alert.threat_class, selectedClass)) {
      return false;
    }

    const conf = typeof alert.confidence_score === "number" ? alert.confidence_score : parseFloat(String(alert.confidence_score || 0));
    if (conf < minConfidence) return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      const flowStr = String(alert.flow_id || "").toLowerCase();
      const classStr = normalizeThreatClass(alert.threat_class).toLowerCase();
      const detailsStr = String(alert.evidence?.details || "").toLowerCase();
      const srcIpStr = String(alert.source_ip || alert.evidence?.source_ip || "").toLowerCase();
      const dstIpStr = String(alert.destination_ip || alert.evidence?.destination_ip || "").toLowerCase();

      const matches =
        flowStr.includes(q) ||
        classStr.includes(q) ||
        detailsStr.includes(q) ||
        srcIpStr.includes(q) ||
        dstIpStr.includes(q);

      if (!matches) return false;
    }

    return true;
  });

  return (
    <div className="flex flex-col flex-1 min-h-[400px]">
      {/* Table Toolbar */}
      <div className="flex items-center justify-between pb-4 border-b border-[var(--hairline)]">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <h2 className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-widest opacity-80 h-[16px] flex items-center">Live Stream</h2>
            <div className="px-1.5 py-0.5 rounded bg-[var(--bg-surface-hover)] border border-[var(--hairline)] text-[10px] font-mono text-[var(--text-secondary)] tracking-widest">
              {filteredAlerts.length} / {alerts.length}
            </div>
          </div>
          
          <div className="flex bg-[var(--bg-surface)] rounded border border-[var(--hairline)] p-0.5 relative">
            <button
              onClick={() => onViewModeChange?.("live")}
              className={`relative z-10 h-[28px] px-3 rounded-sm text-[10px] font-mono tracking-widest transition-colors ${viewMode === "live" ? "text-[var(--text-primary)]" : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"} flex items-center gap-1.5`}
            >
              {viewMode === "live" && motionEnabled && (
                <motion.div layoutId="viewModePill" className="absolute inset-0 bg-[var(--bg-surface-hover)] rounded-sm shadow-sm" transition={motionTokens.spring.press} />
              )}
              {viewMode === "live" && !motionEnabled && (
                <div className="absolute inset-0 bg-[var(--bg-surface-hover)] rounded-sm shadow-sm" />
              )}
              <span className="relative z-10 flex items-center gap-1.5">
                {viewMode === "live" && <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.5)]" />}
                LIVE WS
              </span>
            </button>
            <button
              onClick={() => onViewModeChange?.("archive")}
              className={`relative z-10 h-[28px] px-3 rounded-sm text-[10px] font-mono tracking-widest transition-colors ${viewMode === "archive" ? "text-[var(--text-primary)]" : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"}`}
            >
              {viewMode === "archive" && motionEnabled && (
                <motion.div layoutId="viewModePill" className="absolute inset-0 bg-[var(--bg-surface-hover)] rounded-sm shadow-sm" transition={motionTokens.spring.press} />
              )}
              {viewMode === "archive" && !motionEnabled && (
                <div className="absolute inset-0 bg-[var(--bg-surface-hover)] rounded-sm shadow-sm" />
              )}
              <span className="relative z-10">ARCHIVE REST</span>
            </button>
          </div>

          {viewMode === "archive" && (
            <div className="flex items-center gap-1 font-mono text-[10px] text-[var(--text-muted)] ml-2">
              <button disabled={archivePage === 0} onClick={() => onArchivePageChange?.(Math.max(0, archivePage - 1))} className="h-[28px] px-2 rounded hover:text-[var(--text-primary)] disabled:opacity-50">PREV</button>
              <span className="px-2">PAGE {archivePage + 1}</span>
              <button disabled={!archiveHasNext} onClick={() => onArchivePageChange?.(archivePage + 1)} className="h-[28px] px-2 rounded hover:text-[var(--text-primary)] disabled:opacity-50">NEXT</button>
            </div>
          )}

          {timeWindowTimestamp !== null && (
            <button
              onClick={onClearTimeWindow}
              className="h-[28px] px-3 ml-2 rounded bg-cyan-500/10 border border-cyan-500/20 text-[10px] font-mono text-cyan-400 tracking-widest flex items-center gap-2 hover:bg-cyan-500/20 transition-colors"
            >
              WINDOW {new Date(timeWindowTimestamp).toISOString().substring(11, 19)} <span className="text-[14px] leading-none">×</span>
            </button>
          )}
        </div>

        <div className="flex items-center gap-3">
          {/* Search */}
          <div className="relative">
            <svg className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-muted)]" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            <input
              type="text"
              placeholder="Search IP, vector..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-[32px] w-[180px] pl-8 pr-3 rounded bg-[var(--bg-base)] border border-[#3f3f46] text-[11px] font-mono text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-emerald-500/50"
            />
          </div>

          {/* Vector filter */}
          <div className="relative">
            <select
              value={selectedClass}
              onChange={(e) => setSelectedClass(e.target.value)}
              className="h-[32px] w-[160px] pl-3 pr-8 rounded bg-[var(--bg-base)] border border-[#3f3f46] text-[11px] font-mono text-[var(--text-primary)] appearance-none focus:outline-none focus:border-emerald-500/50 cursor-pointer"
            >
              <option value="ALL">All Vectors</option>
              {Object.values(ThreatClassEnum).map((cls) => (
                <option key={cls} value={cls}>{cls}</option>
              ))}
            </select>
            <svg className="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-muted)] pointer-events-none" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
          </div>

          {/* Confidence slider */}
          <div className="flex items-center gap-2 h-[32px] px-3 rounded bg-[var(--bg-base)] border border-[#3f3f46] text-[11px] font-mono">
            <span className="text-[var(--text-muted)]">Conf &ge;</span>
            <input
              type="range"
              min="0.0"
              max="0.95"
              step="0.05"
              value={minConfidence}
              onChange={(e) => setMinConfidence(parseFloat(e.target.value))}
              className="w-20 appearance-none h-[2px] bg-[var(--hairline)] rounded-full outline-none [&::-webkit-slider-thumb]:appearance-none [&::-webkit-slider-thumb]:w-3 [&::-webkit-slider-thumb]:h-3 [&::-webkit-slider-thumb]:bg-[var(--text-secondary)] [&::-webkit-slider-thumb]:rounded-full cursor-pointer"
            />
            <span className="text-[var(--text-primary)] min-w-[3ch]">{(minConfidence * 100).toFixed(0)}%</span>
          </div>

          {(selectedClass !== "ALL" || minConfidence > 0 || searchQuery.trim() !== "" || severityFilter !== null || timeWindowTimestamp !== null) && (
            <motion.button
              whileTap={{ scale: 0.97 }}
              transition={motionTokens.spring.press as any}
              onClick={() => {
                setSelectedClass("ALL");
                setMinConfidence(0.0);
                setSearchQuery("");
                if (onClearTimeWindow) onClearTimeWindow();
                if (onClearSeverityFilter) onClearSeverityFilter();
              }}
              className="h-[32px] px-3 rounded border border-[#3f3f46] bg-[var(--bg-base)] text-[10px] font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-surface-hover)] transition-colors duration-150"
            >
              CLEAR
            </motion.button>
          )}
        </div>
      </div>

      {/* Main Table */}
      <div
        className="flex-1 overflow-auto mt-4 min-h-0 relative border-t border-transparent"
        onScroll={(e) => setIsScrolled(e.currentTarget.scrollTop > 10)}
        onMouseEnter={handleTableMouseEnter}
        onMouseLeave={handleTableMouseLeave}
      >
        <div aria-live="polite" className="sr-only">
          {ariaAnnouncement}
        </div>

        <div className="min-w-[1080px]">
          <div className="sticky top-0 bg-[var(--bg-base)] z-10 border-b border-[var(--hairline)] grid grid-cols-[104px_minmax(300px,520px)_minmax(220px,380px)_104px_140px_124px_88px] justify-between gap-x-4 px-4 py-3">
            <div className="text-[length:var(--text-label)] font-mono text-[var(--text-muted)] font-normal uppercase tracking-wider whitespace-nowrap">Time</div>
            <div className="text-[length:var(--text-label)] font-mono text-[var(--text-muted)] font-normal uppercase tracking-wider whitespace-nowrap">Flow (Src → Dst)</div>
            <div className="text-[length:var(--text-label)] font-mono text-[var(--text-muted)] font-normal uppercase tracking-wider whitespace-nowrap">Threat Class</div>
            <div className="text-[length:var(--text-label)] font-mono text-[var(--text-muted)] font-normal uppercase tracking-wider whitespace-nowrap">Severity</div>
            <div className="text-[length:var(--text-label)] font-mono text-[var(--text-muted)] font-normal uppercase tracking-wider whitespace-nowrap">Confidence</div>
            <div className="text-[length:var(--text-label)] font-mono text-[var(--text-muted)] font-normal uppercase tracking-wider whitespace-nowrap">Status</div>
            <div className="text-[length:var(--text-label)] font-mono text-[var(--text-muted)] font-normal uppercase tracking-wider whitespace-nowrap text-right">Action</div>
          </div>

          {/* Pinned Hover Pause Banner */}
          {isPaused && pendingCount > 0 && (
            <div className="sticky top-[45px] z-20 flex items-center justify-between px-4 h-[32px] bg-[var(--bg-surface)] border-b border-[var(--hairline)] text-[length:var(--text-label)] font-mono text-[var(--text-secondary)] shadow-sm">
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-[var(--live-accent)] motion-safe:animate-pulse" />
                <span>
                  {pendingCount > 99 ? "99+" : pendingCount} new alert{pendingCount === 1 ? "" : "s"} · Stream paused
                </span>
              </div>
              <button
                type="button"
                onClick={handleResume}
                className="px-2.5 py-0.5 rounded border border-[var(--hairline)] bg-[var(--bg-base)] text-[length:var(--text-label)] text-[var(--text-primary)] hover:bg-[var(--bg-surface-hover)] focus:outline-none focus:ring-2 focus:ring-emerald-500/80 transition-colors"
              >
                Resume
              </button>
            </div>
          )}
          
          {/* Body */}
          <motion.div 
            ref={tableBodyRef} 
            className="flex flex-col divide-y divide-[var(--hairline)]"
            key={`${selectedClass}-${minConfidence}-${searchQuery}-${severityFilter}`}
            initial={motionEnabled ? { opacity: 0 } : false}
            animate={motionEnabled ? { opacity: 1 } : false}
            transition={{ duration: 0.12, ease: "easeOut" }}
          >
            {filteredAlerts.length === 0 ? (
              <div className="h-40 flex flex-col items-center justify-center gap-3">
                <span className="text-[14px] text-[var(--text-secondary)]">
                  {alerts.length === 0
                    ? "Waiting for telemetry"
                    : severityFilter
                    ? `No ${severityFilter} alerts in the current ${alerts.length}-alert buffer`
                    : "No alerts match these filters"}
                </span>
                {alerts.length > 0 && (
                  <button
                    onClick={() => {
                      if (severityFilter && onClearSeverityFilter) {
                        onClearSeverityFilter();
                      } else {
                        setSelectedClass("ALL");
                        setMinConfidence(0.0);
                        setSearchQuery("");
                        if (onClearTimeWindow) onClearTimeWindow();
                      }
                    }}
                    className="px-3 py-1.5 rounded border border-[#3f3f46] bg-[var(--bg-base)] text-[12px] text-[var(--text-primary)] hover:bg-[var(--bg-surface-hover)] transition-colors focus:outline-none focus:ring-2 focus:ring-emerald-500"
                  >
                    {severityFilter ? "Clear severity filter" : "Clear filters"}
                  </button>
                )}
              </div>
            ) : (
              filteredAlerts.map((alert, idx) => {
                const isSelected = selectedAlert?.flow_id === alert.flow_id && selectedAlert?.timestamp === alert.timestamp;
                const alertKey = getAlertKey(alert);
                const isFresh = freshAlerts.has(alertKey) && viewMode === "live";
                const isAnimated = animatedFreshAlerts.has(alertKey);

                // Severity colors for bars and pills
                const severityColors: Record<string, string> = {
                  critical: "var(--severity-critical)",
                  high: "var(--severity-high)",
                  moderate: "var(--severity-moderate)",
                  low: "var(--severity-low)",
                };
                const sevKey = alert.severity?.toLowerCase() || "info";
                const sevHex = severityColors[sevKey] || severityColors.low;

                // Split flow IPs and ports
                const [src, dst] = alert.flow_id.split("->").map(s => s.trim());
                const formatIP = (ipPort: string) => {
                  const parts = ipPort.split(":");
                  if (parts.length > 1) {
                    return <><span className="text-[var(--text-primary)]">{parts.slice(0, -1).join(":")}</span><span className="text-[var(--text-muted)]">:{parts[parts.length - 1]}</span></>;
                  }
                  return <span className="text-[var(--text-primary)]">{ipPort}</span>;
                };

                // Confidence map to 0-100 width
                const confScore = typeof alert.confidence_score === "number" ? alert.confidence_score : parseFloat(String(alert.confidence_score || 0));
                const confPct = Math.round(confScore * 100);
                const barWidth = confPct;

                // Tags
                const tags = getEvidenceTags(alert);

                // Status
                const status = (alert.status ?? AlertStatusEnum.NEW).toLowerCase();
                const statusDots: Record<string, string> = {
                  new: "bg-rose-500",
                  acknowledged: "bg-sky-500",
                  investigating: "bg-purple-500",
                  resolved: "bg-emerald-500",
                  false_positive: "bg-zinc-500",
                };
                const dotColor = status !== "new" && statusDots[status] ? statusDots[status] : "bg-transparent";

                return (
                  <motion.div
                    key={alertKey}
                    ref={(el) => { rowRefs.current[idx] = el; }}
                    tabIndex={0}
                    role="row"
                    aria-selected={isSelected}
                    onFocus={() => setIsRowFocused(true)}
                    onBlur={() => setIsRowFocused(false)}
                    onClick={() => onSelectAlert(alert)}
                    onKeyDown={(e) => {
                      if (e.key === "ArrowDown") {
                        e.preventDefault();
                        rowRefs.current[idx + 1]?.focus();
                      } else if (e.key === "ArrowUp") {
                        e.preventDefault();
                        rowRefs.current[idx - 1]?.focus();
                      } else if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onSelectAlert(alert);
                      }
                    }}
                    initial={motionEnabled ? {
                      ...(isAnimated ? { opacity: 0, y: -6 } : {}),
                      backgroundColor: isFresh ? "rgba(16, 185, 129, 0.12)" : "rgba(0,0,0,0)"
                    } : {}}
                    animate={motionEnabled ? {
                      ...(isAnimated ? { opacity: 1, y: 0 } : {}),
                      backgroundColor: "rgba(0,0,0,0)"
                    } : {}}
                    whileHover={motionEnabled ? { backgroundColor: "var(--bg-surface-hover)" } : {}}
                    transition={motionEnabled ? {
                      opacity: { duration: 0.18, ease: "easeOut" },
                      y: { duration: 0.18, ease: motionTokens.easing.standard },
                      backgroundColor: { duration: isFresh ? 0.9 : 0.12, ease: "easeOut" }
                    } : { duration: 0 }}
                    className={`group h-[44px] cursor-pointer relative grid grid-cols-[104px_minmax(300px,520px)_minmax(220px,380px)_104px_140px_124px_88px] justify-between gap-x-4 px-4 items-center focus:outline-none focus:ring-2 focus:ring-emerald-500/80 focus:ring-offset-1 focus:ring-offset-[var(--bg-base)] ${
                      !motionEnabled ? (isSelected ? "bg-[var(--bg-surface-hover)]" : isFresh ? "bg-emerald-500/[0.12]" : "bg-transparent hover:bg-[var(--bg-surface-hover)] transition-colors duration-150") : (isSelected ? "bg-[var(--bg-surface-hover)]" : "")
                    }`}
                  >
                    {/* Left edge severity bar */}
                    <div className="absolute left-0 top-0 bottom-0 w-[2px]" style={{ backgroundColor: sevHex }} />

                    {/* Time */}
                    <div className="font-mono text-[length:var(--text-body)] text-[var(--text-secondary)] tabular-nums whitespace-nowrap">
                      {formatTimestamp(alert.timestamp).substring(11, 23)}
                    </div>

                    {/* Flow */}
                    <div className="font-mono text-[length:var(--text-body)] truncate whitespace-nowrap" title={alert.flow_id}>
                      <div className="flex items-center gap-2 truncate">
                        <span className="truncate">{src ? formatIP(src) : "Unknown"}</span>
                        <svg className="w-3 h-3 text-[var(--text-muted)] shrink-0" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"></line><polyline points="12 5 19 12 12 19"></polyline></svg>
                        <span className="truncate">{dst ? formatIP(dst) : "Unknown"}</span>
                      </div>
                    </div>

                    {/* Threat Class */}
                    <div className="flex items-center gap-2 text-[var(--text-primary)] text-[length:var(--text-body)] min-w-0" title={alert.threat_class}>
                      <span className="hidden xl:inline truncate">{alert.threat_class}</span>
                      <span className="xl:hidden inline truncate">{getShortThreatName(alert.threat_class)}</span>
                      {tags.length > 0 && (
                        <span className="shrink-0 px-1.5 py-[1px] rounded bg-[var(--bg-surface)] border border-[var(--hairline)] text-[9px] font-mono text-[var(--text-secondary)]">
                          {tags[0]}
                        </span>
                      )}
                    </div>

                    {/* Severity */}
                    <div className="flex items-center h-full">
                      <span
                        className="inline-flex items-center justify-center h-[20px] px-2 rounded-[2px] text-[10px] font-mono tracking-widest leading-none pt-[1px]"
                        style={{ backgroundColor: `color-mix(in srgb, ${sevHex} 12%, transparent)`, color: sevHex }}
                      >
                        {alert.severity ? alert.severity.toUpperCase() : "INFO"}
                      </span>
                    </div>

                    {/* Confidence */}
                    <div className="flex items-center gap-2" title={`Confidence: ${confPct}%`}>
                      <span className="font-mono text-[length:var(--text-body)] text-[var(--text-primary)] tabular-nums text-right w-[40px] shrink-0">{confPct}%</span>
                      <div className="w-[64px] h-[4px] rounded-full bg-[var(--hairline)] overflow-hidden shrink-0">
                        <div className="h-full" style={{ width: `${barWidth}%`, backgroundColor: sevHex }} />
                      </div>
                    </div>

                    {/* Status */}
                    <div onClick={(e) => e.stopPropagation()} className="relative shrink-0">
                      <motion.select
                        whileTap={{ scale: 0.97 }}
                        transition={motionTokens.spring.press as any}
                        value={alert.status ?? AlertStatusEnum.NEW}
                        disabled={!onAlertStatusChange || statusUpdating === getAlertKey(alert)}
                        onFocus={() => setDropdownOpen(true)}
                        onBlur={() => setDropdownOpen(false)}
                        onChange={async (event) => {
                          if (!onAlertStatusChange) return;
                          setStatusUpdating(getAlertKey(alert));
                          try {
                            await onAlertStatusChange(alert.flow_id, event.target.value as AlertStatusEnum);
                          } finally {
                            setStatusUpdating(null);
                          }
                        }}
                        className={`w-full h-[28px] pl-2 pr-6 rounded border border-[#3f3f46] text-[10px] font-mono uppercase appearance-none cursor-pointer focus:outline-none focus:border-[var(--text-secondary)] disabled:opacity-50 transition-colors bg-[var(--bg-base)] ${status !== "new" ? "text-[var(--text-primary)]" : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"}`}
                      >
                        {Object.values(AlertStatusEnum).map((s) => (
                          <option key={s} value={s} className="bg-[var(--bg-base)]">{s.replace("_", " ")}</option>
                        ))}
                      </motion.select>
                      <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1.5 pointer-events-none">
                        {status !== "new" && <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />}
                        <svg className="w-3 h-3 text-[var(--text-muted)]" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
                      </div>
                    </div>

                    {/* Action */}
                    <div className="text-right shrink-0">
                      <motion.button
                        whileTap={{ scale: 0.97 }}
                        transition={motionTokens.spring.press as any}
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(alert);
                        }}
                        className="h-[28px] px-3 rounded border border-[#3f3f46] bg-[var(--bg-base)] text-[10px] font-mono tracking-widest text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-zinc-500 transition-colors duration-150 focus:outline-none"
                      >
                        INSPECT
                      </motion.button>
                    </div>
                  </motion.div>
                );
              })
            )}
          </motion.div>
        </div>
      </div>
    </div>
  );
}
