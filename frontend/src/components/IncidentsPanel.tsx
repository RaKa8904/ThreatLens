import { useEffect, useState } from "react";
import { ArrowDown01Icon as ChevronDown, Shield01Icon as ShieldSecurity } from "hugeicons-react";
import { getShortThreatName } from "@/lib/threatMapping";

interface Incident {
  incident_id: string;
  source_ip?: string | null;
  first_seen: string;
  last_seen: string;
  threat_classes: string[];
  alerts: Array<{ flow_id: string; confidence_score: number }>;
}

function extractCleanIp(raw: string): string {
  if (!raw) return "";
  const trimmed = raw.trim();
  if (trimmed.includes(":") && !trimmed.includes("::")) {
    return trimmed.split(":")[0];
  }
  return trimmed;
}

function formatErrorDetail(detail: any): string {
  if (!detail) return "Server error while creating suppression rule.";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((d) => d.msg || d.detail || JSON.stringify(d)).join(", ");
  }
  if (typeof detail === "object") {
    return detail.msg || detail.detail || detail.message || JSON.stringify(detail);
  }
  return String(detail);
}

export function IncidentsPanel() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [suppressedIps, setSuppressedIps] = useState<Set<string>>(new Set());
  const [feedbackMsg, setFeedbackMsg] = useState<string | null>(null);

  // Custom suppression confirmation modal states
  const [modalOpen, setModalOpen] = useState(false);
  const [targetIp, setTargetIp] = useState("");
  const [description, setDescription] = useState("Direct suppression from SOC Incidents Table");
  const [modalLoading, setModalLoading] = useState(false);
  const [modalError, setModalError] = useState<string | null>(null);

  const [isOpen, setIsOpen] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem("threatlens_incidents_panel_open");
      return saved !== null ? saved === "true" : true;
    } catch {
      return true;
    }
  });

  const toggleOpen = () => {
    setIsOpen((prev) => {
      const next = !prev;
      try {
        localStorage.setItem("threatlens_incidents_panel_open", String(next));
      } catch {
        // ignore
      }
      return next;
    });
  };

  useEffect(() => {
    let mounted = true;
    const loadRules = () => {
      fetch("/api/config/suppressions")
        .then((res) => (res.ok ? res.json() : []))
        .then((rules: any[]) => {
          if (!mounted) return;
          const active = new Set(
            rules.filter((r) => r.enabled && r.source_ip).map((r) => String(r.source_ip))
          );
          setSuppressedIps(active);
        })
        .catch(() => {});
    };

    loadRules();
    const refresh = () =>
      fetch("/api/incidents?limit=20")
        .then((response) => (response.ok ? response.json() : Promise.reject(new Error("incident request failed"))))
        .then((data: Incident[]) => {
          if (mounted) setIncidents(data);
        })
        .catch(() => {
          if (mounted) setIncidents([]);
        });
    refresh();
    const interval = window.setInterval(refresh, 5000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

  // Keyboard shortcut for modal (Escape closes)
  useEffect(() => {
    if (!modalOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !modalLoading) {
        setModalOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [modalOpen, modalLoading]);

  const openSuppressModal = (sourceIp: string, event: React.MouseEvent) => {
    event.stopPropagation();
    if (!sourceIp || sourceIp === "Unknown source") return;
    const clean = extractCleanIp(sourceIp);
    setTargetIp(clean);
    setDescription("Direct suppression from SOC Incidents Table");
    setModalError(null);
    setModalOpen(true);
  };

  const handleConfirmSuppress = async (e: React.FormEvent) => {
    e.preventDefault();
    const ip = targetIp.trim();
    if (!ip) {
      setModalError("Please provide a valid source IP address.");
      return;
    }

    setModalLoading(true);
    setModalError(null);

    try {
      const res = await fetch("/api/config/suppressions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          rule_type: "source_ip",
          source_ip: ip,
          description: description.trim() || "Direct suppression from SOC Incidents Table",
          enabled: true,
        }),
      });

      if (res.ok) {
        setSuppressedIps((prev) => new Set([...prev, ip]));
        setFeedbackMsg(`Suppressed ${ip}`);
        setModalOpen(false);
        setTimeout(() => setFeedbackMsg(null), 3500);
      } else {
        const err = await res.json().catch(() => ({}));
        setModalError(formatErrorDetail(err.detail));
      }
    } catch (err) {
      console.error("Suppression request error:", err);
      setModalError("Network error: Failed to communicate with suppression service.");
    } finally {
      setModalLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full border-t xl:border-t-0 border-[var(--hairline)] pt-6 xl:pt-0">
      <div
        role="button"
        tabIndex={0}
        aria-expanded={isOpen}
        aria-label={isOpen ? "Hide incident section" : "Show incident section"}
        onClick={toggleOpen}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            toggleOpen();
          }
        }}
        className="flex items-center justify-between cursor-pointer select-none pb-3 border-b border-[var(--hairline)] hover:opacity-80 transition-opacity xl:cursor-default xl:pointer-events-none"
      >
        <div className="flex items-center gap-3">
          <h2 className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-widest opacity-80 h-[16px] flex items-center">
            Incidents
          </h2>
          {incidents.length > 0 && (
            <span className="rounded bg-[var(--bg-surface-hover)] px-2 py-0.5 font-mono text-[10px] text-[var(--text-primary)] border border-[var(--hairline)]">
              {incidents.length} active
            </span>
          )}
          {feedbackMsg && (
            <span className="rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 font-mono text-[9px] motion-safe:animate-fade-in">
              {feedbackMsg}
            </span>
          )}
        </div>
        <ChevronDown
          className={`h-4 w-4 transition-transform duration-300 text-[var(--text-secondary)] xl:hidden ${
            isOpen ? "rotate-180" : "rotate-0"
          }`}
        />
      </div>

      <div className={`flex flex-col overflow-y-auto pr-1 flex-1 ${!isOpen ? "hidden xl:flex" : "flex"}`}>
        {incidents.length === 0 && (
          <div className="font-mono text-[length:var(--text-label)] text-[var(--text-muted)] italic mt-4">
            No correlated incidents.
          </div>
        )}
        {incidents.map((incident) => {
          const firstSeenStr = new Date(incident.first_seen).toISOString().substring(11, 16);
          const lastSeenStr = new Date(incident.last_seen).toISOString().substring(11, 16);
          const timeStr = firstSeenStr === lastSeenStr ? firstSeenStr : `${firstSeenStr} - ${lastSeenStr}`;
          const isSuppressed = incident.source_ip ? suppressedIps.has(incident.source_ip) : false;
          
          return (
            <div
              key={incident.incident_id}
              className="group flex items-center justify-between border-b border-[var(--hairline)] h-[36px] font-mono text-[11px] hover:bg-[var(--bg-surface-hover)]/30 transition-colors px-1"
            >
              <div className="flex items-center gap-2 min-w-0 truncate text-[var(--text-primary)]">
                <span className={`font-semibold ${isSuppressed ? "line-through text-zinc-500" : ""}`}>
                  {incident.source_ip ?? "Unknown source"}
                </span>
                
                {incident.source_ip && incident.source_ip !== "Unknown source" && (
                  isSuppressed ? (
                    <span className="px-1.5 py-0.5 rounded text-[8px] font-mono text-zinc-500 bg-zinc-800/40 border border-zinc-700/40">
                      SUPPRESSED
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={(e) => openSuppressModal(incident.source_ip!, e)}
                      title={`Suppress alerts from ${incident.source_ip}`}
                      className="opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity px-1.5 py-0.5 rounded text-[9px] font-mono border border-[var(--hairline)] hover:border-rose-500/50 hover:bg-rose-500/10 text-zinc-400 hover:text-rose-300"
                    >
                      SUPPRESS
                    </button>
                  )
                )}

                <span className="text-[var(--text-muted)]">·</span>
                <span className="text-[var(--text-secondary)] truncate">
                  {incident.threat_classes.map((c) => getShortThreatName(c)).join(", ")}
                </span>
                <span className="text-[var(--text-muted)] ml-1 whitespace-nowrap">
                  ({incident.alerts.length})
                </span>
              </div>
              
              <div className="text-[var(--text-muted)] whitespace-nowrap ml-4 text-right tabular-nums">
                {timeStr}
              </div>
            </div>
          );
        })}
      </div>

      {/* Custom Confirmation Popup Modal */}
      {modalOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="suppress-dialog-title"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150"
          onClick={() => !modalLoading && setModalOpen(false)}
        >
          <div
            className="w-full max-w-md rounded-xl border border-[var(--hairline)] bg-[var(--bg-surface)] p-6 shadow-2xl text-[var(--text-primary)] font-sans select-none flex flex-col gap-4 animate-in zoom-in-95 duration-150"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <div className="h-10 w-10 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center justify-center shrink-0">
                  <ShieldSecurity className="h-5 w-5" />
                </div>
                <div>
                  <h3 id="suppress-dialog-title" className="text-sm font-bold uppercase tracking-wider text-[var(--text-primary)] font-mono">
                    Confirm IP Suppression
                  </h3>
                  <p className="text-[11px] text-[var(--text-secondary)] font-mono mt-0.5">
                    ThreatLens Zero-Transmit Filter
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setModalOpen(false)}
                disabled={modalLoading}
                className="text-[var(--text-muted)] hover:text-[var(--text-primary)] p-1 rounded transition-colors disabled:opacity-50"
                aria-label="Close modal"
              >
                <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M18 6L6 18M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Target Details Form */}
            <form onSubmit={handleConfirmSuppress} className="flex flex-col gap-4">
              <div className="rounded-lg border border-[var(--hairline)] bg-[var(--bg-base)] p-3.5 space-y-2">
                <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider text-[var(--text-secondary)]">
                  <span>Target Source IP</span>
                  <span className="px-1.5 py-0.5 rounded text-[9px] bg-rose-500/10 text-rose-400 border border-rose-500/20 font-bold">
                    RULE: source_ip
                  </span>
                </div>
                <input
                  type="text"
                  value={targetIp}
                  onChange={(e) => setTargetIp(e.target.value)}
                  placeholder="e.g. 192.168.1.100 or 10.0.0.0/24"
                  required
                  className="w-full bg-[var(--bg-surface)] border border-[var(--hairline)] rounded px-3 py-1.5 font-mono text-sm text-rose-400 font-bold focus:outline-none focus:ring-1 focus:ring-rose-500"
                />
                <p className="text-[11px] text-[var(--text-muted)] leading-relaxed pt-1">
                  Alerts originating from this address will be suppressed from the live console stream. Raw telemetry packets remain captured in the backend archive for compliance.
                </p>
              </div>

              {/* Description Input */}
              <div className="flex flex-col gap-1.5">
                <label className="text-[10px] font-mono uppercase tracking-wider text-[var(--text-secondary)]">
                  Suppression Note / Reason
                </label>
                <input
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Reason for suppression..."
                  className="bg-[var(--bg-base)] border border-[var(--hairline)] rounded px-3 py-1.5 text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:ring-1 focus:ring-zinc-600 font-mono"
                />
              </div>

              {/* Error Alert Display */}
              {modalError && (
                <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 text-[11px] text-rose-300 font-mono flex items-start gap-2">
                  <span className="text-rose-400 font-bold shrink-0">ERROR:</span>
                  <span className="break-all">{modalError}</span>
                </div>
              )}

              {/* Modal Actions */}
              <div className="flex items-center justify-end gap-2.5 pt-2 border-t border-[var(--hairline)]">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  disabled={modalLoading}
                  className="px-3.5 py-1.5 rounded-lg border border-[var(--hairline)] hover:bg-[var(--bg-surface-hover)] text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] font-mono transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={modalLoading || !targetIp.trim()}
                  className="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-mono font-bold transition-all shadow-sm flex items-center gap-2 disabled:opacity-50"
                >
                  {modalLoading && (
                    <span className="h-3 w-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  )}
                  <span>{modalLoading ? "SUPPRESSING..." : "CONFIRM SUPPRESSION"}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
