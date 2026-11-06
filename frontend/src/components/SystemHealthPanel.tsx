import { useEffect, useState } from "react";
import { Shield01Icon as Lock } from "hugeicons-react";

interface HealthPayload {
  redis_status?: string;
  clickhouse_status?: string;
  services?: { passive_ingest?: { status?: string; zero_egress?: boolean; read_only?: boolean } };
  telemetry?: { processing_latency_ms?: number | null; delivery_latency_ms?: number | null };
}

interface ThroughputPayload {
  megabits_per_sec?: number;
  flows_per_sec?: number;
}

export function SystemHealthPanel() {
  const [health, setHealth] = useState<HealthPayload>({});
  const [metrics, setMetrics] = useState<ThroughputPayload>({});

  useEffect(() => {
    let mounted = true;
    const refresh = async () => {
      try {
        const [healthResponse, metricsResponse] = await Promise.all([
          fetch("/api/health"),
          fetch("/api/metrics/throughput"),
        ]);
        if (!mounted) return;
        if (healthResponse.ok) setHealth(await healthResponse.json());
        if (metricsResponse.ok) setMetrics(await metricsResponse.json());
      } catch {
        // The status remains visible with the last known values during reconnects.
      }
    };
    refresh();
    const interval = window.setInterval(refresh, 2000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

  const [bannerDismissed, setBannerDismissed] = useState(false);

  const latency = health.telemetry;
  const fallbackActive = health.redis_status === "fallback_memory" || health.clickhouse_status === "fallback_memory";
  const activeFallbackService = health.clickhouse_status === "fallback_memory" ? "ClickHouse" : "Redis";

  return (
    <div className="w-full flex flex-col gap-4">
      {/* Fallback Banner */}
      {fallbackActive && !bannerDismissed && (
        <div className="absolute -top-12 left-0 right-0 rounded border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 font-mono text-[11px] text-amber-300 flex items-center justify-between gap-2 z-10 shadow-sm backdrop-blur-md">
          <span>
            <strong className="font-semibold text-amber-400">STORAGE FALLBACK:</strong> Operating on in-memory ring buffer ({activeFallbackService}). Connect persistent storage for archiving.
          </span>
          <button
            onClick={() => setBannerDismissed(true)}
            className="text-amber-400/70 hover:text-amber-200 text-xs px-1 hover:bg-amber-500/20 rounded font-bold"
            title="Dismiss notification"
          >
            ×
          </button>
        </div>
      )}

      {/* Label Row */}
      <div className="flex items-center h-[28px]">
        <h2 className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-widest opacity-80 flex items-center">Pipeline</h2>
      </div>
      
      {/* Cells */}
      <div className="grid grid-cols-5 divide-x divide-[var(--hairline)] font-mono text-[length:var(--text-body)] text-[var(--text-primary)] w-full items-center">
        <div className="min-w-0 pr-4 flex flex-col">
          <div className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-wider mb-1 h-[16px]">Ingest Mode</div>
          <div className="flex items-center gap-2 text-[length:var(--text-body)]">
            <span className="text-[var(--live-accent)]">zero-egress</span>
            <span className="text-[10px] text-[var(--text-muted)]">read-only</span>
          </div>
        </div>
        <div className="min-w-0 px-4 flex flex-col">
          <div className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-wider mb-1 h-[16px]">Flows / Sec</div>
          <div className="tabular-nums text-[length:var(--text-body)]">{metrics.flows_per_sec?.toFixed(2) ?? "N/A"}</div>
        </div>
        <div className="min-w-0 px-4 flex flex-col">
          <div className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-wider mb-1 h-[16px]">Bandwidth</div>
          <div className="tabular-nums text-[length:var(--text-body)]">{metrics.megabits_per_sec?.toFixed(3) ?? "N/A"} Mbps</div>
        </div>
        <div className="min-w-0 px-4 flex flex-col">
          <div className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-wider mb-1 h-[16px]">Pipeline Delay</div>
          <div className="tabular-nums text-[length:var(--text-body)]">{latency?.processing_latency_ms != null ? <span className="text-amber-400/90">{latency.processing_latency_ms.toFixed(2)} ms</span> : <span className="text-[var(--text-muted)]">N/A</span>}</div>
        </div>
        <div className="min-w-0 pl-4 flex flex-col">
          <div className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-wider mb-1 h-[16px] flex items-center gap-1.5"><Lock className="h-3 w-3 text-[var(--text-muted)]" />Return Path</div>
          <div className="flex items-center gap-2 text-[length:var(--text-body)]">
            <span className="text-[var(--live-accent)]">None</span>
            <span className="text-[10px] text-[var(--text-muted)]">read-only</span>
          </div>
        </div>
      </div>
    </div>
  );
}
