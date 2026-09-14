import { useEffect, useState } from "react";
import { Activity01Icon as Activity, Shield01Icon as Lock } from "hugeicons-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

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

  const passive = health.services?.passive_ingest;
  const latency = health.telemetry;
  const fallbackActive = health.redis_status === "fallback_memory" || health.clickhouse_status === "fallback_memory";

  return (
    <Card className="border-zinc-800/80 bg-[#090d16]/80 backdrop-blur-xl">
      <CardHeader className="py-3 px-4 border-b border-zinc-800/60">
        <CardTitle className="flex items-center gap-2 text-[length:var(--text-heading)] uppercase font-mono tracking-wider text-zinc-300">
          <Activity className="h-4 w-4 text-cyan-400" /> Pipeline Health
        </CardTitle>
      </CardHeader>
      {fallbackActive && <div className="mx-3 mt-3 rounded border border-amber-500/50 bg-amber-500/10 px-3 py-2 font-mono text-[11px] text-amber-200">DEGRADED STORAGE: {health.redis_status === "fallback_memory" ? "Redis" : "ClickHouse"} is using in-memory fallback. Data may be lost on restart.</div>}
      <CardContent className="p-0 grid grid-cols-2 lg:grid-cols-5 divide-x divide-zinc-800/70 font-mono text-[length:var(--text-body)]">
        <div className="p-3">
          <div className="text-[length:var(--text-label)] text-zinc-500 uppercase">Ingest Mode</div>
          <div className="mt-1 text-emerald-300">{passive?.status ?? "CHECKING"}</div>
        </div>
        <div className="p-3">
          <div className="text-[length:var(--text-label)] text-zinc-500 uppercase">Flows / Sec</div>
          <div className="mt-1 text-cyan-300 tabular-nums">{metrics.flows_per_sec?.toFixed(2) ?? "N/A"}</div>
        </div>
        <div className="p-3">
          <div className="text-[length:var(--text-label)] text-zinc-500 uppercase">Bandwidth</div>
          <div className="mt-1 text-cyan-300 tabular-nums">{metrics.megabits_per_sec?.toFixed(3) ?? "N/A"} Mbps</div>
        </div>
        <div className="p-3">
          <div className="text-[length:var(--text-label)] text-zinc-500 uppercase">Pipeline Delay</div>
          <div className="mt-1 text-amber-300 tabular-nums">{latency?.processing_latency_ms?.toFixed(2) ?? "N/A"} ms</div>
        </div>
        <div className="p-3 flex items-center gap-2">
          <Lock className="h-4 w-4 text-emerald-400 shrink-0" />
          <div><div className="text-zinc-500 uppercase">Return Path</div><div className="mt-1 text-emerald-300">{passive?.zero_egress && passive.read_only ? "NONE / READ-ONLY" : "VERIFY"}</div></div>
        </div>
      </CardContent>
    </Card>
  );
}
