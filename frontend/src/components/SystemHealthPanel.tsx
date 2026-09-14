import { useEffect, useState } from "react";
import { Activity01Icon as Activity, Shield01Icon as Lock } from "hugeicons-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface HealthPayload {
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

  return (
    <Card className="border-zinc-800/80 bg-[#090d16]/80 backdrop-blur-xl">
      <CardHeader className="py-3 px-4 border-b border-zinc-800/60">
        <CardTitle className="flex items-center gap-2 text-xs uppercase font-mono tracking-wider text-zinc-300">
          <Activity className="h-4 w-4 text-cyan-400" /> Pipeline Health
        </CardTitle>
      </CardHeader>
      <CardContent className="p-3 grid grid-cols-2 lg:grid-cols-5 gap-2 font-mono text-[11px]">
        <div className="rounded border border-emerald-500/20 bg-emerald-500/[0.04] p-2">
          <div className="text-zinc-500 uppercase">Ingest Mode</div>
          <div className="mt-1 text-emerald-300">{passive?.status ?? "CHECKING"}</div>
        </div>
        <div className="rounded border border-cyan-500/20 bg-cyan-500/[0.04] p-2">
          <div className="text-zinc-500 uppercase">Flows / Sec</div>
          <div className="mt-1 text-cyan-300">{metrics.flows_per_sec?.toFixed(2) ?? "N/A"}</div>
        </div>
        <div className="rounded border border-cyan-500/20 bg-cyan-500/[0.04] p-2">
          <div className="text-zinc-500 uppercase">Bandwidth</div>
          <div className="mt-1 text-cyan-300">{metrics.megabits_per_sec?.toFixed(3) ?? "N/A"} Mbps</div>
        </div>
        <div className="rounded border border-amber-500/20 bg-amber-500/[0.04] p-2">
          <div className="text-zinc-500 uppercase">Pipeline Delay</div>
          <div className="mt-1 text-amber-300">{latency?.processing_latency_ms?.toFixed(2) ?? "N/A"} ms</div>
        </div>
        <div className="rounded border border-emerald-500/20 bg-emerald-500/[0.04] p-2 flex items-center gap-2">
          <Lock className="h-4 w-4 text-emerald-400 shrink-0" />
          <div><div className="text-zinc-500 uppercase">Return Path</div><div className="mt-1 text-emerald-300">{passive?.zero_egress && passive.read_only ? "NONE / READ-ONLY" : "VERIFY"}</div></div>
        </div>
      </CardContent>
    </Card>
  );
}
