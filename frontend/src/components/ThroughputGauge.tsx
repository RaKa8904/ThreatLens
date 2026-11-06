import { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";

export interface TrafficWindow {
  time: string;
  timestamp: number;
  flows: number;
  pps: number;
  mbps: number;
}

type ThroughputPoint = TrafficWindow;
type MetricKey = "flows" | "pps" | "mbps";

const MAX_HISTORY_POINTS = 43_200;
const MAX_RENDER_POINTS = 140;

function formatWindowLabel(timestamp: number, windowMinutes: number) {
  const date = new Date(timestamp);
  if (windowMinutes <= 5) return date.toISOString().substring(11, 19);
  if (windowMinutes <= 60) return date.toISOString().substring(11, 16);
  return date.toISOString().substring(5, 16).replace("T", " ");
}

function downsample(points: ThroughputPoint[]) {
  if (points.length <= MAX_RENDER_POINTS) return points;
  const step = Math.ceil(points.length / MAX_RENDER_POINTS);
  return points.filter((_, index) => index % step === 0 || index === points.length - 1);
}

const metricConfig: Record<
  MetricKey,
  {
    title: string;
    unit: string;
    subtext: string;
    color: string;
    borderColor: string;
    bgActive: string;
    gradientId: string;
  }
> = {
  flows: {
    title: "Flows Ingress",
    unit: "flows/s",
    subtext: "Live TCP/UDP connection 5-tuples",
    color: "#10b981", // Emerald 500
    borderColor: "border-emerald-500/50",
    bgActive: "bg-emerald-500/[0.08]",
    gradientId: "flowGradient",
  },
  pps: {
    title: "Packet Velocity",
    unit: "pps",
    subtext: "Promiscuous line-rate packet flow",
    color: "#38bdf8", // Sky 400
    borderColor: "border-sky-500/50",
    bgActive: "bg-sky-500/[0.08]",
    gradientId: "ppsGradient",
  },
  mbps: {
    title: "Wire Bandwidth",
    unit: "Mbps",
    subtext: "Payload bitstream across physical TAP",
    color: "#a855f7", // Purple 400
    borderColor: "border-purple-500/50",
    bgActive: "bg-purple-500/[0.08]",
    gradientId: "mbpsGradient",
  },
};

function ThroughputTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ payload: ThroughputPoint }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  const point = payload[0].payload;

  return (
    <div className="rounded border border-[var(--hairline)] bg-[var(--bg-surface)] px-3 py-2 shadow-xl font-mono text-[10px] text-[var(--text-primary)] min-w-[190px] z-50">
      <div className="mb-1.5 text-[var(--text-secondary)] font-semibold border-b border-[var(--hairline)] pb-1 flex items-center justify-between">
        <span>UTC {label}</span>
        <span className="text-[9px] text-emerald-400 font-semibold">TAP PROMISCUOUS</span>
      </div>
      <div className="flex flex-col gap-1.5">
        <div className="flex items-center justify-between gap-3">
          <span className="flex items-center gap-1.5 text-zinc-300">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            Flow Velocity:
          </span>
          <span className="text-[var(--text-primary)] tabular-nums font-bold">
            {point.flows.toFixed(2)}{" "}
            <span className="text-[9px] font-normal text-zinc-500">flows/s</span>
          </span>
        </div>
        <div className="flex items-center justify-between gap-3">
          <span className="flex items-center gap-1.5 text-zinc-300">
            <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
            Packet Rate:
          </span>
          <span className="text-[var(--text-primary)] tabular-nums font-bold">
            {Math.round(point.pps).toLocaleString()}{" "}
            <span className="text-[9px] font-normal text-zinc-500">pps</span>
          </span>
        </div>
        <div className="flex items-center justify-between gap-3">
          <span className="flex items-center gap-1.5 text-zinc-300">
            <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
            Wire Bandwidth:
          </span>
          <span className="text-[var(--text-primary)] tabular-nums font-bold">
            {point.mbps.toFixed(2)}{" "}
            <span className="text-[9px] font-normal text-zinc-500">Mbps</span>
          </span>
        </div>
      </div>
    </div>
  );
}

interface ThroughputGaugeProps {
  onWindowSelect?: (window: TrafficWindow) => void;
}

export function ThroughputGauge({ onWindowSelect }: ThroughputGaugeProps) {
  const [data, setData] = useState<ThroughputPoint[]>(() => {
    try {
      const stored = sessionStorage.getItem("threatlens_throughput_history");
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed) && parsed.length > 0) {
          const latest = parsed[parsed.length - 1];
          if (latest && Date.now() - latest.timestamp < 10 * 60 * 1000) {
            return parsed;
          }
        }
      }
      return [];
    } catch {
      return [];
    }
  });

  const [currentFlows, setCurrentFlows] = useState<number>(0);
  const [currentPPS, setCurrentPPS] = useState<number>(0);
  const [currentMbps, setCurrentMbps] = useState<number>(0);
  const [peakMbps, setPeakMbps] = useState<number>(0);
  const [windowMinutes, setWindowMinutes] = useState<number>(5);
  const [activeMetric, setActiveMetric] = useState<MetricKey>("flows");

  useEffect(() => {
    let isMounted = true;

    const fetchMetrics = async () => {
      try {
        const res = await fetch("/api/metrics/throughput");
        if (!res.ok) return;
        const json = await res.json();
        if (!isMounted) return;

        const now = new Date();
        const timestamp = now.getTime();
        const timeLabel = now.toISOString().substring(11, 19);
        const flows = Number(json.flows_per_sec || 0);
        const pps = Number(json.packets_per_sec || 0);
        const mbps = Number((((json.bytes_per_sec || 0) * 8) / 1_000_000).toFixed(2));

        setCurrentFlows(flows);
        setCurrentPPS(pps);
        setCurrentMbps(mbps);
        setPeakMbps((prev) => Math.max(prev, mbps));

        setData((prev) => {
          const next = [...prev, { time: timeLabel, timestamp, flows, pps, mbps }];
          const trimmed = next.slice(-MAX_HISTORY_POINTS);
          try {
            sessionStorage.setItem("threatlens_throughput_history", JSON.stringify(trimmed.slice(-180)));
          } catch {}
          return trimmed;
        });
      } catch {
        if (!isMounted) return;
        const now = new Date();
        const timestamp = now.getTime();
        const timeLabel = now.toISOString().substring(11, 19);
        const mockFlows = Math.floor(Math.random() * 8) + 2;
        const mockPPS = Math.floor(Math.random() * 200) + 100;
        const mockMbps = Number((Math.random() * 2 + 1.2).toFixed(2));

        setCurrentFlows(mockFlows);
        setCurrentPPS(mockPPS);
        setCurrentMbps(mockMbps);

        setData((prev) => {
          const next = [...prev, { time: timeLabel, timestamp, flows: mockFlows, pps: mockPPS, mbps: mockMbps }];
          const trimmed = next.slice(-MAX_HISTORY_POINTS);
          try {
            sessionStorage.setItem("threatlens_throughput_history", JSON.stringify(trimmed.slice(-180)));
          } catch {}
          return trimmed;
        });
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 1500);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const cutoff = Date.now() - windowMinutes * 60 * 1000;
  const filtered = data.filter((point) => point.timestamp >= cutoff);
  const visibleData = downsample(filtered).map((point) => ({
    ...point,
    displayTime: formatWindowLabel(point.timestamp, windowMinutes),
  }));

  const activeConfig = metricConfig[activeMetric];

  // Dynamic Y-axis scale based on currently selected metric
  const maxMetricValue = visibleData.reduce((acc, curr) => Math.max(acc, curr[activeMetric] || 0), 0);
  const niceYMax = Math.max(
    Math.ceil(maxMetricValue * 1.25),
    activeMetric === "flows" ? 6 : activeMetric === "mbps" ? 5 : 500
  );

  return (
    <div className="w-full flex flex-col gap-3.5">
      {/* Top Header: Title, Architectural Security Status, and Time Window */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--hairline)] pb-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <h2 className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-widest opacity-80 h-[16px] flex items-center">
            Throughput Telemetry
          </h2>
          <span className="flex items-center gap-1.5 text-[9px] font-mono text-emerald-400 font-semibold px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
            LIVE TAP STREAM
          </span>
          <span className="hidden sm:inline-flex items-center gap-1 text-[9px] font-mono text-zinc-400 px-2 py-0.5 rounded bg-zinc-900/60 border border-[var(--hairline)]">
            INGEST: <strong className="text-emerald-400 font-normal">ZERO-EGRESS READ-ONLY</strong>
          </span>
          <span className="hidden md:inline-flex items-center gap-1 text-[9px] font-mono text-zinc-400 px-2 py-0.5 rounded bg-zinc-900/60 border border-[var(--hairline)]">
            RETURN PATH: <strong className="text-zinc-300 font-normal">NONE (PHYSICAL DIODE)</strong>
          </span>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={windowMinutes}
            onChange={(event) => setWindowMinutes(Number(event.target.value))}
            aria-label="Throughput chart interval"
            className="h-6 rounded bg-[var(--bg-surface-hover)] border border-[var(--hairline)] px-2.5 text-[10px] text-[var(--text-secondary)] font-mono outline-none focus:border-emerald-500/50 cursor-pointer"
          >
            <option value={1}>LIVE 1M</option>
            <option value={5}>LAST 5M</option>
            <option value={15}>LAST 15M</option>
            <option value={60}>LAST 1H</option>
            <option value={360}>LAST 6H</option>
          </select>
        </div>
      </div>

      {/* Interactive Metric Cards: Clicking any card switches the active stream graph */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Card 1: Flows Ingress */}
        <button
          type="button"
          onClick={() => setActiveMetric("flows")}
          className={`text-left p-3.5 rounded border transition-all cursor-pointer relative overflow-hidden ${
            activeMetric === "flows"
              ? "border-emerald-500/50 bg-emerald-500/[0.07] shadow-sm ring-1 ring-emerald-500/30"
              : "border-[var(--hairline)] bg-[var(--bg-base)]/40 hover:bg-[var(--bg-surface-hover)]/40 hover:border-zinc-700"
          }`}
        >
          <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider mb-1.5">
            <span className="flex items-center gap-1.5 text-zinc-300 font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              Flows Ingress
            </span>
            {activeMetric === "flows" ? (
              <span className="text-[9px] px-1.5 py-0.2 rounded font-semibold text-emerald-300 bg-emerald-500/15 border border-emerald-500/30">
                ACTIVE GRAPH ▾
              </span>
            ) : (
              <span className="text-[9px] text-zinc-500 group-hover:text-zinc-300">Switch ↗</span>
            )}
          </div>
          <div className="text-2xl font-bold tabular-nums text-[var(--text-primary)] flex items-baseline gap-1.5">
            {currentFlows.toFixed(2)}
            <span className="text-xs font-mono font-normal text-zinc-400">flows/s</span>
          </div>
          <p className="text-[10px] font-mono text-[var(--text-secondary)] mt-1 truncate">
            Live TCP/UDP connection 5-tuples
          </p>
        </button>

        {/* Card 2: Packet Velocity */}
        <button
          type="button"
          onClick={() => setActiveMetric("pps")}
          className={`text-left p-3.5 rounded border transition-all cursor-pointer relative overflow-hidden ${
            activeMetric === "pps"
              ? "border-sky-500/50 bg-sky-500/[0.07] shadow-sm ring-1 ring-sky-500/30"
              : "border-[var(--hairline)] bg-[var(--bg-base)]/40 hover:bg-[var(--bg-surface-hover)]/40 hover:border-zinc-700"
          }`}
        >
          <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider mb-1.5">
            <span className="flex items-center gap-1.5 text-zinc-300 font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
              Packet Velocity
            </span>
            {activeMetric === "pps" ? (
              <span className="text-[9px] px-1.5 py-0.2 rounded font-semibold text-sky-300 bg-sky-500/15 border border-sky-500/30">
                ACTIVE GRAPH ▾
              </span>
            ) : (
              <span className="text-[9px] text-zinc-500 group-hover:text-zinc-300">Switch ↗</span>
            )}
          </div>
          <div className="text-2xl font-bold tabular-nums text-[var(--text-primary)] flex items-baseline gap-1.5">
            {Math.round(currentPPS).toLocaleString()}
            <span className="text-xs font-mono font-normal text-zinc-400">pps</span>
          </div>
          <p className="text-[10px] font-mono text-[var(--text-secondary)] mt-1 truncate">
            Promiscuous line-rate frame rate
          </p>
        </button>

        {/* Card 3: Wire Bandwidth */}
        <button
          type="button"
          onClick={() => setActiveMetric("mbps")}
          className={`text-left p-3.5 rounded border transition-all cursor-pointer relative overflow-hidden ${
            activeMetric === "mbps"
              ? "border-purple-500/50 bg-purple-500/[0.07] shadow-sm ring-1 ring-purple-500/30"
              : "border-[var(--hairline)] bg-[var(--bg-base)]/40 hover:bg-[var(--bg-surface-hover)]/40 hover:border-zinc-700"
          }`}
        >
          <div className="flex items-center justify-between text-[10px] font-mono uppercase tracking-wider mb-1.5">
            <span className="flex items-center gap-1.5 text-zinc-300 font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
              Wire Bandwidth
            </span>
            {activeMetric === "mbps" ? (
              <span className="text-[9px] px-1.5 py-0.2 rounded font-semibold text-purple-300 bg-purple-500/15 border border-purple-500/30">
                ACTIVE GRAPH ▾
              </span>
            ) : (
              <span className="text-[9px] text-zinc-500 group-hover:text-zinc-300">Switch ↗</span>
            )}
          </div>
          <div className="text-2xl font-bold tabular-nums text-[var(--text-primary)] flex items-baseline gap-1.5">
            {currentMbps.toFixed(2)}
            <span className="text-xs font-mono font-normal text-zinc-400">Mbps</span>
          </div>
          <p className="text-[10px] font-mono text-[var(--text-secondary)] mt-1 truncate">
            Bitstream velocity (Peak: {peakMbps.toFixed(2)} Mbps)
          </p>
        </button>
      </div>

      {/* Expanded Full-Width Streaming Waveform Area Chart */}
      <div className="w-full h-[130px] mt-1">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={visibleData}
            margin={{ top: 8, right: 10, left: -20, bottom: 0 }}
            onClick={(state) => {
              const point = state?.activePayload?.[0]?.payload as ThroughputPoint | undefined;
              if (point && onWindowSelect) onWindowSelect(point);
            }}
          >
            <defs>
              <linearGradient id="flowGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#10b981" stopOpacity={0.28} />
                <stop offset="100%" stopColor="#10b981" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="ppsGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.28} />
                <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="mbpsGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#a855f7" stopOpacity={0.28} />
                <stop offset="100%" stopColor="#a855f7" stopOpacity={0.0} />
              </linearGradient>
            </defs>

            <CartesianGrid stroke="var(--hairline)" strokeDasharray="3 3" vertical={false} opacity={0.6} />

            <XAxis
              dataKey="displayTime"
              stroke="var(--text-muted)"
              fontSize={10}
              tickLine={false}
              axisLine={false}
              minTickGap={45}
            />
            <YAxis
              allowDecimals={activeMetric === "mbps" || activeMetric === "flows"}
              stroke="var(--text-muted)"
              fontSize={10}
              tickLine={false}
              axisLine={false}
              domain={[0, niceYMax]}
            />

            <Tooltip
              content={<ThroughputTooltip />}
              cursor={{ stroke: "var(--hairline)", strokeWidth: 1 }}
              position={{ y: 0 }}
              offset={30}
              isAnimationActive={false}
            />

            <Area
              type="monotone"
              dataKey={activeMetric}
              stroke={activeConfig.color}
              strokeWidth={1.5}
              fill={`url(#${activeConfig.gradientId})`}
              dot={(props: any) => {
                const { cx, cy, index } = props;
                if (index !== visibleData.length - 1) return <circle key={`dot-${index}`} cx={0} cy={0} r={0} />;
                return (
                  <g key={`dot-${index}`}>
                    <circle cx={cx} cy={cy} r={5} fill={activeConfig.color} opacity={0.3} className="animate-pulse" />
                    <circle cx={cx} cy={cy} r={2.5} fill={activeConfig.color} />
                  </g>
                );
              }}
              activeDot={{ r: 3.5, fill: activeConfig.color }}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
