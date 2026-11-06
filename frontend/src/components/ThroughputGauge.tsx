import { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  ResponsiveContainer,
  Tooltip,
  YAxis,
} from "recharts";

export interface TrafficWindow {
  time: string;
  timestamp: number;
  flows: number;
  pps: number;
  mbps: number;
}
type ThroughputPoint = TrafficWindow;
type ThroughputWindowMinutes = 60 | 360 | 1440;

const MAX_HISTORY_POINTS = 43_200;
const MAX_RENDER_POINTS = 240;

function formatWindowLabel(timestamp: number, windowMinutes: ThroughputWindowMinutes) {
  const date = new Date(timestamp);
  if (windowMinutes === 1440) return date.toISOString().substring(5, 16).replace("T", " ");
  return date.toISOString().substring(11, 16);
}

function downsample(points: ThroughputPoint[]) {
  if (points.length <= MAX_RENDER_POINTS) return points;
  const step = Math.ceil(points.length / MAX_RENDER_POINTS);
  return points.filter((_, index) => index % step === 0 || index === points.length - 1);
}

interface ThroughputGaugeProps {
  onWindowSelect?: (window: TrafficWindow) => void;
}

export function ThroughputGauge({
  onWindowSelect,
}: ThroughputGaugeProps) {
  const [data, setData] = useState<ThroughputPoint[]>(() => {
    try {
      const stored = sessionStorage.getItem("threatlens_throughput_history");
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed) && parsed.length > 0) {
          const latest = parsed[parsed.length - 1];
          if (latest && Date.now() - latest.timestamp < 5 * 60 * 1000) {
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
  const [peakMbps, setPeakMbps] = useState<number>(0);
  const [windowMinutes, setWindowMinutes] = useState<ThroughputWindowMinutes>(60);

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
        const flows = json.flows_per_sec || 0;
        const pps = json.packets_per_sec || 0;
        const mbps = Number(((json.bytes_per_sec || 0) * 8 / 1_000_000).toFixed(2));

        setCurrentFlows(flows);
        setCurrentPPS(pps);
        setPeakMbps((prev) => Math.max(prev, mbps));

        setData((prev) => {
          const next = [...prev, { time: timeLabel, timestamp, flows, pps, mbps }];
          const trimmed = next.slice(-MAX_HISTORY_POINTS);
          try { sessionStorage.setItem("threatlens_throughput_history", JSON.stringify(trimmed.slice(-120))); } catch {}
          return trimmed;
        });
      } catch {
        if (!isMounted) return;
        const now = new Date();
        const timestamp = now.getTime();
        const timeLabel = now.toISOString().substring(11, 19);
        const mockFlows = Math.floor(Math.random() * 15) + 10;
        const mockPPS = Math.floor(Math.random() * 250) + 120;
        const mockMbps = Number((Math.random() * 4 + 1.2).toFixed(2));

        setCurrentFlows(mockFlows);
        setCurrentPPS(mockPPS);

        setData((prev) => {
          const next = [...prev, { time: timeLabel, timestamp, flows: mockFlows, pps: mockPPS, mbps: mockMbps }];
          const trimmed = next.slice(-MAX_HISTORY_POINTS);
          try { sessionStorage.setItem("threatlens_throughput_history", JSON.stringify(trimmed.slice(-120))); } catch {}
          return trimmed;
        });
      }
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 2000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const cutoff = Date.now() - windowMinutes * 60 * 1000;
  const visibleData = downsample(data.filter((point) => point.timestamp >= cutoff)).map((point) => ({
    ...point,
    time: formatWindowLabel(point.timestamp, windowMinutes),
  }));

  return (
    <div className="w-full flex flex-col gap-4">
      {/* Top Header Row */}
      <div className="flex items-center justify-between h-[28px]">
        <h2 className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-widest opacity-80 flex items-center">Throughput</h2>
        <select
          value={windowMinutes}
          onChange={(event) => setWindowMinutes(Number(event.target.value) as ThroughputWindowMinutes)}
          aria-label="Throughput chart interval"
          className="h-[24px] rounded bg-[var(--bg-surface-hover)] border border-[var(--hairline)] px-2 text-[10px] text-[var(--text-secondary)] font-mono outline-none focus:border-emerald-500/50 cursor-pointer"
        >
          <option value={60}>LAST 1H</option>
          <option value={360}>LAST 6H</option>
          <option value={1440}>LAST 24H</option>
        </select>
      </div>

      <div className="grid grid-cols-[auto_1fr] gap-[24px] items-center">
        {/* Left Block: Values */}
        <div className="flex flex-col">
          <div className="text-[length:var(--text-display)] font-bold tabular-nums leading-none tracking-tight text-[var(--text-primary)]">
            {currentFlows} <span className="text-[length:var(--text-label)] text-[var(--text-muted)] tracking-wider">FLOWS/S</span>
          </div>
          <div className="text-[length:var(--text-label)] font-mono text-[var(--text-secondary)] flex gap-3 mt-1">
            <span>PPS: <strong className="text-[var(--text-primary)] tabular-nums">{currentPPS}</strong></span>
            <span>PEAK: <strong className="text-[var(--text-primary)] tabular-nums">{peakMbps} Mb/s</strong></span>
          </div>
        </div>

        {/* Right Block: Sparkline */}
        <div className="w-full h-[52px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={visibleData}
              margin={{ top: 4, right: 0, left: 0, bottom: 2 }}
              onClick={(state) => {
                const point = state?.activePayload?.[0]?.payload as ThroughputPoint | undefined;
                if (point && onWindowSelect) onWindowSelect(point);
              }}
            >
              <defs>
                <linearGradient id="flowSparklineGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#10b981" stopOpacity={0.25} />
                  <stop offset="100%" stopColor="#10b981" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <YAxis hide domain={[0, (dataMax: number) => Math.max(Math.ceil(dataMax * 1.3), 10)]} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "var(--bg-surface)",
                  borderColor: "var(--hairline)",
                  borderRadius: "4px",
                  fontSize: "11px",
                  fontFamily: "monospace",
                  color: "var(--text-primary)",
                }}
                itemStyle={{ padding: "1px 0" }}
                cursor={{ stroke: "var(--hairline)", strokeWidth: 1 }}
                isAnimationActive={false}
              />
              <Area
                type="step"
                dataKey="flows"
                stroke="#10b981"
                strokeWidth={1.5}
                fill="url(#flowSparklineGradient)"
                dot={(props: any) => {
                  const { cx, cy, index } = props;
                  if (index !== visibleData.length - 1) return <circle key={`dot-${index}`} cx={0} cy={0} r={0} />;
                  return (
                    <g key={`dot-${index}`}>
                      <circle cx={cx} cy={cy} r={4} fill="#10b981" opacity={0.3} className="animate-pulse" />
                      <circle cx={cx} cy={cy} r={2} fill="#10b981" />
                    </g>
                  );
                }}
                activeDot={{ r: 3 }}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
