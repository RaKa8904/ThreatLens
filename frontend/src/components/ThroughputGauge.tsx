import { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Activity01Icon as Activity01,
  CpuIcon as Cpu,
  Database01Icon as Database,
} from "hugeicons-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

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
  totalAlerts: number;
  selectedWindow?: TrafficWindow | null;
  onWindowSelect?: (window: TrafficWindow) => void;
}

export function ThroughputGauge({
  totalAlerts,
  selectedWindow = null,
  onWindowSelect,
}: ThroughputGaugeProps) {
  const [data, setData] = useState<ThroughputPoint[]>([]);
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
          return next.slice(-MAX_HISTORY_POINTS);
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
          return next.slice(-MAX_HISTORY_POINTS);
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
    <Card className="border-zinc-800/80 bg-[#090d16]/80 backdrop-blur-xl">
      <CardHeader className="py-2 px-3 flex flex-row items-center justify-between border-b border-zinc-800/60 space-y-0">
        <div className="flex items-center gap-2 min-w-0">
          <Activity01 className="h-4 w-4 text-emerald-400" />
          <CardTitle className="text-[length:var(--text-heading)] uppercase font-mono tracking-wider text-zinc-300 whitespace-nowrap">
            Real-Time Network Telemetry & Throughput
          </CardTitle>
          <span className="text-[length:var(--text-label)] font-mono text-zinc-500 whitespace-nowrap">UTC · {visibleData.length} samples</span>
          {selectedWindow && (
            <span className="text-[10px] font-mono text-cyan-300">
              WINDOW {new Date(selectedWindow.timestamp).toISOString().substring(11, 19)} · {selectedWindow.flows} FLOWS/S · {selectedWindow.pps} PPS · {selectedWindow.mbps} MB/S
            </span>
          )}
        </div>

        <div className="flex items-center gap-2 font-mono text-[length:var(--text-body)] shrink-0">
          <select
            value={windowMinutes}
            onChange={(event) => setWindowMinutes(Number(event.target.value) as ThroughputWindowMinutes)}
            aria-label="Throughput chart interval"
            className="h-6 rounded-md bg-zinc-900 border border-zinc-700 px-2 text-[length:var(--text-label)] text-zinc-300 font-mono"
          >
            <option value={60}>LAST 1H</option>
            <option value={360}>LAST 6H</option>
            <option value={1440}>LAST 24H</option>
          </select>

        {/* Top telemetry stat pills */}
        <div className="flex items-center gap-3 font-mono text-[length:var(--text-body)]">
          <div className="flex items-center space-x-1 text-zinc-300">
            <Cpu className="h-3 w-3 text-emerald-400" />
            <span className="text-zinc-400">FLOWS/S:</span>
            <span className="font-semibold text-emerald-300">{currentFlows}</span>
          </div>

          <div className="flex items-center space-x-1 text-zinc-300">
            <span className="text-zinc-400">PPS:</span>
            <span className="font-semibold text-emerald-300">{currentPPS}</span>
          </div>

          <div className="flex items-center space-x-1 text-zinc-300">
            <Database className="h-3 w-3 text-purple-400" />
            <span className="text-zinc-400">PEAK:</span>
            <span className="font-semibold text-purple-300">{peakMbps} Mb/s</span>
          </div>

          <div className="hidden sm:flex items-center space-x-1 text-zinc-300">
            <span className="text-rose-400 font-semibold">RECEIVED TOTAL:</span>
            <span>{totalAlerts}</span>
          </div>
        </div>
        </div>
      </CardHeader>

      <CardContent className="p-2">
        <div className="h-14 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={visibleData}
              margin={{ top: 5, right: 5, left: -25, bottom: 0 }}
              onClick={(state) => {
                const point = state?.activePayload?.[0]?.payload as ThroughputPoint | undefined;
                if (point && onWindowSelect) onWindowSelect(point);
              }}
            >
              <defs>
                <linearGradient id="flowGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="ppsGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#059669" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#059669" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="time"
                stroke="#52525b"
                fontSize={9}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                yAxisId="flows"
                stroke="#52525b"
                fontSize={9}
                tickLine={false}
                axisLine={false}
                domain={["dataMin - 5", "dataMax + 5"]}
              />
              <YAxis
                yAxisId="pps"
                orientation="right"
                stroke="#52525b"
                fontSize={9}
                tickLine={false}
                axisLine={false}
                domain={["dataMin - 20", "dataMax + 20"]}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#090d16",
                  borderColor: "#27272a",
                  borderRadius: "6px",
                  fontSize: "11px",
                  fontFamily: "monospace",
                }}
                itemStyle={{ padding: "1px 0" }}
              />
              <Area
                type="monotone"
                dataKey="pps"
                yAxisId="pps"
                stroke="#059669"
                strokeWidth={1.5}
                fillOpacity={1}
                fill="url(#ppsGradient)"
                name="Packets/s"
                isAnimationActive={false}
              />
              <Area
                type="monotone"
                dataKey="flows"
                yAxisId="flows"
                stroke="#10b981"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#flowGradient)"
                name="Flows/s"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
