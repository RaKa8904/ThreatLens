import { useEffect, useRef, useState } from "react";
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Legend } from "recharts";
import { ThreatAlertSchema, ThreatClassEnum } from "@/types/threat";
import { getShortThreatName } from "@/lib/threatMapping";

interface ThreatTrendsProps {
  alerts: ThreatAlertSchema[];
}

const vectorColors: Record<string, string> = {
  [ThreatClassEnum.VOLUMETRIC_DOS]: "#38bdf8", // Sky 400
  [ThreatClassEnum.BOTNET_C2]: "#a855f7",     // Purple 500
  [ThreatClassEnum.DGA_DNS]: "#ec4899",       // Pink 500
  [ThreatClassEnum.ENCRYPTED_MALWARE]: "#f43f5e", // Rose 500
  [ThreatClassEnum.RECON_SCAN]: "#eab308",    // Amber / Yellow 500
  [ThreatClassEnum.DATA_EXFIL]: "#10b981",    // Emerald 500
};

const fallbackColors = ["#38bdf8", "#a855f7", "#ec4899", "#f43f5e", "#eab308", "#10b981"];

interface CachedAlert {
  id: string;
  timestamp: number;
  threatClass: string;
}

function TrendTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null;
  const activeEntries = payload.filter((entry) => entry.value > 0);
  return (
    <div className="rounded border border-[var(--hairline)] bg-[var(--bg-surface)] px-2.5 py-2 shadow-xl font-mono text-[10px] text-[var(--text-primary)] min-w-[150px] z-50 relative">
      <div className="mb-1.5 text-[var(--text-secondary)] font-semibold border-b border-[var(--hairline)] pb-1 flex items-center justify-between">
        <span>UTC {label}</span>
        <span className="text-[9px] text-zinc-500 font-normal">window slice</span>
      </div>
      {activeEntries.length === 0 ? (
        <div className="text-[var(--text-muted)] italic py-0.5">No active threats in slice</div>
      ) : (
        <div className="flex flex-col gap-1">
          {activeEntries.map((entry) => (
            <div key={entry.name} className="flex items-center justify-between gap-3">
              <span className="flex items-center gap-1.5 truncate">
                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: entry.color }} />
                <span className="text-zinc-300">{getShortThreatName(entry.name)}</span>
              </span>
              <span className="text-[var(--text-primary)] tabular-nums font-bold">
                {entry.value} <span className="text-[9px] font-normal text-zinc-500">alerts</span>
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function ThreatTrends({ alerts }: ThreatTrendsProps) {
  const [windowMinutes, setWindowMinutes] = useState(5);
  const [now, setNow] = useState(() => Date.now());
  const [hoveredSeries, setHoveredSeries] = useState<string | null>(null);

  // Maintain historical alert cache so older alerts in the session are not lost when live buffer shifts
  const alertHistoryRef = useRef<Map<string, CachedAlert>>(new Map());

  useEffect(() => {
    if (!alerts || alerts.length === 0) return;
    for (const alert of alerts) {
      const id = alert.alert_id || `${alert.timestamp}-${alert.flow_id}-${alert.threat_class}`;
      if (!alertHistoryRef.current.has(id)) {
        const ts = new Date(alert.timestamp).getTime();
        if (Number.isFinite(ts)) {
          alertHistoryRef.current.set(id, {
            id,
            timestamp: ts,
            threatClass: alert.threat_class,
          });
        }
      }
    }

    // Prune entries older than 6 hours to conserve memory
    const cutoff = Date.now() - 6 * 60 * 60 * 1000;
    for (const [id, item] of alertHistoryRef.current.entries()) {
      if (item.timestamp < cutoff) {
        alertHistoryRef.current.delete(id);
      }
    }
  }, [alerts]);

  // Tick every 1 second to advance the streaming timeline continuously
  useEffect(() => {
    const interval = window.setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => window.clearInterval(interval);
  }, []);

  const threatClasses = Object.values(ThreatClassEnum);
  const pointsPerChart = windowMinutes <= 1 ? 30 : 60;
  const totalWindowMs = windowMinutes * 60 * 1000;
  const bucketMs = totalWindowMs / pointsPerChart;
  const start = now - totalWindowMs;

  const chartData: Array<{ timestamp: number; time: string; [key: string]: any }> = Array.from(
    { length: pointsPerChart },
    (_, i) => {
      const bucketStart = start + i * bucketMs;
      const bucketEnd = bucketStart + bucketMs;
      const counts = threatClasses.reduce<Record<string, number>>((result, threatClass) => {
        result[threatClass] = 0;
        return result;
      }, {});

      const timeLabel =
        windowMinutes <= 5
          ? new Date(bucketEnd).toISOString().substring(11, 19)
          : new Date(bucketEnd).toISOString().substring(11, 16);

      return {
        timestamp: bucketEnd,
        time: timeLabel,
        ...counts,
      };
    }
  );

  // Distribute cached alerts into the real-time sliding time slices
  for (const item of alertHistoryRef.current.values()) {
    if (item.timestamp >= start && item.timestamp <= now) {
      const idx = Math.floor((item.timestamp - start) / bucketMs);
      if (idx >= 0 && idx < pointsPerChart) {
        const point = chartData[idx];
        if (point && point[item.threatClass] !== undefined) {
          (point as any)[item.threatClass] += 1;
        }
      }
    }
  }

  const maxDataValue = chartData.reduce((acc, curr) => {
    let currMax = 0;
    for (const cls of threatClasses) {
      const val = (curr as Record<string, any>)[cls] as number;
      if (val > currMax) currMax = val;
    }
    return Math.max(acc, currMax);
  }, 0);

  const niceMaxs = [3, 5, 10, 15, 20, 30, 50, 100];
  let niceMax = 5;
  for (const m of niceMaxs) {
    if (maxDataValue <= m) {
      niceMax = m;
      break;
    }
  }
  if (maxDataValue > 100) niceMax = Math.ceil(maxDataValue / 50) * 50;

  let ticks = [0, niceMax];
  if (niceMax === 3) ticks = [0, 1, 2, 3];
  else if (niceMax === 5) ticks = [0, 2, 5];
  else if (niceMax === 10) ticks = [0, 5, 10];
  else if (niceMax === 15) ticks = [0, 5, 10, 15];
  else if (niceMax === 20) ticks = [0, 10, 20];
  else if (niceMax === 30) ticks = [0, 15, 30];
  else ticks = [0, Math.floor(niceMax / 2), niceMax];

  return (
    <div className="flex flex-col gap-4 h-full">
      <div className="flex items-center justify-between border-b border-[var(--hairline)] pb-3">
        <div className="flex items-center gap-2.5">
          <h2 className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-widest opacity-80 h-[16px] flex items-center">
            Threat vectors
          </h2>
          <span className="flex items-center gap-1.5 text-[9px] font-mono text-emerald-400 font-semibold px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
            STREAMING
          </span>
        </div>
        <select
          value={windowMinutes}
          onChange={(event) => setWindowMinutes(Number(event.target.value))}
          className="h-6 rounded bg-[var(--bg-surface-hover)] border border-[var(--hairline)] px-2 text-[10px] text-[var(--text-secondary)] font-mono outline-none focus:border-emerald-500/50 cursor-pointer"
        >
          <option value={1}>LIVE 1M</option>
          <option value={5}>LAST 5M</option>
          <option value={15}>LAST 15M</option>
          <option value={60}>LAST 1H</option>
          <option value={360}>LAST 6H</option>
        </select>
      </div>
      <div className="flex-1 w-full min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartData} margin={{ top: 5, right: 10, left: -25, bottom: 0 }}>
            <XAxis
              dataKey="time"
              stroke="var(--text-muted)"
              fontSize={10}
              tickLine={false}
              axisLine={false}
              minTickGap={35}
            />
            <YAxis
              allowDecimals={false}
              stroke="var(--text-muted)"
              fontSize={10}
              tickLine={false}
              axisLine={false}
              domain={[0, niceMax]}
              ticks={ticks}
            />
            <Tooltip
              content={<TrendTooltip />}
              cursor={{ stroke: "var(--hairline)", strokeWidth: 1 }}
              position={{ y: 0 }}
              offset={30}
              isAnimationActive={false}
            />
            <Legend
              wrapperStyle={{
                fontSize: "10px",
                color: "var(--text-secondary)",
                fontFamily: "monospace",
                transition: "all 0.12s",
              }}
              iconType="circle"
              iconSize={6}
              formatter={(value) => getShortThreatName(value as string)}
              onMouseEnter={(e: any) => setHoveredSeries(e.dataKey)}
              onMouseLeave={() => setHoveredSeries(null)}
            />
            {threatClasses.map((threatClass, index) => {
              const isHovered = hoveredSeries === threatClass;
              const opacity = hoveredSeries ? (isHovered ? 1 : 0.2) : 1;
              const strokeColor = vectorColors[threatClass] || fallbackColors[index % fallbackColors.length];
              return (
                <Line
                  key={threatClass}
                  type="monotone"
                  dataKey={threatClass}
                  stroke={strokeColor}
                  strokeWidth={1.5}
                  dot={false}
                  activeDot={{ r: 3 }}
                  name={threatClass}
                  isAnimationActive={false}
                  strokeOpacity={opacity}
                  style={{ transition: "stroke-opacity 0.12s ease" }}
                />
              );
            })}
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
