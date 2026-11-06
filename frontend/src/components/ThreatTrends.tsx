import { useEffect, useState } from "react";
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis, Legend } from "recharts";
import { ThreatAlertSchema, ThreatClassEnum } from "@/types/threat";
import { getShortThreatName } from "@/lib/threatMapping";

interface ThreatTrendsProps {
  alerts: ThreatAlertSchema[];
}

const vectorColors = ["#0ea5e9", "#a855f7", "#ec4899", "#8b5cf6", "#06b6d4", "#d946ef"];

function TrendTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null;
  const activeEntries = payload.filter((entry) => entry.value > 0);
  return (
    <div className="rounded border border-[var(--hairline)] bg-[var(--bg-surface)] px-2 py-1.5 shadow-xl font-mono text-[10px] text-[var(--text-primary)] min-w-[140px] z-50 relative">
      <div className="mb-1 text-[var(--text-secondary)]">UTC {label}</div>
      {activeEntries.length === 0 ? (
        <div className="text-[var(--text-muted)] italic">No detections</div>
      ) : (
        activeEntries.map((entry) => (
          <div key={entry.name} className="flex items-center justify-between gap-3">
            <span className="flex items-center gap-1.5 truncate">
              <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: entry.color }} />
              {getShortThreatName(entry.name)}
            </span>
            <span className="text-[var(--text-primary)] tabular-nums font-bold">{entry.value}</span>
          </div>
        ))
      )}
    </div>
  );
}

export function ThreatTrends({ alerts }: ThreatTrendsProps) {
  const [windowMinutes, setWindowMinutes] = useState(60);
  const [now, setNow] = useState(() => Date.now());
  const [isInitialRender, setIsInitialRender] = useState(true);
  const [hoveredSeries, setHoveredSeries] = useState<string | null>(null);

  useEffect(() => {
    const timer = setTimeout(() => setIsInitialRender(false), 650);
    return () => clearTimeout(timer);
  }, []);

  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now()), 3000);
    return () => window.clearInterval(interval);
  }, [windowMinutes]);

  const threatClasses = Object.values(ThreatClassEnum);
  const bucketMilliseconds = 5 * 60 * 1000;
  const start = Math.floor((now - windowMinutes * 60 * 1000) / bucketMilliseconds) * bucketMilliseconds;
  const bucketCount = Math.floor((windowMinutes * 60 * 1000) / bucketMilliseconds) + 1;
  const chartData = Array.from({ length: bucketCount }, (_, index) => {
    const bucketTimestamp = start + index * bucketMilliseconds;
    const counts = threatClasses.reduce<Record<string, number>>((result, threatClass) => {
      result[threatClass] = 0;
      return result;
    }, {});

    alerts.forEach((alert) => {
      const timestamp = new Date(alert.timestamp).getTime();
      if (!Number.isFinite(timestamp) || timestamp < start || timestamp > now) return;
      const alertBucket = Math.floor(timestamp / bucketMilliseconds) * bucketMilliseconds;
      if (alertBucket === bucketTimestamp && counts[alert.threat_class] !== undefined) {
        counts[alert.threat_class] += 1;
      }
    });

    return {
      timestamp: bucketTimestamp,
      time: new Date(bucketTimestamp).toISOString().substring(11, 16),
      ...counts,
    };
  });

  const maxDataValue = chartData.reduce((acc, curr) => {
    let currMax = 0;
    for (const cls of threatClasses) {
      const val = (curr as Record<string, any>)[cls] as number;
      if (val > currMax) currMax = val;
    }
    return Math.max(acc, currMax);
  }, 0);

  const niceMaxs = [5, 10, 20, 30, 50, 100, 200, 500, 1000];
  let niceMax = 5;
  for (const m of niceMaxs) {
    if (maxDataValue <= m) {
      niceMax = m;
      break;
    }
  }
  if (maxDataValue > 1000) niceMax = Math.ceil(maxDataValue / 500) * 500;

  let ticks = [0, 5];
  if (niceMax === 5) ticks = [0, 5];
  else if (niceMax === 10) ticks = [0, 5, 10];
  else if (niceMax === 20) ticks = [0, 10, 20];
  else if (niceMax === 30) ticks = [0, 10, 20, 30];
  else if (niceMax === 50) ticks = [0, 25, 50];
  else if (niceMax === 100) ticks = [0, 50, 100];
  else ticks = [0, Math.floor(niceMax / 2), niceMax];

  return (
    <div className="flex flex-col gap-4 h-full">
      <div className="flex items-center justify-between border-b border-[var(--hairline)] pb-3">
        <h2 className="text-[length:var(--text-label)] text-[var(--text-secondary)] uppercase tracking-widest opacity-80 h-[16px] flex items-center">Threat vectors</h2>
        <select value={windowMinutes} onChange={(event) => setWindowMinutes(Number(event.target.value))} className="h-6 rounded bg-[var(--bg-surface-hover)] border border-[var(--hairline)] px-2 text-[10px] text-[var(--text-secondary)] font-mono outline-none focus:border-emerald-500/50">
          <option value={60}>LAST 1H</option>
          <option value={360}>LAST 6H</option>
          <option value={1440}>LAST 24H</option>
        </select>
      </div>
      <div className="flex-1 w-full min-h-0">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartData} margin={{ top: 5, right: 10, left: -25, bottom: 0 }}>
            <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={11} tickLine={false} axisLine={false} />
            <YAxis allowDecimals={false} stroke="var(--text-muted)" fontSize={11} tickLine={false} axisLine={false} domain={[0, niceMax]} ticks={ticks} />
            <Tooltip content={<TrendTooltip />} cursor={{ stroke: "var(--hairline)", strokeWidth: 1 }} position={{ y: 0 }} offset={30} isAnimationActive={false} />
            <Legend 
              wrapperStyle={{ fontSize: "10px", color: "var(--text-secondary)", fontFamily: "monospace", transition: "all 0.12s" }} 
              iconType="circle" 
              iconSize={6} 
              formatter={(value) => getShortThreatName(value as string)}
              onMouseEnter={(e: any) => setHoveredSeries(e.dataKey)}
              onMouseLeave={() => setHoveredSeries(null)}
            />
            {threatClasses.map((threatClass, index) => {
              const isHovered = hoveredSeries === threatClass;
              const opacity = hoveredSeries ? (isHovered ? 1 : 0.2) : 1;
              return (
                <Line 
                  key={threatClass} 
                  type="step" 
                  dataKey={threatClass} 
                  stroke={vectorColors[index % vectorColors.length]} 
                  strokeWidth={1.5} 
                  dot={false} 
                  activeDot={{ r: 3 }} 
                  name={threatClass} 
                  isAnimationActive={isInitialRender} 
                  animationDuration={600}
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
