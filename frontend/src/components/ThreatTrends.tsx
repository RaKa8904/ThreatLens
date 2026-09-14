import { useEffect, useState } from "react";
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ThreatAlertSchema, ThreatClassEnum } from "@/types/threat";

interface ThreatTrendsProps {
  alerts: ThreatAlertSchema[];
}

const vectorColors = ["#38bdf8", "#a78bfa", "#22d3ee", "#e879f9", "#60a5fa", "#818cf8"];

function TrendTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded border border-zinc-700 bg-[#090d16]/95 px-2 py-1.5 shadow-xl font-mono text-[10px]">
      <div className="mb-1 text-zinc-400">UTC {label}</div>
      {payload.filter((entry) => entry.value > 0).map((entry) => (
        <div key={entry.name} className="flex max-w-[220px] items-center justify-between gap-3">
          <span className="truncate" style={{ color: entry.color }}>{entry.name}</span>
          <span className="text-zinc-100">{entry.value}</span>
        </div>
      ))}
    </div>
  );
}

export function ThreatTrends({ alerts }: ThreatTrendsProps) {
  const [windowMinutes, setWindowMinutes] = useState(60);
  const [now, setNow] = useState(() => Date.now());

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

  return (
    <Card className="border-zinc-800/80 bg-[#090d16]/80 backdrop-blur-xl">
      <CardHeader className="py-3 px-4 flex flex-row items-center justify-between border-b border-zinc-800/60 space-y-0">
        <CardTitle className="text-[length:var(--text-heading)] uppercase font-mono tracking-wider text-zinc-300">Threat Vectors &amp; Trends</CardTitle>
        <select value={windowMinutes} onChange={(event) => setWindowMinutes(Number(event.target.value))} className="h-7 rounded bg-zinc-900 border border-zinc-800 px-2 text-[11px] text-zinc-300 font-mono">
          <option value={60}>LAST 1H</option>
          <option value={360}>LAST 6H</option>
          <option value={1440}>LAST 24H</option>
        </select>
      </CardHeader>
      <CardContent className="p-3">
        <div className="h-48 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
              <XAxis dataKey="time" stroke="#52525b" fontSize={9} tickLine={false} axisLine={false} />
              <YAxis allowDecimals={false} stroke="#52525b" fontSize={9} tickLine={false} axisLine={false} />
              <Tooltip content={<TrendTooltip />} cursor={false} />
              {threatClasses.map((threatClass, index) => (
                <Line key={threatClass} type="monotone" dataKey={threatClass} stroke={vectorColors[index % vectorColors.length]} strokeWidth={2} dot={false} activeDot={{ r: 3 }} name={threatClass} isAnimationActive={false} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
