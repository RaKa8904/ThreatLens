import { useEffect, useState } from "react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ThreatClassEnum } from "@/types/threat";

interface TrendPoint {
  timestamp: string;
  counts: Record<string, number>;
}

interface TrendPayload {
  threat_classes: string[];
  points: TrendPoint[];
}

const vectorColors = ["#fb7185", "#f59e0b", "#22d3ee", "#a78bfa", "#facc15", "#34d399"];

export function ThreatTrends() {
  const [windowMinutes, setWindowMinutes] = useState(60);
  const [payload, setPayload] = useState<TrendPayload>({ threat_classes: Object.values(ThreatClassEnum), points: [] });

  useEffect(() => {
    let mounted = true;
    fetch(`/api/analytics/trends?window_minutes=${windowMinutes}&bucket_minutes=5`)
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("trend request failed")))
      .then((data: TrendPayload) => { if (mounted) setPayload(data); })
      .catch(() => { if (mounted) setPayload((current) => ({ ...current, points: [] })); });
    return () => { mounted = false; };
  }, [windowMinutes]);

  const chartData = payload.points.map((point) => ({
    time: new Date(point.timestamp).toISOString().substring(11, 16),
    ...point.counts,
  }));

  return (
    <Card className="border-zinc-800/80 bg-[#090d16]/80 backdrop-blur-xl">
      <CardHeader className="py-3 px-4 flex flex-row items-center justify-between border-b border-zinc-800/60 space-y-0">
        <CardTitle className="text-xs uppercase font-mono tracking-wider text-zinc-300">Threat Vectors &amp; Trends</CardTitle>
        <select value={windowMinutes} onChange={(event) => setWindowMinutes(Number(event.target.value))} className="h-7 rounded bg-zinc-900 border border-zinc-800 px-2 text-[11px] text-zinc-300 font-mono">
          <option value={60}>LAST 1H</option>
          <option value={360}>LAST 6H</option>
          <option value={1440}>LAST 24H</option>
        </select>
      </CardHeader>
      <CardContent className="p-3">
        <div className="h-48 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
              <XAxis dataKey="time" stroke="#52525b" fontSize={9} tickLine={false} axisLine={false} />
              <YAxis allowDecimals={false} stroke="#52525b" fontSize={9} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={{ backgroundColor: "#090d16", borderColor: "#27272a", fontSize: "10px", fontFamily: "monospace" }} />
              {payload.threat_classes.map((threatClass, index) => (
                <Area key={threatClass} type="monotone" dataKey={threatClass} stackId="threats" stroke={vectorColors[index % vectorColors.length]} fill={vectorColors[index % vectorColors.length]} fillOpacity={0.28} name={threatClass} isAnimationActive={false} />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
