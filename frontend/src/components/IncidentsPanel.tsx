import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface Incident {
  incident_id: string;
  source_ip?: string | null;
  first_seen: string;
  last_seen: string;
  threat_classes: string[];
  alerts: Array<{ flow_id: string; confidence_score: number }>;
}

export function IncidentsPanel() {
  const [incidents, setIncidents] = useState<Incident[]>([]);

  useEffect(() => {
    let mounted = true;
    const refresh = () => fetch("/api/incidents?limit=20")
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("incident request failed")))
      .then((data: Incident[]) => { if (mounted) setIncidents(data); })
      .catch(() => { if (mounted) setIncidents([]); });
    refresh();
    const interval = window.setInterval(refresh, 5000);
    return () => { mounted = false; window.clearInterval(interval); };
  }, []);

  return (
    <Card className="border-zinc-800/80 bg-[#090d16]/80 backdrop-blur-xl">
      <CardHeader className="border-b border-zinc-800/60 py-3 px-4">
        <CardTitle className="text-[length:var(--text-heading)] uppercase font-mono tracking-wider text-zinc-300">Incidents</CardTitle>
      </CardHeader>
      <CardContent className="p-3 space-y-2">
        {incidents.length === 0 && <div className="font-mono text-[length:var(--text-label)] text-zinc-600">No correlated incidents.</div>}
        {incidents.map((incident) => (
          <div key={incident.incident_id} className="rounded border border-zinc-800/70 p-3 font-mono text-[11px]">
            <div className="flex flex-wrap items-center justify-between gap-2 text-cyan-300"><span>{incident.source_ip ?? "Unknown source"}</span><span>{incident.alerts.length} alerts</span></div>
            <div className="mt-1 flex flex-wrap gap-1">{incident.threat_classes.map((threatClass) => <span key={threatClass} className="rounded border border-zinc-700 px-1.5 py-0.5 text-zinc-400">{threatClass}</span>)}</div>
            <div className="mt-2 text-zinc-600">{new Date(incident.first_seen).toISOString()} to {new Date(incident.last_seen).toISOString()}</div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
