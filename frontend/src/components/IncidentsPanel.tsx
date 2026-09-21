import { useEffect, useState } from "react";
import { ArrowDown01Icon as ChevronDown } from "hugeicons-react";
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
  const [isOpen, setIsOpen] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem("threatlens_incidents_panel_open");
      return saved !== null ? saved === "true" : true;
    } catch {
      return true;
    }
  });

  const toggleOpen = () => {
    setIsOpen((prev) => {
      const next = !prev;
      try {
        localStorage.setItem("threatlens_incidents_panel_open", String(next));
      } catch {
        // ignore
      }
      return next;
    });
  };

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
    <Card className={`border-zinc-800/80 bg-[#090d16]/80 backdrop-blur-xl flex flex-col overflow-hidden transition-all duration-300 ${isOpen ? "h-[600px]" : "h-auto"}`}>
      <CardHeader
        role="button"
        tabIndex={0}
        aria-expanded={isOpen}
        aria-label={isOpen ? "Hide incident section" : "Show incident section"}
        onClick={toggleOpen}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            toggleOpen();
          }
        }}
        className={`py-3 px-4 flex flex-row items-center justify-between cursor-pointer select-none space-y-0 transition-colors hover:bg-zinc-800/30 ${
          isOpen ? "border-b border-zinc-800/60" : ""
        }`}
      >
        <div className="flex items-center gap-2.5">
          <CardTitle className="text-[length:var(--text-heading)] uppercase font-mono tracking-wider text-zinc-300">
            Incidents
          </CardTitle>
          {incidents.length > 0 && (
            <span className="rounded bg-zinc-800/80 px-2 py-0.5 font-mono text-[10px] text-zinc-400 border border-zinc-700/50">
              {incidents.length} active
            </span>
          )}
        </div>
        <button
          type="button"
          aria-label={isOpen ? "Hide incident section" : "Show incident section"}
          className="rounded p-1 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60 transition-colors focus:outline-none"
          onClick={(e) => {
            e.stopPropagation();
            toggleOpen();
          }}
        >
          <ChevronDown
            className={`h-4 w-4 transition-transform duration-300 ${
              isOpen ? "rotate-180 text-cyan-400" : "rotate-0 text-zinc-400"
            }`}
          />
        </button>
      </CardHeader>
      {isOpen && (
        <CardContent className="min-h-0 flex-1 overflow-y-auto p-3 space-y-2">
          {incidents.length === 0 && (
            <div className="font-mono text-[length:var(--text-label)] text-zinc-600">
              No correlated incidents.
            </div>
          )}
          {incidents.map((incident) => (
            <div
              key={incident.incident_id}
              className="rounded border border-zinc-800/70 p-3 font-mono text-[11px] bg-zinc-900/30 hover:border-zinc-700/80 transition-colors"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 text-cyan-300">
                <span className="font-semibold">{incident.source_ip ?? "Unknown source"}</span>
                <span className="text-zinc-400">{incident.alerts.length} alerts</span>
              </div>
              <div className="mt-1 flex flex-wrap gap-1">
                {incident.threat_classes.map((threatClass) => (
                  <span
                    key={threatClass}
                    className="rounded border border-zinc-700 bg-zinc-800/50 px-1.5 py-0.5 text-zinc-400"
                  >
                    {threatClass}
                  </span>
                ))}
              </div>
              <div className="mt-2 text-zinc-600">
                {new Date(incident.first_seen).toISOString()} to{" "}
                {new Date(incident.last_seen).toISOString()}
              </div>
            </div>
          ))}
        </CardContent>
      )}
    </Card>
  );
}

