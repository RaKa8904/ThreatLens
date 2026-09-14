import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ThreatClassEnum,
  ThresholdConfigResponse,
  ThresholdEntry,
  SuppressionRule,
  SuppressionRuleCreate,
} from "@/types/threat";

interface DetectionConfigProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

type RowState = "idle" | "saving" | "saved" | "error";

const RULE_TYPE_LABELS: Record<SuppressionRule["rule_type"], string> = {
  source_ip: "Source IP",
  destination_ip: "Destination IP",
  source_ip_threat_class: "Source IP + Threat Class",
};

function describeValue(entry: ThresholdEntry): string {
  return Array.isArray(entry.value) ? entry.value.join(", ") : String(entry.value);
}

function rangeHint(entry: ThresholdEntry): string {
  const bounds = [];
  if (entry.min !== null) bounds.push(`min ${entry.min}`);
  if (entry.max !== null) bounds.push(`max ${entry.max}`);
  if (entry.kind === "int_list") bounds.push("comma-separated ports");
  return bounds.length ? bounds.join(" · ") : "no bounds";
}

export function DetectionConfig({ open, onOpenChange }: DetectionConfigProps) {
  const [config, setConfig] = useState<ThresholdConfigResponse | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [rowState, setRowState] = useState<Record<string, RowState>>({});
  const [rowMessage, setRowMessage] = useState<Record<string, string>>({});

  const [rules, setRules] = useState<SuppressionRule[]>([]);
  const [rulesError, setRulesError] = useState<string | null>(null);
  const [draft, setDraft] = useState<SuppressionRuleCreate>({
    rule_type: "source_ip",
    source_ip: "",
    description: "",
    threat_class: null,
    enabled: true,
  });
  const [addError, setAddError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const key = (entry: ThresholdEntry) => `${entry.rule}.${entry.parameter}`;

  const loadThresholds = useCallback(async () => {
    try {
      const response = await fetch("/api/config/thresholds");
      if (!response.ok) throw new Error(`threshold request failed (${response.status})`);
      const data: ThresholdConfigResponse = await response.json();
      setConfig(data);
      setDrafts({});
      setLoadError(null);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : "threshold request failed");
    }
  }, []);

  const loadRules = useCallback(async () => {
    try {
      const response = await fetch("/api/config/suppressions");
      if (!response.ok) throw new Error(`suppression request failed (${response.status})`);
      setRules(await response.json());
      setRulesError(null);
    } catch (error) {
      setRulesError(error instanceof Error ? error.message : "suppression request failed");
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    void loadThresholds();
    void loadRules();
  }, [open, loadThresholds, loadRules]);

  const grouped = useMemo(() => {
    const groups = new Map<string, ThresholdEntry[]>();
    for (const entry of config?.thresholds ?? []) {
      const bucket = groups.get(entry.rule_label) ?? [];
      bucket.push(entry);
      groups.set(entry.rule_label, bucket);
    }
    return [...groups.entries()];
  }, [config]);

  const saveThreshold = async (entry: ThresholdEntry) => {
    const id = key(entry);
    const raw = drafts[id] ?? describeValue(entry);
    const value = entry.kind === "int_list"
      ? raw.split(",").map((part) => Number(part.trim())).filter((part) => Number.isFinite(part))
      : Number(raw);

    setRowState((current) => ({ ...current, [id]: "saving" }));
    setRowMessage((current) => ({ ...current, [id]: "" }));
    try {
      const response = await fetch("/api/config/thresholds", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rule: entry.rule, parameter: entry.parameter, value }),
      });
      if (!response.ok) {
        const detail = await response.json().catch(() => null);
        throw new Error(detail?.detail ?? `update failed (${response.status})`);
      }
      const data: ThresholdConfigResponse = await response.json();
      setConfig(data);
      setDrafts((current) => {
        const next = { ...current };
        delete next[id];
        return next;
      });
      setRowState((current) => ({ ...current, [id]: "saved" }));
    } catch (error) {
      setRowState((current) => ({ ...current, [id]: "error" }));
      setRowMessage((current) => ({
        ...current,
        [id]: error instanceof Error ? error.message : "update failed",
      }));
    }
  };

  const addRule = async () => {
    setAdding(true);
    setAddError(null);
    const payload: SuppressionRuleCreate = {
      rule_type: draft.rule_type,
      description: draft.description?.trim() ? draft.description.trim() : null,
      source_ip: draft.source_ip?.trim() ? draft.source_ip.trim() : null,
      destination_ip: draft.destination_ip?.trim() ? draft.destination_ip.trim() : null,
      threat_class: draft.rule_type === "source_ip_threat_class" ? draft.threat_class : null,
      enabled: draft.enabled,
    };
    try {
      const response = await fetch("/api/config/suppressions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const detail = await response.json().catch(() => null);
        const message = Array.isArray(detail?.detail)
          ? detail.detail.map((item: { msg?: string }) => item.msg ?? "invalid value").join("; ")
          : detail?.detail;
        throw new Error(message ?? `add failed (${response.status})`);
      }
      setDraft({
        rule_type: draft.rule_type,
        source_ip: "",
        destination_ip: "",
        description: "",
        threat_class: null,
        enabled: true,
      });
      await loadRules();
    } catch (error) {
      setAddError(error instanceof Error ? error.message : "add failed");
    } finally {
      setAdding(false);
    }
  };

  const deleteRule = async (ruleId: string) => {
    setRulesError(null);
    try {
      const response = await fetch(`/api/config/suppressions/${encodeURIComponent(ruleId)}`, {
        method: "DELETE",
      });
      if (!response.ok) throw new Error(`delete failed (${response.status})`);
      await loadRules();
    } catch (error) {
      setRulesError(error instanceof Error ? error.message : "delete failed");
    }
  };

  const needsSourceIp = draft.rule_type !== "destination_ip";
  const needsDestinationIp = draft.rule_type === "destination_ip";

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full lg:max-w-2xl">
        <SheetClose />
        <SheetHeader>
          <SheetTitle>Detection Configuration</SheetTitle>
          <SheetDescription>
            Analyst-configurable detection thresholds and suppression rules. Changes apply to
            subsequent detections immediately; no restart required.
          </SheetDescription>
        </SheetHeader>

        {config && (
          <div className="mt-3 flex items-center gap-2">
            <Badge variant={config.persistent ? "success" : "high"}>
              {config.persistent ? "PERSISTED (REDIS)" : "RUNTIME ONLY"}
            </Badge>
            <span className="text-[11px] font-mono text-slate-500">
              {config.persistent
                ? "Configuration is stored durably and restored on restart."
                : "No durable store reachable — changes are lost when the backend restarts."}
            </span>
          </div>
        )}

        <Tabs defaultValue="thresholds" className="mt-4">
          <TabsList>
            <TabsTrigger value="thresholds">Thresholds</TabsTrigger>
            <TabsTrigger value="suppressions">Suppression Rules</TabsTrigger>
          </TabsList>

          <TabsContent value="thresholds" className="mt-4">
            {loadError && <p className="text-xs text-rose-400 font-mono">{loadError}</p>}
            {!config && !loadError && <p className="text-xs text-slate-500 font-mono">Loading thresholds...</p>}
            {grouped.map(([ruleLabel, entries]) => (
              <section key={ruleLabel} className="mb-5">
                <h4 className="mb-2 text-[11px] font-mono uppercase tracking-wider text-slate-400">
                  {ruleLabel}
                </h4>
                <div className="space-y-2">
                  {entries.map((entry) => {
                    const id = key(entry);
                    const state = rowState[id] ?? "idle";
                    return (
                      <div
                        key={id}
                        className="rounded-md border border-slate-800/80 bg-slate-900/40 p-3 space-y-2"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div>
                            <div className="text-xs font-semibold text-slate-200">{entry.label}</div>
                            <div className="text-[10px] font-mono text-slate-500">
                              {entry.rule}.{entry.parameter} · consumed by {entry.consumed_by}
                            </div>
                          </div>
                          <div className="flex items-center gap-1.5">
                            {entry.modified && <Badge variant="low">MODIFIED</Badge>}
                            <Badge variant="outline">{entry.kind}</Badge>
                          </div>
                        </div>

                        <p className="text-[11px] text-slate-400">{entry.description}</p>

                        <div className="flex flex-wrap items-center gap-2">
                          <input
                            aria-label={`${entry.label} value`}
                            value={drafts[id] ?? describeValue(entry)}
                            onChange={(event) =>
                              setDrafts((current) => ({ ...current, [id]: event.target.value }))
                            }
                            className="h-7 w-40 rounded border border-slate-800 bg-slate-950/70 px-2 font-mono text-xs text-slate-100 focus:border-cyan-500/60 focus:outline-none"
                          />
                          <span className="text-[10px] font-mono text-slate-500">{rangeHint(entry)}</span>
                          <span className="text-[10px] font-mono text-slate-600">
                            default {Array.isArray(entry.default) ? entry.default.join(", ") : entry.default}
                          </span>
                          <Button
                            size="sm"
                            variant="subtle"
                            disabled={state === "saving"}
                            onClick={() => void saveThreshold(entry)}
                          >
                            {state === "saving" ? "Saving..." : "Save"}
                          </Button>
                          {state === "saved" && (
                            <span className="text-[10px] font-mono text-emerald-400">Applied</span>
                          )}
                          {state === "error" && (
                            <span className="text-[10px] font-mono text-rose-400">{rowMessage[id]}</span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>
            ))}
          </TabsContent>

          <TabsContent value="suppressions" className="mt-4">
            <div className="rounded-md border border-slate-800/80 bg-slate-900/40 p-3 space-y-2">
              <div className="text-xs font-semibold text-slate-200">Add suppression rule</div>
              <p className="text-[11px] text-slate-400">
                Matching detections are still evaluated and recorded with full evidence; only
                delivery to this console is withheld.
              </p>
              <div className="flex flex-wrap items-center gap-2">
                <select
                  aria-label="Rule type"
                  value={draft.rule_type}
                  onChange={(event) =>
                    setDraft((current) => ({
                      ...current,
                      rule_type: event.target.value as SuppressionRule["rule_type"],
                    }))
                  }
                  className="h-7 rounded border border-slate-800 bg-slate-950/70 px-2 font-mono text-xs text-slate-100 focus:border-cyan-500/60 focus:outline-none"
                >
                  {Object.entries(RULE_TYPE_LABELS).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>

                {needsSourceIp && (
                  <input
                    aria-label="Source IP or CIDR"
                    placeholder="192.168.1.0/24"
                    value={draft.source_ip ?? ""}
                    onChange={(event) =>
                      setDraft((current) => ({ ...current, source_ip: event.target.value }))
                    }
                    className="h-7 w-44 rounded border border-slate-800 bg-slate-950/70 px-2 font-mono text-xs text-slate-100 focus:border-cyan-500/60 focus:outline-none"
                  />
                )}

                {needsDestinationIp && (
                  <input
                    aria-label="Destination IP or CIDR"
                    placeholder="10.0.0.10"
                    value={draft.destination_ip ?? ""}
                    onChange={(event) =>
                      setDraft((current) => ({ ...current, destination_ip: event.target.value }))
                    }
                    className="h-7 w-44 rounded border border-slate-800 bg-slate-950/70 px-2 font-mono text-xs text-slate-100 focus:border-cyan-500/60 focus:outline-none"
                  />
                )}

                {draft.rule_type === "source_ip_threat_class" && (
                  <select
                    aria-label="Threat class"
                    value={draft.threat_class ?? ""}
                    onChange={(event) =>
                      setDraft((current) => ({
                        ...current,
                        threat_class: (event.target.value || null) as ThreatClassEnum | null,
                      }))
                    }
                    className="h-7 rounded border border-slate-800 bg-slate-950/70 px-2 font-mono text-xs text-slate-100 focus:border-cyan-500/60 focus:outline-none"
                  >
                    <option value="">Any class</option>
                    {Object.values(ThreatClassEnum).map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <input
                  aria-label="Reason"
                  placeholder="Reason (optional)"
                  value={draft.description ?? ""}
                  onChange={(event) =>
                    setDraft((current) => ({ ...current, description: event.target.value }))
                  }
                  className="h-7 w-64 rounded border border-slate-800 bg-slate-950/70 px-2 text-xs text-slate-100 focus:border-cyan-500/60 focus:outline-none"
                />
                <label className="flex items-center gap-1.5 text-[11px] font-mono text-slate-400">
                  <input
                    type="checkbox"
                    checked={draft.enabled ?? true}
                    onChange={(event) =>
                      setDraft((current) => ({ ...current, enabled: event.target.checked }))
                    }
                  />
                  Enabled
                </label>
                <Button size="sm" disabled={adding} onClick={() => void addRule()}>
                  {adding ? "Adding..." : "Add Rule"}
                </Button>
              </div>

              {addError && <p className="text-[10px] font-mono text-rose-400">{addError}</p>}
            </div>

            {rulesError && <p className="mt-3 text-xs text-rose-400 font-mono">{rulesError}</p>}

            <div className="mt-4 space-y-2">
              {rules.length === 0 && !rulesError && (
                <p className="text-xs text-slate-500 font-mono">No suppression rules defined.</p>
              )}
              {rules.map((rule) => (
                <div
                  key={rule.id}
                  className="flex items-start justify-between gap-3 rounded-md border border-slate-800/80 bg-slate-900/40 p-3"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Badge variant={rule.enabled ? "success" : "outline"}>
                        {rule.enabled ? "ENABLED" : "DISABLED"}
                      </Badge>
                      <span className="font-mono text-xs text-slate-200">
                        {rule.source_ip ?? rule.destination_ip}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">
                        {RULE_TYPE_LABELS[rule.rule_type]}
                        {rule.threat_class ? ` · ${rule.threat_class}` : ""}
                      </span>
                    </div>
                    {rule.description && (
                      <p className="mt-1 text-[11px] text-slate-400 break-words">{rule.description}</p>
                    )}
                    <p className="mt-1 font-mono text-[10px] text-slate-600">
                      {rule.id} · added {rule.created_at}
                    </p>
                  </div>
                  <Button size="sm" variant="subtle" onClick={() => void deleteRule(rule.id)}>
                    Delete
                  </Button>
                </div>
              ))}
            </div>
          </TabsContent>
        </Tabs>
      </SheetContent>
    </Sheet>
  );
}
