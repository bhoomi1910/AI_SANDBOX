import { useState } from "react";
import { useOutletContext } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Crosshair, X, Loader2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/badge";
import { mitreTechniques as mockTechniques, mitreTactics as mockTactics } from "@/data/deepdive";
import { cn } from "@/lib/utils";
import { api, USE_BACKEND } from "@/lib/api";
import type { Investigation, MitreTechnique } from "@/data/types";

const sevBg: Record<string, string> = {
  critical: "border-critical/40 bg-critical/10 hover:bg-critical/20",
  high: "border-high/40 bg-high/10 hover:bg-high/20",
  medium: "border-medium/40 bg-medium/10 hover:bg-medium/20",
  low: "border-low/40 bg-low/10 hover:bg-low/20",
  info: "border-info/40 bg-info/10 hover:bg-info/20",
  clean: "border-success/40 bg-success/10 hover:bg-success/20",
};

function mapLive(t: Record<string, unknown>): MitreTechnique {
  const evidence = (t.evidence as string[]) ?? [];
  const findings = (t.findings as string[]) ?? [];
  return {
    id: t.technique_id as string,
    name: t.technique as string,
    tactic: t.tactic as string,
    description:
      findings.length > 0
        ? findings.join(" · ")
        : "Evidence-backed mapping from static indicators.",
    severity: (t.severity as MitreTechnique["severity"]) ?? "info",
    evidence: evidence.join(" · ") || "No raw evidence snippet recorded.",
  };
}

export default function Mitre() {
  const { inv } = useOutletContext<{ inv: Investigation }>();
  const [active, setActive] = useState<MitreTechnique | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["mitre", inv.id],
    queryFn: () => api.getMitre(inv.id),
    enabled: USE_BACKEND,
    retry: 1,
  });

  const live = USE_BACKEND && data?.status === "completed"
    ? (data.techniques as Record<string, unknown>[]).map(mapLive)
    : null;
  const isPending = USE_BACKEND && data?.status === "pending";
  const techniques = live ?? mockTechniques;
  const tactics = live
    ? Array.from(new Set(techniques.map((t) => t.tactic)))
    : mockTactics;

  if (isLoading && USE_BACKEND && !data) {
    return (
      <div className="grid place-items-center rounded-xl border border-border bg-surface/40 py-24 text-center">
        <Loader2 className="mb-3 size-8 animate-spin text-primary" />
        <p className="text-sm font-medium text-foreground">Loading MITRE mapping…</p>
      </div>
    );
  }

  if (isPending) {
    return (
      <div className="grid place-items-center rounded-xl border border-border bg-surface/40 py-24 text-center">
        <Loader2 className="mb-3 size-8 animate-spin text-primary" />
        <p className="text-sm font-medium text-foreground">Static analysis is still running…</p>
        <p className="mt-1 text-xs text-muted-foreground">Evidence-backed MITRE mappings will appear here when ready.</p>
      </div>
    );
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
      {/* Kill chain flow */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Crosshair className="size-4 text-primary" /> Attack Kill-Chain</CardTitle>
          <span className="text-xs text-muted-foreground">{techniques.length} technique{techniques.length === 1 ? "" : "s"} · {tactics.length} tactic{tactics.length === 1 ? "" : "s"}</span>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-1 overflow-x-auto pb-2 no-scrollbar">
            {tactics.map((tactic, i) => {
              const count = techniques.filter((t) => t.tactic === tactic).length;
              return (
                <div key={tactic} className="flex items-center">
                  <div className="flex min-w-[120px] flex-col items-center rounded-lg border border-border bg-surface/50 px-3 py-2.5 text-center">
                    <span className="grid size-6 place-items-center rounded-full bg-primary/15 text-[0.7rem] font-bold text-primary">{i + 1}</span>
                    <span className="mt-1.5 text-xs font-medium text-foreground">{tactic}</span>
                    <span className="text-[0.65rem] text-muted-foreground">{count} technique{count !== 1 ? "s" : ""}</span>
                  </div>
                  {i < tactics.length - 1 && <div className="h-px w-4 shrink-0 bg-gradient-to-r from-primary/40 to-primary/10" />}
                </div>
              );
            })}
            {tactics.length === 0 && <span className="text-xs text-muted-foreground">No techniques mapped for this sample.</span>}
          </div>
        </CardContent>
      </Card>

      {/* Matrix */}
      <div>
        <h3 className="mb-3 text-sm font-semibold text-foreground">ATT&CK Matrix — mapped techniques</h3>
        <div className="grid grid-flow-col gap-3 overflow-x-auto pb-2 no-scrollbar" style={{ gridAutoColumns: "minmax(190px, 1fr)" }}>
          {tactics.map((tactic) => {
              const techs = techniques.filter((t) => t.tactic === tactic);
              return (
                <div key={tactic} className="flex flex-col gap-2">
                  <div className="rounded-lg border border-border bg-surface-overlay/40 px-3 py-2 text-center">
                    <div className="text-xs font-semibold text-foreground">{tactic}</div>
                  </div>
                  {techs.map((t) => (
                    <button
                      key={t.id}
                      onClick={() => setActive(t)}
                      className={cn("rounded-lg border p-2.5 text-left transition-colors cursor-pointer", sevBg[t.severity])}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[0.7rem] font-bold text-foreground">{t.id}</span>
                        <span className="size-1.5 rounded-full" style={{ background: sevColor(t.severity) }} />
                      </div>
                      <div className="mt-1 text-xs font-medium text-foreground">{t.name}</div>
                    </button>
                  ))}
                  {techs.length === 0 && (
                    <div className="rounded-lg border border-dashed border-border px-3 py-2 text-center text-[0.7rem] text-muted-foreground/60">no mappings</div>
                  )}
                </div>
              );
          })}
        </div>
      </div>

      {/* Technique detail drawer */}
      {active && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="fixed inset-0 z-50 flex items-end justify-center bg-black/50 backdrop-blur-sm sm:items-center"
          onClick={() => setActive(null)}
        >
          <motion.div
            initial={{ y: 40, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            className="panel-raised w-full max-w-lg p-6"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-bold text-primary">{active.id}</span>
                  <SeverityBadge severity={active.severity} />
                </div>
                <h3 className="mt-1 text-lg font-bold text-foreground">{active.name}</h3>
                <div className="text-xs text-muted-foreground">{active.tactic}</div>
              </div>
              <button onClick={() => setActive(null)} className="grid size-8 place-items-center rounded-lg border border-border text-muted-foreground hover:text-foreground cursor-pointer">
                <X className="size-4" />
              </button>
            </div>
            <p className="mt-4 text-sm leading-relaxed text-muted-foreground">{active.description}</p>
            <div className="mt-4 rounded-lg border border-border bg-surface/50 p-3">
              <div className="text-[0.65rem] uppercase tracking-wide text-muted-foreground">Evidence in this sample</div>
              <div className="mt-1 break-all font-mono text-xs text-foreground">{active.evidence}</div>
            </div>
            <a href={`https://attack.mitre.org/techniques/${active.id}/`} target="_blank" rel="noreferrer" className="mt-4 inline-flex text-xs text-primary hover:underline">
              View on attack.mitre.org →
            </a>
          </motion.div>
        </motion.div>
      )}
    </motion.div>
  );
}

function sevColor(sev: string) {
  return { critical: "#f43f5e", high: "#fb923c", medium: "#facc15", low: "#38bdf8", info: "#818cf8", clean: "#34d399" }[sev];
}
