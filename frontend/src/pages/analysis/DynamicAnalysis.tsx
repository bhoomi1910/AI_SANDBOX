import { useOutletContext } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Cpu,
  ArrowRight,
  Shield,
  Loader2,
  Info,
  Clock,
  Layers,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge, SeverityBadge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { dynamicAnalysis as mockDyn, iocs as mockIocs } from "@/data/deepdive";
import { api, USE_BACKEND } from "@/lib/api";
import type { Investigation } from "@/data/types";
import type { Severity } from "@/components/ui/badge";

type LiveEvidence = {
  id: string;
  category: string;
  type: string;
  value: string;
  source_module: string;
  severity: string;
  confidence: number;
  description: string;
  evidence: string;
  mitre_techniques: string[];
};

type LiveIoc = {
  id: string;
  type: string;
  value: string;
  severity: string;
  confidence: number;
  sources: { module: string; evidence_id: string; context: string }[];
  count: number;
  mitre_techniques: string[];
};

const EVIDENCE_CATEGORIES_ORDER = [
  "execution",
  "persistence",
  "evasion",
  "api",
  "file",
  "yara",
  "capability",
  "metadata",
] as const;

const CATEGORY_LABELS: Record<string, string> = {
  execution: "Execution Indicators",
  persistence: "Persistence Indicators",
  evasion: "Evasion Indicators",
  api: "API / Import Indicators",
  file: "File Artifacts",
  yara: "YARA Matches",
  capability: "Capability Indicators",
  metadata: "Metadata",
};

export default function DynamicAnalysis() {
  const { inv } = useOutletContext<{ inv: Investigation }>();

  const staticQ = useQuery({
    queryKey: ["static", inv.id],
    queryFn: () => api.getStaticAnalysis(inv.id),
    enabled: USE_BACKEND && inv.status === "completed",
    retry: 1,
  });

  const iocQ = useQuery({
    queryKey: ["iocs", inv.id],
    queryFn: () => api.getIocs(inv.id),
    enabled: USE_BACKEND && inv.status === "completed",
    retry: 1,
  });

  const allEvidence =
    (staticQ.data?.result?.evidence as LiveEvidence[] | undefined) ?? [];
  const allIocs = (iocQ.data?.iocs as LiveIoc[] | undefined) ?? [];

  // Execution-relevant: category is execution/persistence/evasion OR type is api/capability
  const executionEvidence = allEvidence.filter(
    (e) =>
      e.category === "execution" ||
      e.category === "persistence" ||
      e.category === "evasion" ||
      e.category === "api" ||
      e.category === "capability"
  );

  // IOCs relevant to dynamic analysis: hashes, commands, registry, windows_path, mutex
  const executionIocs = allIocs.filter((i) =>
    new Set(["hash", "command", "registry", "windows_path", "mutex"]).has(
      i.type
    )
  );

  // Group evidence by category
  const evidenceByCategory = executionEvidence.reduce<
    Record<string, LiveEvidence[]>
  >((acc, ev) => {
    (acc[ev.category] ??= []).push(ev);
    return acc;
  }, {});

  const useLive = USE_BACKEND && inv.status === "completed";
  const isPending = USE_BACKEND && inv.status !== "completed";

  // Mock timeline fallback
  const displayTimeline = useLive
    ? executionEvidence.slice(0, 12).map((ev, i) => ({
        step: i + 1,
        label: `${ev.source_module}: ${ev.type}`,
        detail: ev.description,
        severity: ev.severity,
        mitre: ev.mitre_techniques?.[0],
      }))
    : (mockDyn.timeline ?? []).slice(0, 12).map((t, i) => ({
        step: i + 1,
        label: t.action,
        detail: t.detail,
        severity: "info" as const,
        mitre: undefined,
      }));

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-4"
    >
      {/* Static-only notice */}
      <Card className="border-medium/20 bg-medium/5">
        <CardContent className="flex items-start gap-3 pt-5">
          <Info className="mt-0.5 size-4 shrink-0 text-medium" />
          <div>
            <p className="text-sm text-muted-foreground">
              This platform performs <span className="font-medium text-foreground">static analysis only</span> — the
              sample is never detonated in a VM. The timeline below is{" "}
              <span className="font-medium text-foreground">inferred from file structure</span> — PE
              imports, control-flow patterns, registry paths, and embedded
              strings — rather than from observed runtime behaviour.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Summary */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          {
            k: String(executionEvidence.length),
            v: "Execution evidence",
            icon: Cpu,
            c: "#22d3ee",
          },
          {
            k: String(executionIocs.length),
            v: "Execution IOCs",
            icon: Layers,
            c: "#6366f1",
          },
          {
            k: String(
              new Set(executionEvidence.map((e) => e.source_module)).size
            ),
            v: "Contributing modules",
            icon: Shield,
            c: "#facc15",
          },
          {
            k: String(displayTimeline.length),
            v: "Timeline steps",
            icon: Clock,
            c: "#f43f5e",
          },
        ].map((s) => (
          <Card key={s.v}>
            <CardContent className="flex items-center gap-3 pt-5">
              <div
                className="grid size-10 place-items-center rounded-lg"
                style={{ background: `${s.c}1a`, color: s.c }}
              >
                <s.icon className="size-5" />
              </div>
              <div>
                <div className="text-xl font-bold text-foreground">{s.k}</div>
                <div className="text-[0.7rem] text-muted-foreground">{s.v}</div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Tabs: Timeline + Evidence + IOCs */}
      <Tabs defaultValue="timeline">
        <TabsList className="mb-4">
          <TabsTrigger value="timeline">
            <Clock className="mr-1.5 inline size-3.5" /> Execution Timeline
          </TabsTrigger>
          <TabsTrigger value="evidence">
            <Layers className="mr-1.5 inline size-3.5" /> Evidence Breakdown
          </TabsTrigger>
          <TabsTrigger value="iocs">
            <Cpu className="mr-1.5 inline size-3.5" /> Execution IOCs
          </TabsTrigger>
        </TabsList>

        {/* Timeline */}
        <TabsContent value="timeline">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock className="size-4 text-primary" /> Inferred Execution
                Timeline
              </CardTitle>
              <span className="text-xs text-muted-foreground">
                Steps inferred from file structure, not runtime observation
              </span>
            </CardHeader>
            <CardContent>
              {isPending ? (
                <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground">
                  <Loader2 className="size-4 animate-spin" /> Waiting for
                  analysis…
                </div>
              ) : displayTimeline.length === 0 ? (
                <p className="py-12 text-center text-sm text-muted-foreground">
                  No execution indicators found in this sample.
                </p>
              ) : (
                <div className="relative ml-4 space-y-0 border-l border-border pl-6">
                  {displayTimeline.map((step, idx) => (
                    <div
                      key={idx}
                      className="relative pb-8 last:pb-0"
                    >
                      <div
                        className="absolute -left-[31px] top-0 grid size-4 place-items-center rounded-full border border-border"
                        style={{
                          background:
                            step.severity === "high"
                              ? "#f43f5e"
                              : step.severity === "medium"
                                ? "#facc15"
                                : "#22d3ee",
                        }}
                      />
                      <div className="flex items-start gap-3">
                        <span className="mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-md bg-surface-overlay/60 text-[0.65rem] font-bold text-muted-foreground">
                          {String(step.step).padStart(2, "0")}
                        </span>
                        <div className="min-w-0 flex-1">
                          <p className="text-sm font-medium text-foreground">
                            {step.label}
                          </p>
                          <p className="mt-0.5 break-all font-mono text-xs text-muted-foreground">
                            {step.detail}
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-1.5">
                          <SeverityBadge severity={step.severity as Severity} />
                          {step.mitre && (
                            <Badge
                              tone="warn"
                              className="text-[0.65rem]"
                            >
                              {step.mitre}
                            </Badge>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Evidence Breakdown */}
        <TabsContent value="evidence">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Layers className="size-4 text-primary" /> Execution Evidence
                Breakdown
              </CardTitle>
              <span className="text-xs text-muted-foreground">
                Grouped by evidence category — execution, persistence, evasion,
                APIs, and capabilities
              </span>
            </CardHeader>
            <CardContent>
              {isPending ? (
                <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground">
                  <Loader2 className="size-4 animate-spin" /> Waiting for
                  analysis…
                </div>
              ) : Object.keys(evidenceByCategory).length === 0 ? (
                <p className="py-12 text-center text-sm text-muted-foreground">
                  No execution-category evidence found in this sample.
                </p>
              ) : (
                <div className="space-y-6">
                  {EVIDENCE_CATEGORIES_ORDER.map((cat) => {
                    const evidence = evidenceByCategory[cat];
                    if (!evidence?.length) return null;
                    return (
                      <div key={cat}>
                        <h4 className="mb-3 flex items-center gap-2 text-sm font-semibold text-foreground">
                          <Shield className="size-3.5 text-primary" />
                          {CATEGORY_LABELS[cat] ?? cat}
                          <Badge
                            tone="neutral"
                            className="ml-1 text-[0.65rem]"
                          >
                            {evidence.length}
                          </Badge>
                        </h4>
                        <div className="overflow-x-auto">
                          <table className="w-full min-w-[640px] text-sm">
                            <thead>
                              <tr className="border-y border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                                <th className="px-4 py-2 font-medium">Type</th>
                                <th className="px-3 py-2 font-medium">
                                  Description
                                </th>
                                <th className="px-3 py-2 font-medium">
                                  Module
                                </th>
                                <th className="px-3 py-2 font-medium">
                                  MITRE
                                </th>
                                <th className="px-4 text-right font-medium">
                                  Severity
                                </th>
                              </tr>
                            </thead>
                            <tbody>
                              {evidence.map((ev, i) => (
                                <tr
                                  key={ev.id || i}
                                  className="border-b border-border/50 last:border-0 hover:bg-surface-overlay/30"
                                >
                                  <td className="px-4 py-2">
                                    <span className="rounded-md bg-surface-overlay/60 px-2 py-1 text-xs text-muted-foreground">
                                      {ev.type}
                                    </span>
                                  </td>
                                  <td className="px-3 py-2 text-xs text-muted-foreground">
                                    {ev.description}
                                  </td>
                                  <td className="px-3 py-2 text-xs text-muted-foreground">
                                    {ev.source_module}
                                  </td>
                                  <td className="px-3 py-2 font-mono text-[0.7rem] text-accent">
                                    {ev.mitre_techniques?.join(", ") || "—"}
                                  </td>
                                  <td className="px-4 text-right">
                                    <SeverityBadge
                                      severity={ev.severity as Severity}
                                    />
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Execution IOCs */}
        <TabsContent value="iocs">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Cpu className="size-4 text-primary" /> Execution-Related IOCs
              </CardTitle>
              <span className="text-xs text-muted-foreground">
                Hashes, commands, registry keys, file paths, and mutexes
                extracted from the sample
              </span>
            </CardHeader>
            <CardContent className="px-0 pb-0">
              {isPending ? (
                <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground">
                  <Loader2 className="size-4 animate-spin" /> Waiting for
                  analysis…
                </div>
              ) : executionIocs.length === 0 ? (
                <p className="py-12 text-center text-sm text-muted-foreground">
                  No execution-related IOCs found in this sample.
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[640px] text-sm">
                    <thead>
                      <tr className="border-y border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                        <th className="px-5 py-2.5 font-medium">Type</th>
                        <th className="px-3 py-2.5 font-medium">Value</th>
                        <th className="px-3 py-2.5 font-medium">Source</th>
                        <th className="px-3 py-2.5 font-medium">Confidence</th>
                        <th className="px-5 py-2.5 text-right font-medium">
                          Severity
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {executionIocs.map((ioc, i) => (
                        <tr
                          key={i}
                          className="border-b border-border/50 last:border-0 hover:bg-surface-overlay/30"
                        >
                          <td className="px-5 py-2.5">
                            <span className="inline-flex items-center gap-1.5 rounded-md bg-surface-overlay/60 px-2 py-1 text-xs text-muted-foreground">
                              {ioc.type}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 break-all font-mono text-xs text-foreground">
                            {ioc.value}
                          </td>
                          <td className="px-3 py-2.5 text-xs text-muted-foreground">
                            {ioc.sources?.[0]?.module ?? "—"}
                          </td>
                          <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">
                            {typeof ioc.confidence === "number"
                              ? `${(ioc.confidence * 100).toFixed(0)}%`
                              : "n/a"}
                          </td>
                          <td className="px-5 py-2.5 text-right">
                            <SeverityBadge
                              severity={ioc.severity as Severity}
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
