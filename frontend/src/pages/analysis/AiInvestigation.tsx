import { useOutletContext } from "react-router-dom";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Sparkles,
  Brain,
  ShieldAlert,
  Target,
  Building2,
  ListChecks,
  ArrowRight,
  Loader2,
  Zap,
  CircleAlert,
  GitCommitHorizontal,
  CircleX,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/badge";
import { ScoreRing } from "@/components/shared/ScoreRing";
import { DataRow, SectionLabel } from "@/components/ui/misc";
import { aiInvestigation as mockAi } from "@/data/deepdive";
import { cn } from "@/lib/utils";
import { api, USE_BACKEND } from "@/lib/api";
import type { Investigation, MitreTechnique, Severity } from "@/data/types";

const priorityStyle: Record<string, string> = {
  immediate: "border-critical/30 bg-critical/5 text-critical",
  high: "border-high/30 bg-high/5 text-high",
  medium: "border-medium/30 bg-medium/5 text-medium",
};

type LiveAi = {
  status: string;
  provider?: string;
  model?: string;
  generated_at?: string;
  executive_summary?: string;
  technical_summary?: string;
  threat_explanation?: string;
  key_findings?: string[];
  risk_factors?: string[];
  mitre_explanation?: { technique_id: string; explanation: string }[];
  recommendations?: { priority: "immediate" | "high" | "medium"; action: string }[];
  business_impact?: string[];
  limitations?: string[];
  confidence?: number;
  severity?: string;
  verdict?: string;
  score_total?: number;
  family?: string;
  classification?: string;
  provenance?: { findings_used: number; iocs_used: number; mitre_used: number; note: string };
};

type AiView = {
  provider: string;
  summary: string;
  verdict: string;
  severity: Severity;
  confidence: number;
  scoreTotal: number;
  family: string;
  whatItDoes: string[];
  whyDangerous: string[];
  attackChain: { stage: string; technique: string; detail: string; mitre: string }[];
  businessImpact: string[];
  recommendations: { priority: "immediate" | "high" | "medium"; action: string }[];
  reasoning: string[];
};

function fromMock(inv: Investigation): AiView {
  return {
    provider: "AI Investigation · local model",
    summary: mockAi.summary,
    verdict: inv.verdict,
    severity: (inv.severity as Severity) ?? "info",
    confidence: mockAi.confidence,
    scoreTotal: inv.riskScore,
    family: inv.classification || "Unknown",
    whatItDoes: mockAi.whatItDoes,
    whyDangerous: mockAi.whyDangerous,
    attackChain: mockAi.attackChain,
    businessImpact: mockAi.businessImpact,
    recommendations: mockAi.recommendations,
    reasoning: mockAi.reasoning,
  };
}

function fromLive(live: LiveAi, techniques: MitreTechnique[], inv: Investigation): AiView {
  const explanations = new Map((live.mitre_explanation ?? []).map((e) => [e.technique_id, e.explanation]));
  const attackChain = techniques.map((t) => ({
    stage: t.tactic,
    technique: t.name,
    detail: explanations.get(t.id) ?? t.description,
    mitre: t.id,
  }));
  const provenanceNote =
    live.provenance?.note ??
    `Interpretation of ${live.provenance?.findings_used ?? 0} findings, ${live.provenance?.iocs_used ?? 0} IOCs and ${live.provenance?.mitre_used ?? 0} MITRE mappings.`;
  return {
    provider: live.provider ?? `Ollama${live.model ? ` · ${live.model}` : ""}`,
    summary: live.executive_summary ?? "No executive summary was produced.",
    verdict: live.verdict ?? inv.verdict,
    severity: (live.severity as Severity) ?? (inv.severity as Severity) ?? "info",
    confidence: live.confidence ?? 0,
    scoreTotal: live.score_total ?? inv.riskScore,
    family: live.classification || live.family || "Unknown",
    whatItDoes: live.key_findings ?? [],
    whyDangerous: live.risk_factors ?? [],
    attackChain,
    businessImpact: live.business_impact && live.business_impact.length > 0 ? live.business_impact : (live.risk_factors ?? []),
    recommendations: live.recommendations ?? [],
    reasoning: [provenanceNote, ...(live.limitations ?? [])],
  };
}

function mapMitre(t: Record<string, unknown>): MitreTechnique {
  return {
    id: t.technique_id as string,
    name: t.technique as string,
    tactic: t.tactic as string,
    description: ((t.findings as string[]) ?? []).join(" · ") || "Evidence-backed mapping from static indicators.",
    severity: (t.severity as MitreTechnique["severity"]) ?? "info",
    evidence: ((t.evidence as string[]) ?? []).join(" · ") || "No raw evidence snippet recorded.",
  };
}

export default function AiInvestigation() {
  const { inv } = useOutletContext<{ inv: Investigation }>();
  const navigate = useNavigate();

  const aiQ = useQuery({
    queryKey: ["ai", inv.id],
    queryFn: () => api.getAiAnalysis(inv.id),
    enabled: USE_BACKEND,
    retry: 1,
    refetchInterval: (query) => (query.state.data?.status === "completed" ? false : 3000),
  });
  const mitreQ = useQuery({
    queryKey: ["mitre", inv.id],
    queryFn: () => api.getMitre(inv.id),
    enabled: USE_BACKEND,
    retry: 1,
  });

  const aiStatus = USE_BACKEND ? aiQ.data?.status : undefined;
  const live = aiStatus === "completed" ? (aiQ.data as unknown as LiveAi) : null;
  const techniques =
    mitreQ.data?.status === "completed"
      ? ((mitreQ.data.techniques as Record<string, unknown>[]) ?? []).map(mapMitre)
      : [];

  const ai = live ? fromLive(live, techniques, inv) : fromMock(inv);
  const isPending = USE_BACKEND && aiStatus === "pending";
  const isDown = USE_BACKEND && (aiStatus === "unavailable" || aiStatus === "error");

  if (aiQ.isLoading && USE_BACKEND && !aiQ.data) {
    return (
      <div className="grid place-items-center rounded-xl border border-border bg-surface/40 py-24 text-center">
        <Loader2 className="mb-3 size-8 animate-spin text-primary" />
        <p className="text-sm font-medium text-foreground">Loading AI analysis…</p>
      </div>
    );
  }

  if (isPending) {
    return (
      <div className="grid place-items-center rounded-xl border border-border bg-surface/40 py-24 text-center">
        <Loader2 className="mb-3 size-8 animate-spin text-primary" />
        <p className="text-sm font-medium text-foreground">Static analysis is still running…</p>
        <p className="mt-1 text-xs text-muted-foreground">The AI interpretation appears once the deterministic analysis completes.</p>
      </div>
    );
  }

  if (isDown) {
    const note = (aiQ.data as { note?: string; reason?: string })?.note;
    const reason = (aiQ.data as { reason?: string })?.reason;
    return (
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
        <Card className="border-critical/20">
          <CardContent className="pt-6">
            <div className="flex items-start gap-4">
              <div className="grid size-10 shrink-0 place-items-center rounded-lg bg-critical/15 text-critical">
                <CircleX className="size-5" />
              </div>
              <div className="flex-1">
                <h2 className="text-lg font-bold text-foreground">AI analysis unavailable</h2>
                <p className="mt-1 text-sm text-muted-foreground">{note}</p>
                {reason && <p className="mt-1 font-mono text-xs text-muted-foreground/70">{reason}</p>}
              </div>
            </div>
            <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div className="rounded-lg border border-border bg-surface/50 p-3">
                <SectionLabel>Deterministic verdict</SectionLabel>
                <div className="mt-2 flex items-center gap-2">
                  <span className="text-sm font-semibold capitalize text-foreground">{inv.verdict}</span>
                  <SeverityBadge severity={inv.severity} />
                </div>
              </div>
              <div className="rounded-lg border border-border bg-surface/50 p-3">
                <SectionLabel>Risk score</SectionLabel>
                <div className="mt-2 text-sm font-semibold text-foreground">{inv.riskScore}/100</div>
              </div>
              <div className="rounded-lg border border-border bg-surface/50 p-3">
                <SectionLabel>Classification</SectionLabel>
                <div className="mt-2 text-sm font-semibold text-foreground">{inv.classification}</div>
              </div>
            </div>
            <p className="mt-4 text-xs text-muted-foreground">
              Findings, IOCs and MITRE mappings are still available on the other tabs — the AI only interprets deterministic output.
            </p>
          </CardContent>
        </Card>
      </motion.div>
    );
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
      {/* Hero verdict */}
      <Card className="relative overflow-hidden border-accent/25">
        <div className="pointer-events-none absolute -right-16 -top-16 size-64 rounded-full bg-accent/10 blur-3xl" />
        <div className="pointer-events-none absolute -left-16 top-10 size-48 rounded-full bg-primary/10 blur-3xl" />
        <div className="hairline-top" />
        <CardContent className="pt-6">
          <div className="flex flex-col gap-6 lg:flex-row lg:items-center">
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <div className="grid size-9 place-items-center rounded-lg bg-accent/15 ring-1 ring-accent/30">
                  <Sparkles className="size-4 text-accent" />
                </div>
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-accent">{ai.provider}</span>
                {!live && <span className="badge border-accent/30 bg-accent/10 text-accent">demo data</span>}
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-2">
                <h2 className="text-2xl font-bold tracking-tight text-foreground">Verdict:</h2>
                <span className="text-2xl font-bold capitalize text-foreground">{ai.verdict}</span>
                <SeverityBadge severity={ai.severity} />
                <span className="badge border-accent/30 bg-accent/10 text-accent">{ai.family}</span>
              </div>

              <p className="mt-3 min-h-[6rem] text-sm leading-relaxed text-muted-foreground lg:text-[0.95rem]">{ai.summary}</p>
            </div>

            {/* Gauges */}
            <div className="flex shrink-0 items-center justify-center gap-8 lg:flex-col lg:gap-4">
              <div className="text-center">
                <ScoreRing value={ai.confidence} size={120} label={`${ai.confidence}%`} sublabel="AI confidence" color="#a78bfa" />
              </div>
              <div className="text-center">
                <ScoreRing value={ai.scoreTotal} size={96} label={`${ai.scoreTotal}/100`} sublabel="Deterministic score" color="#22d3ee" />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* What it does + Why dangerous */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Zap className="size-4 text-primary" /> Key findings</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {ai.whatItDoes.length === 0 && <span className="text-xs text-muted-foreground">The model produced no key findings.</span>}
            {ai.whatItDoes.map((t, i) => (
              <motion.div key={i} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.3 + i * 0.06 }} className="flex gap-3 text-sm">
                <span className="mt-1 grid size-5 shrink-0 place-items-center rounded-full bg-primary/15 text-[0.65rem] font-bold text-primary">{i + 1}</span>
                <span className="text-muted-foreground">{t}</span>
              </motion.div>
            ))}
          </CardContent>
        </Card>

        <Card className="border-critical/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><ShieldAlert className="size-4 text-critical" /> Risk factors</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {ai.whyDangerous.length === 0 && <span className="text-xs text-muted-foreground">The model produced no risk factors.</span>}
            {ai.whyDangerous.map((t, i) => (
              <div key={i} className="flex gap-3 text-sm">
                <CircleAlert className="mt-0.5 size-4 shrink-0 text-critical" />
                <span className="text-muted-foreground">{t}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Attack chain */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Target className="size-4 text-primary" /> Evidence & MITRE Explanation</CardTitle>
          <span className="text-xs text-muted-foreground">mapped from deterministic evidence; AI text in italics</span>
        </CardHeader>
        <CardContent>
          {ai.attackChain.length === 0 ? (
            <span className="text-xs text-muted-foreground">No MITRE techniques were mapped for this sample.</span>
          ) : (
            <div className="relative flex flex-col gap-3 lg:flex-row lg:items-stretch lg:gap-0 lg:overflow-x-auto lg:pb-2">
              {ai.attackChain.map((step, i) => (
                <div key={i} className="flex items-center lg:flex-col lg:items-stretch">
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 + i * 0.08 }}
                    className="relative flex-1 rounded-xl border border-border bg-surface/50 p-3.5 lg:w-52 lg:min-w-52"
                  >
                    <div className="flex items-center gap-2">
                      <span className="grid size-6 place-items-center rounded-full bg-primary/15 text-[0.7rem] font-bold text-primary">{i + 1}</span>
                      <span className="text-xs font-semibold uppercase tracking-wide text-primary">{step.stage}</span>
                    </div>
                    <div className="mt-2 text-sm font-medium text-foreground">{step.technique}</div>
                    <div className="mt-1 text-xs text-muted-foreground">{step.detail}</div>
                    <span className="mt-2 inline-block rounded bg-accent/10 px-1.5 py-0.5 font-mono text-[0.6rem] text-accent">{step.mitre}</span>
                  </motion.div>
                  {i < ai.attackChain.length - 1 && (
                    <div className="grid shrink-0 place-items-center px-1 py-1 lg:py-3">
                      <ArrowRight className="size-4 rotate-90 text-muted-foreground/50 lg:rotate-0" />
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Business impact + AI reasoning */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Building2 className="size-4 text-medium" /> Business Impact</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {ai.businessImpact.length === 0 && <span className="text-xs text-muted-foreground">The model produced no business impact assessment.</span>}
            {ai.businessImpact.map((t, i) => (
              <div key={i} className="flex gap-3 rounded-lg border border-medium/20 bg-medium/5 p-2.5 text-sm">
                <Building2 className="mt-0.5 size-4 shrink-0 text-medium" />
                <span className="text-muted-foreground">{t}</span>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card className="border-accent/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Brain className="size-4 text-accent" /> AI Reasoning & Limitations</CardTitle>
            <span className="badge border-accent/30 bg-accent/10 text-accent">interpretation only</span>
          </CardHeader>
          <CardContent>
            <div className="relative space-y-3 pl-5">
              <div className="absolute left-[7px] top-1 bottom-1 w-px bg-accent/20" />
              {ai.reasoning.map((r, i) => (
                <div key={i} className="relative flex gap-3 text-sm">
                  <GitCommitHorizontal className="absolute -left-5 top-0.5 size-3.5 text-accent" />
                  <span className="text-muted-foreground">{r}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Recommendations */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><ListChecks className="size-4 text-primary" /> Recommended Response Actions</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {ai.recommendations.length === 0 && <span className="text-xs text-muted-foreground">The model produced no recommendations.</span>}
          {ai.recommendations.map((r, i) => (
            <div key={i} className={cn("flex items-center gap-3 rounded-lg border p-3", priorityStyle[r.priority])}>
              <span className="shrink-0 rounded border border-current px-2 py-0.5 text-[0.6rem] font-bold uppercase tracking-wide">
                {r.priority}
              </span>
              <span className="text-sm text-foreground">{r.action}</span>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* CTA */}
      <div className="flex flex-col items-center justify-between gap-3 rounded-xl border border-border bg-surface/50 p-4 sm:flex-row">
        <div className="flex items-center gap-3">
          <div className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary"><Sparkles className="size-4" /></div>
          <div>
            <div className="text-sm font-medium text-foreground">Investigation complete</div>
            <div className="text-xs text-muted-foreground">Generate the formal report for stakeholders and IR handoff.</div>
          </div>
        </div>
        <Button onClick={() => navigate("/investigation/inv-0412/report")}>
          Generate report <ArrowRight className="size-4" />
        </Button>
      </div>
    </motion.div>
  );
}
