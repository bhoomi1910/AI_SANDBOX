import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
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
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/badge";
import { ScoreRing } from "@/components/shared/ScoreRing";
import { aiInvestigation as ai } from "@/data/deepdive";
import { cn } from "@/lib/utils";

const priorityStyle: Record<string, string> = {
  immediate: "border-critical/30 bg-critical/5 text-critical",
  high: "border-high/30 bg-high/5 text-high",
  medium: "border-medium/30 bg-medium/5 text-medium",
};

export default function AiInvestigation() {
  const navigate = useNavigate();
  const [typed, setTyped] = useState("");
  const [done, setDone] = useState(false);

  // Typewriter for the AI summary
  useEffect(() => {
    let i = 0;
    const full = ai.summary;
    const timer = setInterval(() => {
      i += 3;
      setTyped(full.slice(0, i));
      if (i >= full.length) {
        clearInterval(timer);
        setDone(true);
      }
    }, 12);
    return () => clearInterval(timer);
  }, []);

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
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-accent">AI Investigation · aegis-analyst-v2</span>
                {!done && <Loader2 className="size-3.5 animate-spin text-muted-foreground" />}
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-2">
                <h2 className="text-2xl font-bold tracking-tight text-foreground">Verdict:</h2>
                <span className="text-2xl font-bold text-critical">Malicious</span>
                <SeverityBadge severity="critical" />
                <span className="badge border-accent/30 bg-accent/10 text-accent">{ai.family}</span>
              </div>

              <p className="mt-3 min-h-[6rem] text-sm leading-relaxed text-muted-foreground lg:text-[0.95rem]">
                {typed}
                {!done && <span className="ml-0.5 inline-block h-4 w-1.5 animate-pulse bg-accent align-middle" />}
              </p>
            </div>

            {/* Gauges */}
            <div className="flex shrink-0 items-center justify-center gap-8 lg:flex-col lg:gap-4">
              <div className="text-center">
                <ScoreRing value={ai.confidence} size={120} label={`${ai.confidence}%`} sublabel="Confidence" color="#a78bfa" />
              </div>
              <div className="text-center">
                <ScoreRing value={ai.familyConfidence} size={96} label={`${ai.familyConfidence}%`} sublabel="Family match" color="#22d3ee" />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* What it does + Why dangerous */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Zap className="size-4 text-primary" /> What this malware does</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5">
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
            <CardTitle className="flex items-center gap-2"><ShieldAlert className="size-4 text-critical" /> Why it is dangerous</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5">
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
          <CardTitle className="flex items-center gap-2"><Target className="size-4 text-primary" /> Reconstructed Attack Chain</CardTitle>
        </CardHeader>
        <CardContent>
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
        </CardContent>
      </Card>

      {/* Business impact + AI reasoning */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Building2 className="size-4 text-medium" /> Business Impact</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5">
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
            <CardTitle className="flex items-center gap-2"><Brain className="size-4 text-accent" /> AI Reasoning Trace</CardTitle>
            <span className="badge border-accent/30 bg-accent/10 text-accent">explainable</span>
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
