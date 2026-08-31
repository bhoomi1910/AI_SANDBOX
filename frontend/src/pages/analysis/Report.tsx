import { useState } from "react";
import { useOutletContext } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  FileText,
  Download,
  Loader2,
  CheckCircle2,
  CircleAlert,
  FileWarning,
  Sparkles,
  Hash,
  Crosshair,
  ListChecks,
  ShieldCheck,
  FileSearch,
  Info,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/badge";
import { ScoreRing } from "@/components/shared/ScoreRing";
import { DataRow } from "@/components/ui/misc";
import { api, USE_BACKEND } from "@/lib/api";
import { cn, formatBytes } from "@/lib/utils";
import type { Investigation } from "@/data/types";
import { iocs as mockIocs, mitreTechniques as mockMitre } from "@/data/deepdive";

type LiveAi = {
  status: string;
  executive_summary?: string;
  technical_summary?: string;
  threat_explanation?: string;
  key_findings?: string[];
  risk_factors?: string[];
  mitre_explanation?: { technique_id: string; explanation: string }[];
  recommendations?: { priority: string; action: string }[];
  business_impact?: string[];
  limitations?: string[];
  confidence?: number;
  provider?: string;
  model?: string;
};

type Finding = Record<string, unknown>;
type Technique = Record<string, unknown>;

export default function Report() {
  const { inv } = useOutletContext<{ inv: Investigation }>();
  const [dl, setDl] = useState<{ state: "idle" | "loading" | "success" | "error"; message?: string }>({
    state: "idle",
  });

  const completed = inv.status === "completed";

  const staticQ = useQuery({
    queryKey: ["static", inv.id],
    queryFn: () => api.getStaticAnalysis(inv.id),
    enabled: USE_BACKEND && completed,
    retry: 1,
  });
  const aiQ = useQuery({
    queryKey: ["ai", inv.id],
    queryFn: () => api.getAiAnalysis(inv.id),
    enabled: USE_BACKEND && completed,
    retry: 1,
  });
  const iocQ = useQuery({
    queryKey: ["iocs", inv.id],
    queryFn: () => api.getIocs(inv.id),
    enabled: USE_BACKEND && completed,
    retry: 1,
  });
  const mitreQ = useQuery({
    queryKey: ["mitre", inv.id],
    queryFn: () => api.getMitre(inv.id),
    enabled: USE_BACKEND && completed,
    retry: 1,
  });

  const live = USE_BACKEND ? staticQ.data?.result : undefined;
  const findings = (live?.findings as Finding[] | undefined) ?? [];
  const iocs = (iocQ.data?.iocs as Array<Record<string, unknown>> | undefined) ?? (USE_BACKEND ? [] : mockIocs as unknown as Array<Record<string, unknown>>);
  const techniques =
    (mitreQ.data?.techniques as Technique[] | undefined) ?? (USE_BACKEND ? [] : mockMitre as unknown as Technique[]);
  const ai = USE_BACKEND ? (aiQ.data as LiveAi | undefined) : undefined;
  const aiOk = ai?.status === "completed";

  const generatedAt = new Date().toUTCString();

  const download = async () => {
    if (!USE_BACKEND) {
      window.print();
      return;
    }
    setDl({ state: "loading" });
    try {
      const blob = await api.getReportPdf(inv.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${inv.caseId}-report.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setDl({ state: "success" });
      window.setTimeout(() => setDl({ state: "idle" }), 3000);
    } catch (err) {
      setDl({
        state: "error",
        message: err instanceof Error ? err.message : "Report generation failed.",
      });
    }
  };

  if (!completed) {
    return (
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
        <Card className="border-border/60">
          <CardContent className="pt-6">
            <div className="flex items-start gap-4">
              <div className="grid size-10 shrink-0 place-items-center rounded-lg bg-medium/15 text-medium">
                <FileWarning className="size-5" />
              </div>
              <div className="flex-1">
                <h2 className="text-lg font-bold text-foreground">Report unavailable</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  The investigation report is available once static analysis completes. Current status:{" "}
                  <span className="font-medium capitalize text-foreground">{inv.status.replace("-", " ")}</span>.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    );
  }

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
      {/* Action bar */}
      <div className="flex flex-col items-start justify-between gap-3 rounded-xl border border-border bg-surface/50 p-4 sm:flex-row sm:items-center">
        <div className="flex items-center gap-3">
          <div className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary">
            <FileText className="size-4" />
          </div>
          <div>
            <div className="text-sm font-semibold text-foreground">Investigation report</div>
            <div className="text-xs text-muted-foreground">
              Server-generated PDF · deterministic analysis + AI interpretation when available
            </div>
          </div>
        </div>
        <Button onClick={download} disabled={dl.state === "loading"}>
          {dl.state === "loading" ? (
            <Loader2 className="size-4 animate-spin" />
          ) : (
            <Download className="size-4" />
          )}
          {USE_BACKEND ? "Download Investigation Report" : "Export PDF (print)"}
        </Button>
      </div>

      {dl.state === "success" && (
        <div className="flex items-center gap-2 rounded-lg border border-primary/30 bg-primary/10 px-3 py-2 text-sm text-foreground">
          <CheckCircle2 className="size-4 text-primary" /> Report downloaded successfully.
        </div>
      )}
      {dl.state === "error" && (
        <div className="flex items-start gap-2 rounded-lg border border-critical/30 bg-critical/10 px-3 py-2 text-sm text-foreground">
          <CircleAlert className="mt-0.5 size-4 shrink-0 text-critical" />
          <span>{dl.message ?? "Report generation failed."}</span>
        </div>
      )}

      {/* Document preview */}
      <div className="panel overflow-hidden">
        <div className="border-b border-border bg-surface-raised/60 p-6">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="grid size-11 place-items-center rounded-xl bg-gradient-to-br from-primary/25 to-accent/25 ring-1 ring-primary/40">
                <ShieldCheck className="size-6 text-primary" />
              </div>
              <div>
                <div className="text-lg font-bold tracking-tight text-foreground">AI-Powered Intelligent Sandbox</div>
                <div className="text-xs uppercase tracking-[0.16em] text-muted-foreground">Secure File Investigation Report</div>
              </div>
            </div>
            <div className="text-right text-xs text-muted-foreground">
              <div className="font-mono text-sm font-semibold text-foreground">{inv.caseId}</div>
              <div>Generated {generatedAt}</div>
              <div className="capitalize">Status: {inv.status}</div>
            </div>
          </div>
        </div>

        <div className="space-y-8 p-6 lg:p-8">
          {/* Title + verdict summary */}
          <div className="flex flex-col gap-6 lg:flex-row lg:items-center">
            <div className="flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={inv.severity} />
                <span className="badge border-accent/30 bg-accent/10 text-accent capitalize">{inv.verdict}</span>
                <span className="badge border-primary/30 bg-primary/10 text-primary">{String(live?.family ?? inv.sample.fileType)}</span>
              </div>
              <h1 className="mt-3 break-all text-2xl font-bold tracking-tight text-foreground">{inv.sample.filename}</h1>
              <p className="mt-1 break-all font-mono text-xs text-muted-foreground">SHA-256: {inv.sample.sha256}</p>
            </div>
            <div className="flex items-center gap-6">
              <div className="text-center">
                <ScoreRing value={inv.riskScore} size={104} label={String(inv.riskScore)} sublabel="Deterministic score" color="#22d3ee" />
              </div>
              <div className="text-center">
                <ScoreRing value={aiOk ? (ai?.confidence ?? 0) : 0} size={104} label={`${aiOk ? (ai?.confidence ?? 0) : "n/a"}%`} sublabel="AI confidence" color="#a78bfa" />
              </div>
            </div>
          </div>

          {/* Executive summary */}
          <Section n="1" title="Executive Summary" icon={FileText}>
            {aiOk ? (
              <p className="text-sm leading-relaxed text-muted-foreground">
                <span className="badge border-accent/30 bg-accent/10 text-accent">AI-assisted interpretation</span>{" "}
                {ai?.executive_summary}
              </p>
            ) : (
              <>
                <div className="badge border-medium/30 bg-medium/10 text-medium">AI-assisted interpretation unavailable</div>
                <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                  Deterministic static analysis classified this sample as{" "}
                  <span className="font-medium text-foreground">{inv.classification}</span> (verdict{" "}
                  {inv.verdict}, severity {inv.severity}, score {inv.riskScore}/100) with{" "}
                  {findings.length} finding(s) and {iocs.length} indicator(s) of compromise. This summary is
                  generated from deterministic findings.
                </p>
              </>
            )}
            <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                { k: "Verdict", v: inv.verdict },
                { k: "Classification", v: inv.classification },
                { k: "Severity", v: inv.severity },
                { k: "Score", v: `${inv.riskScore}/100` },
              ].map((x) => (
                <div key={x.k} className="rounded-lg border border-border bg-surface/40 p-3">
                  <div className="text-[0.65rem] uppercase tracking-wide text-muted-foreground">{x.k}</div>
                  <div className="mt-0.5 text-sm font-semibold capitalize text-foreground">{x.v}</div>
                </div>
              ))}
            </div>
          </Section>

          {/* File information */}
          <Section n="2" title="File Information" icon={FileSearch}>
            <div className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
              <DataRow label="Filename" mono>{inv.sample.filename}</DataRow>
              <DataRow label="Size">{formatBytes(inv.sample.size)} ({inv.sample.size.toLocaleString()} bytes)</DataRow>
              <DataRow label="Detected type">{String(inv.sample.fileType)}</DataRow>
              <DataRow label="SHA-256" mono>{inv.sample.sha256}</DataRow>
              <DataRow label="MD5" mono>{inv.sample.md5}</DataRow>
              <DataRow label="Submitted">{new Date(inv.createdAt).toUTCString()}</DataRow>
            </div>
          </Section>

          {/* Detection findings */}
          <Section n="3" title="Detection Findings" icon={ShieldCheck}>
            {findings.length === 0 ? (
              <p className="text-sm text-muted-foreground">No findings recorded.</p>
            ) : (
              <div className="space-y-2.5">
                {findings.slice(0, 30).map((f, i) => (
                  <div key={i} className="rounded-lg border border-border bg-surface/40 p-3 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={cn("badge", severityTone(String(f.severity ?? "info")))}>{String(f.severity)}</span>
                      <span className="font-medium text-foreground">{String(f.title ?? "")}</span>
                      <span className="text-xs text-muted-foreground">· {String(f.category ?? "")}</span>
                    </div>
                    {f.detail ? <p className="mt-1 text-xs text-muted-foreground">{String(f.detail)}</p> : null}
                    <p className="mt-1 text-[0.7rem] text-muted-foreground/70">
                      module {String(f.module ?? "?")} · origin{" "}
                      {String(f.module ?? "").startsWith("detection:") ? "derived (rule correlation)" : "observed"} · confidence{" "}
                      {f.confidence != null ? Number(f.confidence).toFixed(2) : "n/a"}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </Section>

          {/* IOCs */}
          <Section n="4" title="Indicators of Compromise" icon={Hash}>
            {iocs.length === 0 ? (
              <p className="text-sm text-muted-foreground">No IOCs extracted.</p>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-border">
                <table className="w-full min-w-[520px] text-sm">
                  <thead>
                    <tr className="border-b border-border bg-surface/40 text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                      <th className="px-4 py-2 font-medium">Type</th>
                      <th className="px-4 py-2 font-medium">Indicator</th>
                      <th className="px-4 py-2 font-medium">Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {iocs.slice(0, 50).map((ioc, i) => (
                      <tr key={i} className="border-b border-border/50 last:border-0">
                        <td className="px-4 py-2 text-xs uppercase text-muted-foreground">{String(ioc.type ?? "")}</td>
                        <td className="break-all px-4 py-2 font-mono text-xs text-foreground">{String(ioc.value ?? "")}</td>
                        <td className="px-4 py-2 text-xs text-muted-foreground">
                          {ioc.confidence != null ? Number(ioc.confidence).toFixed(2) : "n/a"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>

          {/* MITRE */}
          <Section n="5" title="MITRE ATT&CK Mapping" icon={Crosshair}>
            {techniques.length === 0 ? (
              <p className="text-sm text-muted-foreground">No MITRE ATT&amp;CK techniques were mapped for this sample.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {techniques.map((t, i) => (
                  <span key={i} className="rounded-lg border border-border bg-surface/40 px-2.5 py-1.5 text-xs">
                    <span className="font-mono font-semibold text-primary">{String(t.technique_id ?? "")}</span>{" "}
                    <span className="text-muted-foreground">{String(t.technique ?? "")}</span>
                    <span className="ml-1 text-[0.65rem] uppercase text-muted-foreground/70">· {String(t.tactic ?? "")}</span>
                  </span>
                ))}
              </div>
            )}
          </Section>

          {/* AI investigation */}
          <Section n="6" title="AI Investigation" icon={Sparkles}>
            {aiOk ? (
              <div className="space-y-4">
                {ai?.technical_summary && <DataRow label="Technical summary">{ai.technical_summary}</DataRow>}
                {ai?.threat_explanation && <DataRow label="Threat explanation">{ai.threat_explanation}</DataRow>}
                {ai?.key_findings && ai.key_findings.length > 0 && (
                  <DataRow label="Key findings">{ai.key_findings.join(" · ")}</DataRow>
                )}
                {ai?.risk_factors && ai.risk_factors.length > 0 && (
                  <DataRow label="Risk factors">{ai.risk_factors.join(" · ")}</DataRow>
                )}
                {ai?.mitre_explanation && ai.mitre_explanation.length > 0 && (
                  <DataRow label="MITRE explanation">{ai.mitre_explanation.map((m) => `${m.technique_id}: ${m.explanation}`).join(" · ")}</DataRow>
                )}
                {ai?.recommendations && ai.recommendations.length > 0 && (
                  <DataRow label="AI recommendations">{ai.recommendations.map((r) => `[${r.priority}] ${r.action}`).join(" · ")}</DataRow>
                )}
                {ai?.limitations && ai.limitations.length > 0 && (
                  <DataRow label="AI limitations">{ai.limitations.join(" · ")}</DataRow>
                )}
              </div>
            ) : (
              <div className="flex items-start gap-3">
                <Info className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                <p className="text-sm text-muted-foreground">
                  AI-assisted interpretation was unavailable at the time of report generation. The deterministic
                  sections of this report are complete and unaffected.
                </p>
              </div>
            )}
          </Section>

          {/* Recommendations */}
          <Section n="7" title="Recommendations" icon={ListChecks}>
            <ul className="space-y-2">
              {(aiOk ? (ai?.recommendations ?? []) : []).length > 0 ? (
                ai?.recommendations?.map((r, i) => (
                  <li key={i} className="flex gap-3 text-sm">
                    <span className="grid size-5 shrink-0 place-items-center rounded-full bg-primary/15 text-[0.65rem] font-bold text-primary">{i + 1}</span>
                    <span className="text-muted-foreground">
                      <span className="mr-1.5 rounded bg-accent/15 px-1.5 py-0.5 text-[0.6rem] font-bold uppercase text-accent">AI</span>
                      [<span className="font-medium text-foreground">{r.priority}</span>] {r.action}
                    </span>
                  </li>
                ))
              ) : (
                <li className="text-sm text-muted-foreground">
                  The full deterministic recommendations are included in the server-generated PDF report. Download it
                  for the complete findings, evidence and scoring breakdown.
                </li>
              )}
            </ul>
          </Section>

          {/* Limitations */}
          <Section n="8" title="Limitations" icon={CircleAlert}>
            <ul className="space-y-1.5 text-sm text-muted-foreground">
              <li>Static analysis only — the file was not executed.</li>
              <li>Runtime and network behaviour were not observed.</li>
              <li>Detection results depend on the available analysis modules and rules.</li>
              <li>AI-assisted interpretation may be unavailable or unvalidated.</li>
            </ul>
          </Section>

          <div className="border-t border-border pt-4 text-center text-[0.7rem] text-muted-foreground">
            Generated by AI-Powered Intelligent Sandbox · {generatedAt}
            <br />
            Report ID: RPT-{inv.caseId} · Download the PDF for the full report
          </div>
        </div>
      </div>
    </motion.div>
  );
}

function severityTone(sev: string): string {
  const tones: Record<string, string> = {
    critical: "border-critical/30 bg-critical/10 text-critical",
    high: "border-high/30 bg-high/10 text-high",
    medium: "border-medium/30 bg-medium/10 text-medium",
    low: "border-low/30 bg-low/10 text-low",
    info: "border-info/30 bg-info/10 text-info",
  };
  return tones[sev] ?? "border-border bg-surface text-foreground";
}

function Section({
  n,
  title,
  icon: Icon,
  children,
}: {
  n: string;
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
}) {
  return (
    <section>
      <div className="mb-3 flex items-center gap-2.5 border-b border-border pb-2">
        <div className="grid size-7 place-items-center rounded-lg bg-primary/10 text-primary">
          <Icon className="size-4" />
        </div>
        <h2 className="text-sm font-bold uppercase tracking-wide text-foreground">
          <span className="text-muted-foreground">{n}.</span> {title}
        </h2>
      </div>
      {children}
    </section>
  );
}
