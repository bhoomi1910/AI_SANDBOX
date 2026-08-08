import { motion } from "framer-motion";
import {
  FileText,
  Download,
  Printer,
  ShieldCheck,
  Clock,
  Hash,
  Crosshair,
  ListChecks,
  Building2,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/badge";
import { ScoreRing } from "@/components/shared/ScoreRing";
import { getInvestigation } from "@/data/investigations";
import { aiInvestigation as ai, iocs, mitreTechniques, dynamicAnalysis } from "@/data/deepdive";

export default function Report() {
  const inv = getInvestigation("inv-0412")!;
  const now = new Date("2026-07-29T09:04:00Z");

  const print = () => window.print();

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      {/* Action bar (hidden on print) */}
      <div className="mb-4 flex flex-col items-start justify-between gap-3 print:hidden sm:flex-row sm:items-center">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <FileText className="size-4 text-primary" />
          Investigation report generated · {now.toUTCString()}
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={print}><Printer className="size-4" /> Print</Button>
          <Button onClick={print}><Download className="size-4" /> Export PDF</Button>
        </div>
      </div>

      {/* Report document */}
      <div className="panel overflow-hidden print:border-0 print:bg-white">
        {/* Letterhead */}
        <div className="border-b border-border bg-surface-raised/60 p-6 print:bg-white">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="grid size-11 place-items-center rounded-xl bg-gradient-to-br from-primary/25 to-accent/25 ring-1 ring-primary/40">
                <ShieldCheck className="size-6 text-primary" />
              </div>
              <div>
                <div className="text-lg font-bold tracking-tight text-foreground">Aegis Sandbox AI</div>
                <div className="text-xs uppercase tracking-[0.16em] text-muted-foreground">Threat Investigation Report</div>
              </div>
            </div>
            <div className="text-right text-xs text-muted-foreground">
              <div className="font-mono text-sm font-semibold text-foreground">{inv.caseId}</div>
              <div>Classification: <span className="font-medium text-critical">CONFIDENTIAL</span></div>
              <div>Analyst: {inv.assignedTo}</div>
            </div>
          </div>
        </div>

        <div className="space-y-8 p-6 lg:p-8">
          {/* Title + verdict summary */}
          <div className="flex flex-col gap-6 lg:flex-row lg:items-center">
            <div className="flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity="critical" />
                <span className="badge border-critical/30 bg-critical/10 text-critical">Malicious</span>
                <span className="badge border-accent/30 bg-accent/10 text-accent">{ai.family}</span>
              </div>
              <h1 className="mt-3 text-2xl font-bold tracking-tight text-foreground">
                {inv.sample.filename}
              </h1>
              <p className="mt-1 font-mono text-xs text-muted-foreground">SHA-256: {inv.sample.sha256}</p>
            </div>
            <div className="flex items-center gap-6">
              <div className="text-center">
                <ScoreRing value={inv.riskScore} size={104} label={String(inv.riskScore)} sublabel="Risk score" />
              </div>
              <div className="text-center">
                <ScoreRing value={inv.aiConfidence} size={104} label={`${inv.aiConfidence}%`} sublabel="Confidence" color="#a78bfa" />
              </div>
            </div>
          </div>

          {/* Executive summary */}
          <Section n="1" title="Executive Summary" icon={FileText}>
            <p className="text-sm leading-relaxed text-muted-foreground">{ai.summary}</p>
            <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                { k: "Verdict", v: "Malicious" },
                { k: "Family", v: "Emotet" },
                { k: "Detections", v: `${inv.detections}/${inv.totalEngines}` },
                { k: "First seen", v: "2026-07-24" },
              ].map((x) => (
                <div key={x.k} className="rounded-lg border border-border bg-surface/40 p-3">
                  <div className="text-[0.65rem] uppercase tracking-wide text-muted-foreground">{x.k}</div>
                  <div className="mt-0.5 text-sm font-semibold text-foreground">{x.v}</div>
                </div>
              ))}
            </div>
          </Section>

          {/* Timeline */}
          <Section n="2" title="Incident Timeline" icon={Clock}>
            <div className="relative space-y-3 pl-5">
              <div className="absolute left-[7px] top-1 bottom-1 w-px bg-border" />
              {dynamicAnalysis.timeline.slice(0, 8).map((ev, i) => (
                <div key={i} className="relative flex gap-3 text-sm">
                  <span className="absolute -left-5 top-1 size-2 rounded-full bg-primary" />
                  <span className="w-12 shrink-0 font-mono text-xs text-muted-foreground">+{ev.offset}s</span>
                  <span className="font-medium text-foreground">{ev.action}</span>
                  <span className="text-muted-foreground">— {ev.detail}</span>
                </div>
              ))}
            </div>
          </Section>

          {/* MITRE */}
          <Section n="3" title="MITRE ATT&CK Techniques" icon={Crosshair}>
            <div className="flex flex-wrap gap-2">
              {mitreTechniques.map((t) => (
                <span key={t.id} className="rounded-lg border border-border bg-surface/40 px-2.5 py-1.5 text-xs">
                  <span className="font-mono font-semibold text-primary">{t.id}</span>{" "}
                  <span className="text-muted-foreground">{t.name}</span>
                </span>
              ))}
            </div>
          </Section>

          {/* IOCs */}
          <Section n="4" title="Indicators of Compromise" icon={Hash}>
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full min-w-[520px] text-sm">
                <thead>
                  <tr className="border-b border-border bg-surface/40 text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                    <th className="px-4 py-2 font-medium">Type</th>
                    <th className="px-4 py-2 font-medium">Indicator</th>
                    <th className="px-4 py-2 font-medium">Context</th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.slice(0, 8).map((ioc, i) => (
                    <tr key={i} className="border-b border-border/50 last:border-0">
                      <td className="px-4 py-2 text-xs uppercase text-muted-foreground">{ioc.type}</td>
                      <td className="px-4 py-2 break-all font-mono text-xs text-foreground">{ioc.value}</td>
                      <td className="px-4 py-2 text-xs text-muted-foreground">{ioc.context}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>

          {/* Business impact */}
          <Section n="5" title="Business Impact Assessment" icon={Building2}>
            <ul className="space-y-2">
              {ai.businessImpact.map((t, i) => (
                <li key={i} className="flex gap-2 text-sm text-muted-foreground">
                  <span className="text-medium">▸</span> {t}
                </li>
              ))}
            </ul>
          </Section>

          {/* Recommendations */}
          <Section n="6" title="Recommendations" icon={ListChecks}>
            <ol className="space-y-2">
              {ai.recommendations.map((r, i) => (
                <li key={i} className="flex gap-3 text-sm">
                  <span className="grid size-5 shrink-0 place-items-center rounded-full bg-primary/15 text-[0.65rem] font-bold text-primary">{i + 1}</span>
                  <span className="text-muted-foreground">
                    <span className="mr-1.5 rounded bg-surface-overlay/70 px-1.5 py-0.5 text-[0.6rem] font-bold uppercase text-foreground">{r.priority}</span>
                    {r.action}
                  </span>
                </li>
              ))}
            </ol>
          </Section>

          {/* Footer */}
          <div className="border-t border-border pt-4 text-center text-[0.7rem] text-muted-foreground">
            Generated by Aegis Sandbox AI · aegis-analyst-v2 · {now.toUTCString()} · This is an MSc demonstration prototype.
            <br />
            Report ID: RPT-{inv.caseId} · Page 1 of 1
          </div>
        </div>
      </div>
    </motion.div>
  );
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
