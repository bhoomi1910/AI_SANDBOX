import { motion } from "framer-motion";
import { Radar, ExternalLink, ShieldAlert, Hash, Globe, Server, Link2, Lock, KeyRound, FileWarning } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/badge";
import { threatIntel, iocs } from "@/data/deepdive";
import { cn } from "@/lib/utils";
import type { IoC } from "@/data/types";

const toneStyles: Record<string, string> = {
  danger: "border-critical/30 bg-critical/5",
  warn: "border-medium/30 bg-medium/5",
  neutral: "border-border bg-surface/40",
  success: "border-success/30 bg-success/5",
};
const scoreColor: Record<string, string> = {
  danger: "#f43f5e",
  warn: "#facc15",
  neutral: "#64748b",
  success: "#34d399",
};

const iocIcon: Record<IoC["type"], React.ComponentType<{ className?: string }>> = {
  hash: Hash,
  domain: Globe,
  ip: Server,
  url: Link2,
  mutex: Lock,
  registry: KeyRound,
  filename: FileWarning,
};

export default function ThreatIntel() {
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
      <Card className="relative overflow-hidden border-critical/25">
        <div className="pointer-events-none absolute -right-10 -top-10 size-48 rounded-full bg-critical/10 blur-3xl" />
        <CardContent className="flex flex-col gap-4 pt-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-4">
            <div className="grid size-12 place-items-center rounded-xl bg-critical/10 ring-1 ring-critical/30">
              <ShieldAlert className="size-6 text-critical" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-foreground">Known malicious — high confidence</h3>
                <SeverityBadge severity="critical" />
              </div>
              <p className="mt-0.5 text-sm text-muted-foreground">
                Correlated across 6 intelligence sources · attributed to <span className="font-medium text-foreground">TA542 (Mummy Spider)</span> · Emotet Epoch 5
              </p>
            </div>
          </div>
          <div className="flex gap-6">
            {[
              { k: "6 / 6", v: "Sources agree" },
              { k: "1,240", v: "Related IOCs" },
              { k: "847", v: "Abuse reports" },
            ].map((s) => (
              <div key={s.v} className="text-center">
                <div className="font-mono text-xl font-bold text-critical">{s.k}</div>
                <div className="text-[0.65rem] text-muted-foreground">{s.v}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Enrichment sources */}
      <div>
        <h3 className="mb-3 text-sm font-semibold text-foreground">Threat Intelligence Enrichment</h3>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {threatIntel.map((t, i) => (
            <motion.div
              key={t.source}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.06 }}
              className={cn("group rounded-xl border p-4 transition-colors", toneStyles[t.tone])}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="grid size-9 place-items-center rounded-lg bg-surface-overlay/60 ring-1 ring-border">
                    <Radar className="size-4" style={{ color: scoreColor[t.tone] }} />
                  </div>
                  <div>
                    <div className="text-sm font-semibold text-foreground">{t.source}</div>
                    <div className="text-[0.65rem] text-muted-foreground">Updated {t.lastSeen}</div>
                  </div>
                </div>
                <ExternalLink className="size-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
              </div>
              <div className="mt-3 flex items-center gap-3">
                <div className="relative grid size-12 shrink-0 place-items-center">
                  <svg className="-rotate-90" width="48" height="48">
                    <circle cx="24" cy="24" r="20" fill="none" stroke="rgba(148,163,184,0.12)" strokeWidth="4" />
                    <circle cx="24" cy="24" r="20" fill="none" stroke={scoreColor[t.tone]} strokeWidth="4" strokeLinecap="round" strokeDasharray={2 * Math.PI * 20} strokeDashoffset={2 * Math.PI * 20 * (1 - t.score / 100)} />
                  </svg>
                  <span className="absolute font-mono text-xs font-bold" style={{ color: scoreColor[t.tone] }}>{t.score}</span>
                </div>
                <div className="text-sm font-medium text-foreground">{t.verdict}</div>
              </div>
              <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{t.detail}</p>
            </motion.div>
          ))}
        </div>
      </div>

      {/* IOCs */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Hash className="size-4 text-primary" /> Indicators of Compromise (IOCs)</CardTitle>
          <span className="badge border-primary/30 bg-primary/10 text-primary">{iocs.length} indicators</span>
        </CardHeader>
        <CardContent className="px-0 pb-0">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[640px] text-sm">
              <thead>
                <tr className="border-y border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                  <th className="px-5 py-2.5 font-medium">Type</th>
                  <th className="px-3 py-2.5 font-medium">Indicator</th>
                  <th className="px-3 py-2.5 font-medium">Context</th>
                  <th className="px-5 py-2.5 text-right font-medium">Severity</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc, i) => {
                  const Icon = iocIcon[ioc.type];
                  return (
                    <tr key={i} className="border-b border-border/50 last:border-0 hover:bg-surface-overlay/30">
                      <td className="px-5 py-2.5">
                        <span className="inline-flex items-center gap-1.5 rounded-md bg-surface-overlay/60 px-2 py-1 text-xs text-muted-foreground">
                          <Icon className="size-3.5" /> {ioc.type}
                        </span>
                      </td>
                      <td className="px-3 py-2.5 break-all font-mono text-xs text-foreground">{ioc.value}</td>
                      <td className="px-3 py-2.5 text-xs text-muted-foreground">{ioc.context}</td>
                      <td className="px-5 py-2.5 text-right"><SeverityBadge severity={ioc.severity} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
