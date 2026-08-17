import { useOutletContext } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Shield,
  Hash,
  Globe,
  Server,
  Link2,
  Lock,
  KeyRound,
  FileWarning,
  Terminal,
  Mail,
  Loader2,
  Info,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/badge";
import { iocs as mockIocs } from "@/data/deepdive";
import { api, USE_BACKEND } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { Investigation } from "@/data/types";
import type { Severity } from "@/components/ui/badge";

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

const iocIcon: Record<string, React.ComponentType<{ className?: string }>> = {
  hash: Hash,
  domain: Globe,
  ip: Server,
  url: Link2,
  email: Mail,
  mutex: Lock,
  registry: KeyRound,
  windows_path: FileWarning,
  command: Terminal,
};

export default function ThreatIntel() {
  const { inv } = useOutletContext<{ inv: Investigation }>();

  const iocQ = useQuery({
    queryKey: ["iocs", inv.id],
    queryFn: () => api.getIocs(inv.id),
    enabled: USE_BACKEND && inv.status === "completed",
    retry: 1,
  });

  const backendIocs = (iocQ.data?.iocs as LiveIoc[] | undefined) ?? [];
  const iocs = USE_BACKEND ? backendIocs : mockIocs;
  const isPending = USE_BACKEND && inv.status !== "completed";

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-4"
    >
      {/* Threat profile */}
      <Card className="relative overflow-hidden border-border/60">
        <div className="pointer-events-none absolute -right-10 -top-10 size-48 rounded-full bg-primary/5 blur-3xl" />
        <CardContent className="flex flex-col gap-4 pt-5 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-4">
            <div
              className={cn(
                "grid size-12 place-items-center rounded-xl ring-1",
                inv.severity === "critical"
                  ? "bg-critical/10 ring-critical/30"
                  : inv.severity === "high"
                    ? "bg-high/10 ring-high/30"
                    : "bg-primary/10 ring-primary/30"
              )}
            >
              <Shield
                className={cn(
                  "size-6",
                  inv.severity === "critical"
                    ? "text-critical"
                    : inv.severity === "high"
                      ? "text-high"
                      : "text-primary"
                )}
              />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-foreground capitalize">
                  {inv.verdict}
                </h3>
                <SeverityBadge severity={inv.severity} />
              </div>
              <p className="mt-0.5 text-sm text-muted-foreground">
                Classification:{" "}
                <span className="font-medium text-foreground">
                  {inv.classification}
                </span>
                {inv.malwareFamily && inv.malwareFamily !== "Pending" && (
                  <>
                    {" "}
                    · Family:{" "}
                    <span className="font-medium text-foreground">
                      {inv.malwareFamily}
                    </span>
                  </>
                )}
              </p>
            </div>
          </div>
          <div className="flex gap-6">
            {[
              { k: String(iocs.length), v: "Indicators" },
              { k: `${inv.riskScore}/100`, v: "Risk Score" },
              { k: `${inv.detections}/${inv.totalEngines}`, v: "Detections" },
            ].map((s) => (
              <div key={s.v} className="text-center">
                <div className="font-mono text-xl font-bold text-foreground">
                  {s.k}
                </div>
                <div className="text-[0.65rem] text-muted-foreground">{s.v}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* External feeds note */}
      <Card className="border-medium/20 bg-medium/5">
        <CardContent className="flex items-start gap-3 pt-5">
          <Info className="mt-0.5 size-4 shrink-0 text-medium" />
          <div>
            <p className="text-sm text-muted-foreground">
              External threat-intelligence feeds (VirusTotal, AlienVault OTX,
              AbuseIPDB, etc.) are not yet integrated. The indicators below are
              extracted deterministically from the sample's static analysis. A
              future phase will enrich these with live external lookups.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* IOC table */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Hash className="size-4 text-primary" /> Indicators of Compromise
          </CardTitle>
          <span className="badge border-primary/30 bg-primary/10 text-primary">
            {iocs.length} indicators
          </span>
        </CardHeader>
        <CardContent className="px-0 pb-0">
          {isPending ? (
            <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground">
              <Loader2 className="size-4 animate-spin" /> Waiting for analysis to
              complete…
            </div>
          ) : iocs.length === 0 ? (
            <p className="py-12 text-center text-sm text-muted-foreground">
              No indicators extracted from this sample.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[780px] text-sm">
                <thead>
                  <tr className="border-y border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                    <th className="px-5 py-2.5 font-medium">Type</th>
                    <th className="px-3 py-2.5 font-medium">Indicator</th>
                    <th className="px-3 py-2.5 font-medium">Source</th>
                    <th className="px-3 py-2.5 font-medium">Confidence</th>
                    <th className="px-3 py-2.5 font-medium">MITRE</th>
                    <th className="px-5 py-2.5 text-right font-medium">
                      Severity
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.map((ioc, i) => {
                    const live = ioc as LiveIoc;
                    const Icon = iocIcon[ioc.type] ?? Hash;
                    const confidence =
                      typeof live.confidence === "number"
                        ? `${(live.confidence * 100).toFixed(0)}%`
                        : "n/a";
                    const source = live.sources?.[0]?.module ?? "—";
                    const mitre =
                      live.mitre_techniques?.join(", ") || "—";
                    return (
                      <tr
                        key={i}
                        className="border-b border-border/50 last:border-0 hover:bg-surface-overlay/30"
                      >
                        <td className="px-5 py-2.5">
                          <span className="inline-flex items-center gap-1.5 rounded-md bg-surface-overlay/60 px-2 py-1 text-xs text-muted-foreground">
                            <Icon className="size-3.5" /> {ioc.type}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 break-all font-mono text-xs text-foreground">
                          {ioc.value}
                        </td>
                        <td className="px-3 py-2.5 text-xs text-muted-foreground">
                          {source}
                        </td>
                        <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">
                          {confidence}
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[0.7rem] text-accent">
                          {mitre}
                        </td>
                        <td className="px-5 py-2.5 text-right">
                          <SeverityBadge
                            severity={ioc.severity as Severity}
                          />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
