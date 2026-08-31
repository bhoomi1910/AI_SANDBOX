import { useOutletContext } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Globe,
  Link2,
  Server,
  Mail,
  Loader2,
  Info,
  ShieldAlert,
  ArrowDownUp,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { networkAnalysis as mockNet } from "@/data/deepdive";
import { api, USE_BACKEND } from "@/lib/api";
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

const NETWORK_IOC_TYPES = new Set(["url", "domain", "ip", "email"]);

export default function NetworkAnalysis() {
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

  const allIocs = (iocQ.data?.iocs as LiveIoc[] | undefined) ?? [];
  const allEvidence =
    (staticQ.data?.result?.evidence as LiveEvidence[] | undefined) ?? [];

  const networkIocs = allIocs.filter((i) => NETWORK_IOC_TYPES.has(i.type));
  const networkEvidence = allEvidence.filter(
    (e) => e.category === "network"
  );

  const useLive = USE_BACKEND && inv.status === "completed";
  const isPending = USE_BACKEND && inv.status !== "completed";

  const displayIocs = useLive
    ? networkIocs
    : (mockNet.connections ?? []).map(
        (c) =>
          ({
            id: c.destIp,
            type: "ip",
            value: c.destIp,
            severity: c.malicious ? "high" : "info",
            confidence: c.malicious ? 0.8 : 0.3,
            sources: [{ module: "network", evidence_id: "", context: `${c.org || "unknown"} · port ${c.destPort}` }],
            count: 1,
            mitre_techniques: [],
          }) as unknown as LiveIoc
      );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-4"
    >
      {/* Static analysis only notice */}
      <Card className="border-medium/20 bg-medium/5">
        <CardContent className="flex items-start gap-3 pt-5">
          <Info className="mt-0.5 size-4 shrink-0 text-medium" />
          <div>
            <p className="text-sm text-muted-foreground">
              This platform performs <span className="font-medium text-foreground">static analysis only</span> — the
              sample is never executed and no runtime network traffic is captured.
              The indicators below are <span className="font-medium text-foreground">extracted deterministically</span> from
              the file content (URLs, domains, IPs, and email addresses found in
              strings, imports, and encoded data).
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Summary */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          {
            k: String(networkIocs.length),
            v: "Network IOCs",
            icon: Globe,
            c: "#22d3ee",
          },
          {
            k: String(networkEvidence.length),
            v: "Network evidence",
            icon: ShieldAlert,
            c: "#facc15",
          },
          {
            k: String(
              networkIocs.filter((i) => i.type === "ip").length
            ),
            v: "IP addresses",
            icon: Server,
            c: "#6366f1",
          },
          {
            k: String(
              networkIocs.filter((i) => i.type === "url").length +
                networkIocs.filter((i) => i.type === "domain").length
            ),
            v: "URLs / domains",
            icon: Link2,
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

      {/* Tabs: IOCs + Evidence */}
      <Tabs defaultValue="iocs">
        <TabsList className="mb-4">
          <TabsTrigger value="iocs">
            <Globe className="mr-1.5 inline size-3.5" /> Network IOCs
          </TabsTrigger>
          <TabsTrigger value="evidence">
            <ArrowDownUp className="mr-1.5 inline size-3.5" /> Network Evidence
          </TabsTrigger>
        </TabsList>

        <TabsContent value="iocs">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="size-4 text-primary" /> Extracted Network
                Indicators
              </CardTitle>
              <span className="text-xs text-muted-foreground">
                URLs, domains, IPs, and email addresses found in the sample
              </span>
            </CardHeader>
            <CardContent className="px-0 pb-0">
              {isPending ? (
                <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground">
                  <Loader2 className="size-4 animate-spin" /> Waiting for
                  analysis…
                </div>
              ) : displayIocs.length === 0 ? (
                <p className="py-12 text-center text-sm text-muted-foreground">
                  No network indicators found in this sample.
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[640px] text-sm">
                    <thead>
                      <tr className="border-y border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                        <th className="px-5 py-2.5 font-medium">Type</th>
                        <th className="px-3 py-2.5 font-medium">Indicator</th>
                        <th className="px-3 py-2.5 font-medium">Source</th>
                        <th className="px-3 py-2.5 font-medium">Confidence</th>
                        <th className="px-5 py-2.5 text-right font-medium">
                          Severity
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {displayIocs.map((ioc, i) => (
                        <tr
                          key={i}
                          className="border-b border-border/50 last:border-0 hover:bg-surface-overlay/30"
                        >
                          <td className="px-5 py-2.5">
                            <span className="inline-flex items-center gap-1.5 rounded-md bg-surface-overlay/60 px-2 py-1 text-xs text-muted-foreground">
                              {ioc.type === "ip" && (
                                <Server className="size-3.5" />
                              )}
                              {ioc.type === "url" && (
                                <Link2 className="size-3.5" />
                              )}
                              {ioc.type === "domain" && (
                                <Globe className="size-3.5" />
                              )}
                              {ioc.type === "email" && (
                                <Mail className="size-3.5" />
                              )}
                              {ioc.type}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 break-all font-mono text-xs text-foreground">
                            {ioc.value}
                          </td>
                          <td className="px-3 py-2.5 text-xs text-muted-foreground">
                            {(ioc as LiveIoc).sources?.[0]?.module ?? "—"}
                          </td>
                          <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">
                            {typeof (ioc as LiveIoc).confidence === "number"
                              ? `${((ioc as LiveIoc).confidence * 100).toFixed(0)}%`
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

        <TabsContent value="evidence">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ArrowDownUp className="size-4 text-primary" /> Network
                Evidence
              </CardTitle>
              <span className="text-xs text-muted-foreground">
                Observed indicators from static analysis (strings, PE imports,
                YARA rules)
              </span>
            </CardHeader>
            <CardContent className="px-0 pb-0">
              {isPending ? (
                <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground">
                  <Loader2 className="size-4 animate-spin" /> Waiting for
                  analysis…
                </div>
              ) : networkEvidence.length === 0 ? (
                <p className="py-12 text-center text-sm text-muted-foreground">
                  No network-category evidence found in this sample.
                </p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[640px] text-sm">
                    <thead>
                      <tr className="border-y border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                        <th className="px-5 py-2.5 font-medium">Type</th>
                        <th className="px-3 py-2.5 font-medium">Value</th>
                        <th className="px-3 py-2.5 font-medium">Description</th>
                        <th className="px-3 py-2.5 font-medium">Module</th>
                        <th className="px-3 py-2.5 font-medium">MITRE</th>
                        <th className="px-5 py-2.5 text-right font-medium">
                          Severity
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {networkEvidence.map((ev, i) => (
                        <tr
                          key={ev.id || i}
                          className="border-b border-border/50 last:border-0 hover:bg-surface-overlay/30"
                        >
                          <td className="px-5 py-2.5">
                            <span className="rounded-md bg-surface-overlay/60 px-2 py-1 text-xs text-muted-foreground">
                              {ev.type}
                            </span>
                          </td>
                          <td className="px-3 py-2.5 break-all font-mono text-xs text-foreground">
                            {ev.value}
                          </td>
                          <td className="px-3 py-2.5 text-xs text-muted-foreground">
                            {ev.description}
                          </td>
                          <td className="px-3 py-2.5 text-xs text-muted-foreground">
                            {ev.source_module}
                          </td>
                          <td className="px-3 py-2.5 font-mono text-[0.7rem] text-accent">
                            {ev.mitre_techniques?.join(", ") || "—"}
                          </td>
                          <td className="px-5 py-2.5 text-right">
                            <SeverityBadge
                              severity={ev.severity as Severity}
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
