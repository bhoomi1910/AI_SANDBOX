import { useState } from "react";
import { useOutletContext } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  FileSearch,
  ShieldX,
  ShieldCheck,
  AlertTriangle,
  FileCode2,
  Boxes,
  Fingerprint,
  Search,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataRow, Input, SectionLabel } from "@/components/ui/misc";
import { SeverityBadge } from "@/components/ui/badge";
import { staticAnalysis as s } from "@/data/deepdive";
import { cn, formatBytes } from "@/lib/utils";
import { api, USE_BACKEND } from "@/lib/api";
import type { Investigation, StaticAnalysis } from "@/data/types";

const stringTypeColor: Record<string, string> = {
  url: "#f43f5e",
  ip: "#fb923c",
  registry: "#facc15",
  path: "#38bdf8",
  command: "#f43f5e",
  mutex: "#a78bfa",
  api: "#22d3ee",
  generic: "#64748b",
};

const signatureLabel: Record<string, { text: string; bad: boolean }> = {
  valid: { text: "Valid signature", bad: false },
  unsigned: { text: "Unsigned", bad: false },
  invalid: { text: "Invalid / forged", bad: true },
  revoked: { text: "Revoked", bad: true },
};

type StaticResult = { static: StaticAnalysis; fileType: string; family: string };

export default function StaticAnalysis() {
  const { inv } = useOutletContext<{ inv: Investigation }>();
  const [strFilter, setStrFilter] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["static", inv.id],
    queryFn: () => api.getStaticAnalysis(inv.id),
    enabled: USE_BACKEND,
    retry: 1,
    refetchInterval: (query) =>
      query.state.data?.status === "completed" ? false : 3000,
  });

  const live = data?.status === "completed" ? (data.result as unknown as StaticResult) : null;
  const isLive = USE_BACKEND && data?.status === "pending";
  const staticData = live?.static ?? s;
  const entropyPct = (staticData.entropy / 8) * 100;

  const filteredStrings = staticData.strings.filter((str) =>
    strFilter ? str.value.toLowerCase().includes(strFilter.toLowerCase()) : true
  );

  if (isLoading && USE_BACKEND && !data) {
    return <LoadingState />;
  }

  if (isLive) {
    return (
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="grid place-items-center rounded-xl border border-border bg-surface/40 py-24 text-center">
        <Loader2 className="mb-3 size-8 animate-spin text-primary" />
        <p className="text-sm font-medium text-foreground">Static analysis is still running…</p>
        <p className="mt-1 text-xs text-muted-foreground">Evidence, IOCs and MITRE mapping will appear here when ready.</p>
      </motion.div>
    );
  }

  const sig = signatureLabel[staticData.signatureStatus] ?? signatureLabel.unsigned;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
      {/* File identity + entropy */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Fingerprint className="size-4 text-primary" /> File Identity & Metadata</CardTitle>
            <SeverityBadge severity={inv.severity} />
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 gap-x-8 sm:grid-cols-2">
              <div className="divide-y divide-border/60">
                <DataRow label="File size" mono>{formatBytes(inv.sample.size)} ({inv.sample.size.toLocaleString()} bytes)</DataRow>
                <DataRow label="File type" mono>{live ? `${live.fileType}${live.family ? ` (${live.family})` : ""}` : "PE32 executable (GUI) Intel 80386"}</DataRow>
                <DataRow label="Architecture" mono>{staticData.arch}</DataRow>
                <DataRow label="Subsystem" mono>{staticData.subsystem}</DataRow>
                <DataRow label="Compiler" mono>{staticData.compiler}</DataRow>
              </div>
              <div className="divide-y divide-border/60">
                <DataRow label="Packer" mono>
                  {staticData.packer ? <span className="text-medium">{staticData.packer}</span> : "None"}
                </DataRow>
                <DataRow label="Compile time" mono>{staticData.timestamp}</DataRow>
                <DataRow label="Imphash" mono>{staticData.imphash}</DataRow>
                <DataRow label="Digital signature" mono>
                  {sig.bad ? (
                    <span className="inline-flex items-center gap-1 text-critical"><ShieldX className="size-3.5" /> {sig.text}</span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-muted-foreground"><ShieldCheck className="size-3.5" /> {sig.text}</span>
                  )}
                </DataRow>
                <DataRow label="MD5" mono>{inv.sample.md5}</DataRow>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Entropy gauge */}
        <Card>
          <CardHeader>
            <CardTitle>Entropy Analysis</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline gap-2">
              <span className="text-4xl font-bold text-high">{staticData.entropy}</span>
              <span className="text-sm text-muted-foreground">/ 8.0</span>
            </div>
            <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-surface-overlay">
              <div className="h-full rounded-full bg-gradient-to-r from-low via-medium to-critical" style={{ width: `${entropyPct}%` }} />
            </div>
            <p className="mt-3 flex items-start gap-2 text-xs leading-relaxed text-muted-foreground">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-medium" />
              High entropy (&gt;7.2) strongly indicates packing or encryption. Compressed or encrypted regions obscure the true payload from static inspection.
            </p>
            <div className="mt-4">
              <SectionLabel>Assessment</SectionLabel>
              <div className="mt-3 flex items-center gap-3 rounded-lg border border-critical/25 bg-critical/5 p-3">
                <div className="grid size-11 place-items-center rounded-full border-2 border-critical/40">
                  <span className="font-mono text-sm font-bold text-critical">{inv.detections}</span>
                </div>
                <div>
                  <div className="text-sm font-semibold text-critical">{inv.detections} high/critical indicator{inv.detections === 1 ? "" : "s"}</div>
                  <div className="text-[0.7rem] text-muted-foreground">{live ? inv.classification : "flagged as malicious · Trojan.Emotet"}</div>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Capabilities + YARA */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><AlertTriangle className="size-4 text-high" /> Detected Capabilities</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {staticData.capabilities.length === 0 && <span className="text-xs text-muted-foreground">No family-specific capabilities detected.</span>}
            {staticData.capabilities.map((c) => (
              <span key={c} className="rounded-lg border border-high/25 bg-high/5 px-2.5 py-1.5 text-xs text-high">
                {c}
              </span>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><FileCode2 className="size-4 text-primary" /> YARA Rule Matches</CardTitle>
            <span className="badge border-critical/30 bg-critical/10 text-critical">{staticData.yara.length} hits</span>
          </CardHeader>
          <CardContent className="space-y-2">
            {staticData.yara.length === 0 && <span className="text-xs text-muted-foreground">No YARA rules matched.</span>}
            {staticData.yara.map((y) => (
              <div key={y.rule} className="rounded-lg border border-border bg-surface/40 p-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-sm font-medium text-foreground">{y.rule}</span>
                  <SeverityBadge severity={y.severity} />
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{y.description}</p>
                <div className="mt-2 flex flex-wrap items-center gap-1.5">
                  {y.tags.map((t) => (
                    <span key={t} className="rounded bg-surface-overlay/70 px-1.5 py-0.5 font-mono text-[0.65rem] text-muted-foreground">#{t}</span>
                  ))}
                  <span className="ml-auto text-[0.65rem] text-muted-foreground">by {y.author}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* PE Sections */}
      {staticData.sections.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Boxes className="size-4 text-primary" /> PE Sections</CardTitle>
          </CardHeader>
          <CardContent className="px-0">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px] text-sm">
                <thead>
                  <tr className="border-y border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                    <th className="px-5 py-2.5 font-medium">Section</th>
                    <th className="px-3 py-2.5 font-medium">Virtual size</th>
                    <th className="px-3 py-2.5 font-medium">Raw size</th>
                    <th className="px-3 py-2.5 font-medium">Entropy</th>
                    <th className="px-3 py-2.5 font-medium">Flags</th>
                    <th className="px-5 py-2.5 text-right font-medium">Assessment</th>
                  </tr>
                </thead>
                <tbody>
                  {staticData.sections.map((sec) => (
                    <tr key={sec.name} className="border-b border-border/50 last:border-0">
                      <td className="px-5 py-3 font-mono text-foreground">{sec.name}</td>
                      <td className="px-3 py-3 font-mono text-muted-foreground">{formatBytes(sec.virtualSize)}</td>
                      <td className="px-3 py-3 font-mono text-muted-foreground">{formatBytes(sec.rawSize)}</td>
                      <td className="px-3 py-3">
                        <div className="flex items-center gap-2">
                          <span className={cn("font-mono text-xs", sec.entropy > 7 ? "text-critical" : "text-muted-foreground")}>{sec.entropy.toFixed(2)}</span>
                          <div className="h-1 w-16 overflow-hidden rounded-full bg-surface-overlay">
                            <div className={cn("h-full rounded-full", sec.entropy > 7 ? "bg-critical" : "bg-low")} style={{ width: `${(sec.entropy / 8) * 100}%` }} />
                          </div>
                        </div>
                      </td>
                      <td className="px-3 py-3 font-mono text-muted-foreground">{sec.flags}{sec.flags.includes("X") && sec.flags.includes("W") && <span className="ml-1 text-critical">⚠ RWX</span>}</td>
                      <td className="px-5 py-3 text-right">
                        {sec.suspicious ? <SeverityBadge severity="high" label="suspicious" /> : <SeverityBadge severity="clean" label="normal" />}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Imports + Strings */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {staticData.imports.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Imported Functions</CardTitle>
              <span className="text-xs text-muted-foreground">suspicious calls highlighted</span>
            </CardHeader>
            <CardContent className="space-y-3">
              {staticData.imports.map((imp) => (
                <div key={imp.dll}>
                  <div className="mb-1.5 font-mono text-xs font-semibold text-primary">{imp.dll}</div>
                  <div className="flex flex-wrap gap-1.5">
                    {imp.functions.map((fn) => {
                      const sus = imp.suspicious.includes(fn);
                      return (
                        <span key={fn} className={cn("rounded border px-1.5 py-0.5 font-mono text-[0.7rem]", sus ? "border-critical/30 bg-critical/10 text-critical" : "border-border bg-surface/50 text-muted-foreground")}>
                          {fn}
                        </span>
                      );
                    })}
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        )}

        <Card>
          <CardHeader>
            <CardTitle>Extracted Strings</CardTitle>
            <div className="relative w-40">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input value={strFilter} onChange={(e) => setStrFilter(e.target.value)} placeholder="Filter…" className="h-8 pl-8 text-xs" />
            </div>
          </CardHeader>
          <CardContent className="max-h-[380px] space-y-1 overflow-y-auto">
            {filteredStrings.map((str, i) => (
              <div key={i} className={cn("flex items-center gap-3 rounded-lg px-2 py-1.5 transition-colors hover:bg-surface-overlay/40", str.interesting && "bg-surface/40")}>
                <span className="shrink-0 rounded px-1.5 py-0.5 font-mono text-[0.6rem] uppercase" style={{ background: `${stringTypeColor[str.type] ?? "#64748b"}1f`, color: stringTypeColor[str.type] ?? "#64748b" }}>
                  {str.type}
                </span>
                <span className={cn("min-w-0 flex-1 truncate font-mono text-xs", str.interesting ? "text-foreground" : "text-muted-foreground")}>{str.value}</span>
                <span className="shrink-0 font-mono text-[0.65rem] text-muted-foreground/70">{str.offset}</span>
              </div>
            ))}
            {filteredStrings.length === 0 && <div className="py-6 text-center text-xs text-muted-foreground">No strings match.</div>}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}

function LoadingState() {
  return (
    <div className="grid place-items-center rounded-xl border border-border bg-surface/40 py-24 text-center">
      <Loader2 className="mb-3 size-8 animate-spin text-primary" />
      <p className="text-sm font-medium text-foreground">Loading static analysis…</p>
    </div>
  );
}
