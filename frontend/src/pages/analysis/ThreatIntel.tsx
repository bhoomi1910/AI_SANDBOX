import { useState, useMemo } from "react";
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
  Search,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Copy,
  Check,
  Filter,
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

const IOC_TYPES = [
  "hash",
  "domain",
  "ip",
  "url",
  "email",
  "mutex",
  "registry",
  "windows_path",
  "command",
] as const;

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

type SortField = "type" | "value" | "confidence" | "severity";
type SortDir = "asc" | "desc";

export default function ThreatIntel() {
  const { inv } = useOutletContext<{ inv: Investigation }>();
  const [search, setSearch] = useState("");
  const [selectedTypes, setSelectedTypes] = useState<Set<string>>(new Set());
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  const iocQ = useQuery({
    queryKey: ["iocs", inv.id],
    queryFn: () => api.getIocs(inv.id),
    enabled: USE_BACKEND && inv.status === "completed",
    retry: 1,
  });

  const backendIocs = (iocQ.data?.iocs as LiveIoc[] | undefined) ?? [];
  const iocs = USE_BACKEND ? backendIocs : mockIocs;
  const isPending = USE_BACKEND && inv.status !== "completed";

  const typeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const ioc of iocs) {
      counts[ioc.type] = (counts[ioc.type] || 0) + 1;
    }
    return counts;
  }, [iocs]);

  const filteredIocs = useMemo(() => {
    let result = [...iocs];

    if (selectedTypes.size > 0) {
      result = result.filter((ioc) => selectedTypes.has(ioc.type));
    }

    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (ioc) =>
          ioc.value.toLowerCase().includes(q) ||
          ioc.type.toLowerCase().includes(q) ||
          (ioc as LiveIoc).sources?.[0]?.module?.toLowerCase().includes(q) ||
          (ioc as LiveIoc).mitre_techniques?.some((t) =>
            t.toLowerCase().includes(q)
          )
      );
    }

    result.sort((a, b) => {
      let cmp = 0;
      if (sortField === "severity") {
        cmp =
          (SEVERITY_ORDER[b.severity] || 0) -
          (SEVERITY_ORDER[a.severity] || 0);
      } else if (sortField === "confidence") {
        const aConf =
          typeof (a as LiveIoc).confidence === "number"
            ? (a as LiveIoc).confidence
            : 0;
        const bConf =
          typeof (b as LiveIoc).confidence === "number"
            ? (b as LiveIoc).confidence
            : 0;
        cmp = bConf - aConf;
      } else if (sortField === "type") {
        cmp = a.type.localeCompare(b.type);
      } else if (sortField === "value") {
        cmp = a.value.localeCompare(b.value);
      }
      return sortDir === "asc" ? -cmp : cmp;
    });

    return result;
  }, [iocs, selectedTypes, search, sortField, sortDir]);

  const toggleType = (type: string) => {
    setSelectedTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  };

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir("desc");
    }
  };

  const copyValue = (value: string) => {
    navigator.clipboard.writeText(value);
    setCopiedValue(value);
    setTimeout(() => setCopiedValue(null), 1500);
  };

  const SortIcon = ({
    field,
    className,
  }: {
    field: SortField;
    className?: string;
  }) => {
    if (sortField !== field)
      return <ArrowUpDown className={cn("size-3", className)} />;
    return sortDir === "asc" ? (
      <ArrowUp className={cn("size-3", className)} />
    ) : (
      <ArrowDown className={cn("size-3", className)} />
    );
  };

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

      {/* IOC type summary + search + filter */}
      <Card>
        <CardContent className="pt-5">
          <div className="flex flex-col gap-3">
            {/* Type badges */}
            <div className="flex flex-wrap gap-1.5">
              {IOC_TYPES.filter((t) => typeCounts[t] > 0).map((type) => {
                const Icon = iocIcon[type] ?? Hash;
                const active = selectedTypes.size === 0 || selectedTypes.has(type);
                return (
                  <button
                    key={type}
                    onClick={() => toggleType(type)}
                    className={cn(
                      "inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs transition-colors",
                      active
                        ? "border-primary/30 bg-primary/10 text-primary"
                        : "border-border bg-surface-overlay/30 text-muted-foreground opacity-50"
                    )}
                  >
                    <Icon className="size-3" />
                    {type.replace("_", " ")}
                    <span className="ml-0.5 font-mono text-[0.65rem] opacity-70">
                      {typeCounts[type]}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Search + controls row */}
            <div className="flex items-center gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Search IOCs by value, type, source, or MITRE technique..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full rounded-md border border-border bg-surface-overlay/30 py-1.5 pl-8 pr-3 text-xs text-foreground placeholder:text-muted-foreground focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/30"
                />
              </div>
              {selectedTypes.size > 0 && (
                <button
                  onClick={() => setSelectedTypes(new Set())}
                  className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1.5 text-xs text-muted-foreground hover:bg-surface-overlay/50"
                >
                  <Filter className="size-3" /> Clear filter
                </button>
              )}
            </div>
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
            {filteredIocs.length}
            {filteredIocs.length !== iocs.length && ` / ${iocs.length}`}{" "}
            indicators
          </span>
        </CardHeader>
        <CardContent className="px-0 pb-0">
          {isPending ? (
            <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground">
              <Loader2 className="size-4 animate-spin" /> Waiting for analysis to
              complete…
            </div>
          ) : filteredIocs.length === 0 ? (
            <p className="py-12 text-center text-sm text-muted-foreground">
              {iocs.length === 0
                ? "No indicators extracted from this sample."
                : "No indicators match the current filter."}
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[820px] text-sm">
                <thead>
                  <tr className="border-y border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                    {(
                      [
                        ["type", "Type"],
                        ["value", "Indicator"],
                        ["", "Source"],
                        ["confidence", "Confidence"],
                        ["", "MITRE"],
                        ["severity", "Severity"],
                      ] as [SortField | "", string][]
                    ).map(([field, label]) => (
                      <th
                        key={label}
                        className={cn(
                          "px-5 py-2.5 font-medium",
                          field && "cursor-pointer select-none hover:text-foreground"
                        )}
                        onClick={field ? () => toggleSort(field) : undefined}
                      >
                        <span className="inline-flex items-center gap-1">
                          {label}
                          {field && <SortIcon field={field} />}
                        </span>
                      </th>
                    ))}
                    <th className="px-5 py-2.5 text-right font-medium">
                      Copy
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {filteredIocs.map((ioc, i) => {
                    const live = ioc as LiveIoc;
                    const Icon = iocIcon[ioc.type] ?? Hash;
                    const confidence =
                      typeof live.confidence === "number"
                        ? `${(live.confidence * 100).toFixed(0)}%`
                        : "n/a";
                    const source = live.sources?.[0]?.module ?? "—";
                    const mitre =
                      live.mitre_techniques?.join(", ") || "—";
                    const isCopied = copiedValue === ioc.value;
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
                        <td className="px-5 py-2.5 text-right">
                          <button
                            onClick={() => copyValue(ioc.value)}
                            className={cn(
                              "inline-flex items-center gap-1 rounded-md px-1.5 py-1 text-xs transition-colors",
                              isCopied
                                ? "bg-success/10 text-success"
                                : "text-muted-foreground hover:bg-surface-overlay/50 hover:text-foreground"
                            )}
                            title="Copy to clipboard"
                          >
                            {isCopied ? (
                              <Check className="size-3.5" />
                            ) : (
                              <Copy className="size-3.5" />
                            )}
                          </button>
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

      {/* External feeds note */}
      <Card className="border-medium/20 bg-medium/5">
        <CardContent className="flex items-start gap-3 pt-5">
          <Info className="mt-0.5 size-4 shrink-0 text-medium" />
          <div>
            <p className="text-sm text-muted-foreground">
              External threat-intelligence feeds (VirusTotal, AlienVault OTX,
              AbuseIPDB, etc.) are not yet integrated. The indicators above are
              extracted deterministically from the sample's static analysis. A
              future phase will enrich these with live external lookups.
            </p>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
