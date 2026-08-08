import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { useQuery } from "@tanstack/react-query";
import { ListChecks, Search, SlidersHorizontal } from "lucide-react";
import { PageHeader } from "@/components/shared/PageHeader";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/misc";
import { SeverityBadge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { cn, formatBytes, timeAgo } from "@/lib/utils";
import { api, USE_BACKEND } from "@/lib/api";
import { investigations, statusMeta, severityRank } from "@/data/investigations";
import type { InvestigationStatus } from "@/data/types";

const statusFilters: { key: InvestigationStatus | "all"; label: string }[] = [
  { key: "all", label: "All" },
  { key: "queued", label: "Queued" },
  { key: "running", label: "Running" },
  { key: "analysing", label: "Analysing" },
  { key: "ai-processing", label: "AI Processing" },
  { key: "completed", label: "Completed" },
];

export default function Queue() {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<InvestigationStatus | "all">("all");

  const { data, isLoading, isError } = useQuery({
    queryKey: ["investigations"],
    queryFn: () => api.listInvestigations(),
    retry: 1,
    refetchInterval: 15000,
    enabled: USE_BACKEND,
  });
  const usingDemo = !USE_BACKEND || isError;
  const items = usingDemo ? investigations : (data ?? []);

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: items.length };
    for (const i of items) c[i.status] = (c[i.status] ?? 0) + 1;
    return c;
  }, [items]);

  const rows = useMemo(() => {
    return items
      .filter((i) => (filter === "all" ? true : i.status === filter))
      .filter((i) =>
        query
          ? [i.caseId, i.sample.filename, i.malwareFamily, i.sample.sha256]
              .join(" ")
              .toLowerCase()
              .includes(query.toLowerCase())
          : true
      )
      .sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);
  }, [items, query, filter]);

  return (
    <div>
      <PageHeader
        title="Investigation Queue"
        subtitle="All active and completed malware investigations across the SOC"
        icon={ListChecks}
        badge={
          isLoading && !usingDemo
            ? { label: "Loading…", tone: "neutral" }
            : usingDemo
              ? { label: "DEMO DATA", tone: "warning" }
              : { label: "LIVE", tone: "success" }
        }
      />

      {/* Controls */}
      <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-wrap gap-1.5">
          {statusFilters.map((f) => (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              className={cn(
                "flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer",
                filter === f.key
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-border bg-surface/50 text-muted-foreground hover:text-foreground"
              )}
            >
              {f.label}
              <span className={cn("rounded px-1 text-[0.65rem]", filter === f.key ? "bg-primary/20" : "bg-surface-overlay/70")}>
                {counts[f.key] ?? 0}
              </span>
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <div className="relative w-full lg:w-72">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search cases, files, hashes…" className="pl-9" />
          </div>
          <button className="grid size-9 shrink-0 place-items-center rounded-md border border-border bg-surface/50 text-muted-foreground transition-colors hover:text-foreground cursor-pointer">
            <SlidersHorizontal className="size-4" />
          </button>
        </div>
      </div>

      {/* Table */}
      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[880px] text-sm">
            <thead>
              <tr className="border-b border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                <th className="px-5 py-3 font-medium">Case / Sample</th>
                <th className="px-3 py-3 font-medium">Severity</th>
                <th className="px-3 py-3 font-medium">Family</th>
                <th className="px-3 py-3 font-medium">Status / Progress</th>
                <th className="px-3 py-3 font-medium">Detections</th>
                <th className="px-3 py-3 font-medium">Analyst</th>
                <th className="px-5 py-3 text-right font-medium">Age</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((inv, i) => {
                const meta = statusMeta[inv.status];
                return (
                  <motion.tr
                    key={inv.id}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.03 }}
                    onClick={() => navigate(`/investigation/${inv.id}/static`)}
                    className="group cursor-pointer border-b border-border/50 transition-colors last:border-0 hover:bg-surface-overlay/40"
                  >
                    <td className="px-5 py-3.5">
                      <div className="flex items-center gap-3">
                        <span className="grid size-9 place-items-center rounded-lg text-[0.6rem] font-bold uppercase" style={fileTint(inv.severity)}>
                          {inv.sample.fileType}
                        </span>
                        <div className="min-w-0">
                          <div className="max-w-[220px] truncate font-medium text-foreground group-hover:text-primary">{inv.sample.filename}</div>
                          <div className="flex items-center gap-2 font-mono text-[0.7rem] text-muted-foreground">
                            <span>{inv.caseId}</span><span>·</span><span>{formatBytes(inv.sample.size)}</span>
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-3 py-3.5"><SeverityBadge severity={inv.severity} /></td>
                    <td className="px-3 py-3.5 text-muted-foreground">{inv.malwareFamily}</td>
                    <td className="px-3 py-3.5">
                      <div className="w-40">
                        <div className="mb-1 flex items-center gap-1.5">
                          <span className={cn("size-1.5 rounded-full", meta.dot)} />
                          <span className="text-xs text-foreground">{meta.label}</span>
                          {inv.status !== "completed" && inv.status !== "queued" && (
                            <span className="ml-auto font-mono text-[0.7rem] text-muted-foreground">{inv.progress}%</span>
                          )}
                        </div>
                        {inv.status !== "queued" && (
                          <Progress value={inv.progress} className="h-1" indicatorClassName={inv.status === "completed" ? "from-success to-success" : undefined} />
                        )}
                        {inv.currentStage && inv.status !== "completed" && (
                          <div className="mt-1 max-w-[160px] truncate text-[0.65rem] text-muted-foreground">{inv.currentStage}</div>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-3.5">
                      {inv.totalEngines ? (
                        <span className="font-mono text-xs">
                          <span className={inv.detections > 30 ? "text-critical" : inv.detections > 0 ? "text-medium" : "text-success"}>{inv.detections}</span>
                          <span className="text-muted-foreground">/{inv.totalEngines}</span>
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">pending</span>
                      )}
                    </td>
                    <td className="px-3 py-3.5">
                      <span className="text-xs text-muted-foreground">{inv.assignedTo}</span>
                    </td>
                    <td className="px-5 py-3.5 text-right text-xs text-muted-foreground">{timeAgo(inv.createdAt)}</td>
                  </motion.tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {rows.length === 0 && (
          <div className="grid place-items-center py-16 text-center text-sm text-muted-foreground">
            No investigations match your filters.
          </div>
        )}
      </Card>
    </div>
  );
}

function fileTint(sev: string): React.CSSProperties {
  const map: Record<string, string> = {
    critical: "#f43f5e",
    high: "#fb923c",
    medium: "#facc15",
    low: "#38bdf8",
    info: "#818cf8",
    clean: "#34d399",
  };
  const c = map[sev] ?? "#64748b";
  return { background: `${c}1a`, color: c };
}
