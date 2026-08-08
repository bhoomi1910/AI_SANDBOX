import { NavLink, Outlet, useParams, Link } from "react-router-dom";
import { motion } from "framer-motion";
import { useQuery } from "@tanstack/react-query";
import {
  FileSearch,
  Activity,
  Network,
  Radar,
  Crosshair,
  Sparkles,
  FileText,
  ArrowLeft,
  FileWarning,
} from "lucide-react";
import { getInvestigation, statusMeta } from "@/data/investigations";
import { api, USE_BACKEND } from "@/lib/api";
import { SeverityBadge } from "@/components/ui/badge";
import { CopyChip } from "@/components/ui/misc";
import { cn, formatBytes, timeAgo } from "@/lib/utils";

const tabs = [
  { label: "Static", to: "static", icon: FileSearch },
  { label: "Dynamic", to: "dynamic", icon: Activity },
  { label: "Network", to: "network", icon: Network },
  { label: "Threat Intel", to: "intel", icon: Radar },
  { label: "MITRE ATT&CK", to: "mitre", icon: Crosshair },
  { label: "AI Investigation", to: "ai", icon: Sparkles, hero: true },
  { label: "Report", to: "report", icon: FileText },
];

export function InvestigationLayout() {
  const { id = "inv-0412" } = useParams();
  const mockInv = getInvestigation(id);
  const { data: liveInv } = useQuery({
    queryKey: ["investigation", id],
    queryFn: () => api.getInvestigation(id),
    retry: 1,
    enabled: USE_BACKEND && !mockInv,
  });
  const inv = liveInv ?? mockInv;

  if (!inv) {
    return (
      <div className="grid place-items-center py-24 text-center">
        <FileWarning className="mb-3 size-10 text-muted-foreground" />
        <p className="text-foreground">Investigation not found.</p>
        <Link to="/queue" className="mt-2 text-sm text-primary hover:underline">
          Back to queue
        </Link>
      </div>
    );
  }

  const meta = statusMeta[inv.status];

  return (
    <div>
      {/* Case header */}
      <motion.div
        initial={{ opacity: 0, y: -6 }}
        animate={{ opacity: 1, y: 0 }}
        className="panel-raised mb-5 overflow-hidden"
      >
        <div className="flex flex-col gap-4 p-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-start gap-4">
            <Link
              to="/queue"
              className="mt-0.5 grid size-9 shrink-0 place-items-center rounded-lg border border-border text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
              title="Back to queue"
            >
              <ArrowLeft className="size-4" />
            </Link>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-primary">{inv.caseId}</span>
                <SeverityBadge severity={inv.severity} />
                <span className={cn("badge", meta.tone)}>
                  <span className={cn("size-1.5 rounded-full", meta.dot)} />
                  {meta.label}
                </span>
              </div>
              <h2 className="mt-1 truncate text-lg font-bold tracking-tight text-foreground">
                {inv.sample.filename}
              </h2>
              <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                <span>{formatBytes(inv.sample.size)}</span>
                <span className="uppercase">{inv.sample.fileType}</span>
                <span>{inv.malwareFamily}</span>
                <span>Submitted {timeAgo(inv.createdAt)}</span>
                <span>Assigned: {inv.assignedTo}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-5">
            <div className="text-right">
              <div className="text-[0.65rem] uppercase tracking-wide text-muted-foreground">Detections</div>
              <div className="font-mono text-lg font-bold text-critical">
                {inv.detections}
                <span className="text-sm text-muted-foreground">/{inv.totalEngines}</span>
              </div>
            </div>
            <div className="h-10 w-px bg-border" />
            <div className="text-right">
              <div className="text-[0.65rem] uppercase tracking-wide text-muted-foreground">Risk Score</div>
              <div className="font-mono text-lg font-bold text-high">{inv.riskScore}</div>
            </div>
            <div className="h-10 w-px bg-border" />
            <div className="text-right">
              <div className="text-[0.65rem] uppercase tracking-wide text-muted-foreground">AI Confidence</div>
              <div className="font-mono text-lg font-bold text-primary">{inv.aiConfidence}%</div>
            </div>
          </div>
        </div>

        {/* SHA256 strip */}
        <div className="flex flex-wrap items-center gap-2 border-t border-border bg-surface/40 px-5 py-2.5">
          <span className="text-[0.65rem] uppercase tracking-wide text-muted-foreground">SHA-256</span>
          <CopyChip value={inv.sample.sha256} />
          <span className="ml-2 text-[0.65rem] uppercase tracking-wide text-muted-foreground">MD5</span>
          <CopyChip value={inv.sample.md5} />
        </div>
      </motion.div>

      {/* Analysis sub-nav */}
      <div className="mb-6 flex gap-1 overflow-x-auto rounded-xl border border-border bg-surface/50 p-1 backdrop-blur no-scrollbar">
        {tabs.map((t) => (
          <NavLink
            key={t.to}
            to={`/investigation/${inv.id}/${t.to}`}
            className={({ isActive }) =>
              cn(
                "relative flex shrink-0 items-center gap-2 rounded-lg px-3.5 py-2 text-sm transition-colors",
                isActive
                  ? "text-foreground"
                  : "text-muted-foreground hover:bg-surface-overlay/50 hover:text-foreground"
              )
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <motion.span
                    layoutId="inv-tab-active"
                    className="absolute inset-0 rounded-lg bg-primary/12 ring-1 ring-primary/25"
                  />
                )}
                <t.icon className={cn("relative size-4", t.hero && "text-accent")} />
                <span className="relative">{t.label}</span>
              </>
            )}
          </NavLink>
        ))}
      </div>

      <Outlet context={{ inv }} />
    </div>
  );
}
