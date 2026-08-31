import { useState } from "react";
import { NavLink, Outlet, useParams, Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
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
  ChevronDown,
  ChevronUp,
  Save,
  XCircle,
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
  const queryClient = useQueryClient();
  const [showClosure, setShowClosure] = useState(false);
  const [patch, setPatch] = useState<Record<string, unknown>>({});

  const mockInv = getInvestigation(id);
  const { data: liveInv } = useQuery({
    queryKey: ["investigation", id],
    queryFn: () => api.getInvestigation(id),
    retry: 1,
    enabled: USE_BACKEND && !mockInv,
  });
  const inv = liveInv ?? mockInv;

  const updateMut = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.updateInvestigation(id, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["investigation", id] });
      queryClient.invalidateQueries({ queryKey: ["investigations"] });
      setPatch({});
      setShowClosure(false);
    },
  });

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
  const isClosed = inv.status === "closed";
  const isCompleted = inv.status === "completed";

  const setField = (key: string, value: unknown) =>
    setPatch((p) => ({ ...p, [key]: value }));

  const handleSave = () => {
    if (Object.keys(patch).length === 0) return;
    updateMut.mutate(patch);
  };

  const handleClose = () => {
    const resolution = (patch.resolution as string) ?? "true-positive";
    const notes = (patch.closureNotes as string) ?? "";
    updateMut.mutate({ resolution, closureNotes: notes });
  };

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
                {inv.resolution && (
                  <span className="badge border-success/30 bg-success/10 text-success">
                    {inv.resolution}
                  </span>
                )}
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
                {inv.closedAt && (
                  <span className="text-success">
                    Closed {timeAgo(inv.closedAt)} by {inv.closedBy}
                  </span>
                )}
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

      {/* Case management bar */}
      {!isClosed && (isCompleted || inv.status === "failed") && (
        <div className="mb-4">
          <button
            onClick={() => setShowClosure(!showClosure)}
            className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground"
          >
            {showClosure ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}
            {showClosure ? "Hide case management" : "Open case management"}
          </button>

          <AnimatePresence>
            {showClosure && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden"
              >
                <div className="mt-3 rounded-xl border border-border bg-surface/60 p-4">
                  <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                    {/* Verdict */}
                    <div>
                      <label className="mb-1 block text-[0.65rem] uppercase tracking-wide text-muted-foreground">
                        Verdict
                      </label>
                      <select
                        value={(patch.verdict as string) ?? inv.verdict}
                        onChange={(e) => setField("verdict", e.target.value)}
                        className="w-full rounded-lg border border-border bg-surface px-3 py-1.5 text-sm text-foreground"
                      >
                        <option value="malicious">Malicious</option>
                        <option value="suspicious">Suspicious</option>
                        <option value="clean">Clean</option>
                      </select>
                    </div>

                    {/* Severity */}
                    <div>
                      <label className="mb-1 block text-[0.65rem] uppercase tracking-wide text-muted-foreground">
                        Severity
                      </label>
                      <select
                        value={(patch.severity as string) ?? inv.severity}
                        onChange={(e) => setField("severity", e.target.value)}
                        className="w-full rounded-lg border border-border bg-surface px-3 py-1.5 text-sm text-foreground"
                      >
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="info">Info</option>
                      </select>
                    </div>

                    {/* Assigned to */}
                    <div>
                      <label className="mb-1 block text-[0.65rem] uppercase tracking-wide text-muted-foreground">
                        Assigned to
                      </label>
                      <input
                        type="text"
                        value={(patch.assignedTo as string) ?? inv.assignedTo}
                        onChange={(e) => setField("assignedTo", e.target.value)}
                        className="w-full rounded-lg border border-border bg-surface px-3 py-1.5 text-sm text-foreground"
                      />
                    </div>

                    {/* Family */}
                    <div>
                      <label className="mb-1 block text-[0.65rem] uppercase tracking-wide text-muted-foreground">
                        Malware Family
                      </label>
                      <input
                        type="text"
                        value={(patch.malwareFamily as string) ?? inv.malwareFamily}
                        onChange={(e) => setField("malwareFamily", e.target.value)}
                        className="w-full rounded-lg border border-border bg-surface px-3 py-1.5 text-sm text-foreground"
                      />
                    </div>
                  </div>

                  <div className="mt-4 grid gap-4 sm:grid-cols-2">
                    {/* Resolution */}
                    <div>
                      <label className="mb-1 block text-[0.65rem] uppercase tracking-wide text-muted-foreground">
                        Resolution
                      </label>
                      <select
                        value={(patch.resolution as string) ?? ""}
                        onChange={(e) => setField("resolution", e.target.value)}
                        className="w-full rounded-lg border border-border bg-surface px-3 py-1.5 text-sm text-foreground"
                      >
                        <option value="">— Select resolution —</option>
                        <option value="true-positive">True Positive</option>
                        <option value="false-positive">False Positive</option>
                        <option value="escalated">Escalated</option>
                      </select>
                    </div>

                    {/* Closure notes */}
                    <div>
                      <label className="mb-1 block text-[0.65rem] uppercase tracking-wide text-muted-foreground">
                        Closure Notes
                      </label>
                      <input
                        type="text"
                        value={(patch.closureNotes as string) ?? ""}
                        onChange={(e) => setField("closureNotes", e.target.value)}
                        placeholder="Optional analyst notes..."
                        className="w-full rounded-lg border border-border bg-surface px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
                      />
                    </div>
                  </div>

                  <div className="mt-4 flex items-center gap-3">
                    <button
                      onClick={handleSave}
                      disabled={Object.keys(patch).length === 0 || updateMut.isPending}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
                    >
                      <Save className="size-3.5" />
                      {updateMut.isPending ? "Saving…" : "Save Changes"}
                    </button>
                    {Boolean(patch.resolution || patch.closureNotes) && !isClosed && isCompleted && (
                      <button
                        onClick={handleClose}
                        disabled={updateMut.isPending}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-success/40 bg-success/10 px-3 py-1.5 text-xs font-medium text-success transition-colors hover:bg-success/20 disabled:opacity-50"
                      >
                        <XCircle className="size-3.5" />
                        Close Case
                      </button>
                    )}
                    {Object.keys(patch).length > 0 && (
                      <button
                        onClick={() => setPatch({})}
                        className="text-xs text-muted-foreground hover:text-foreground"
                      >
                        Reset
                      </button>
                    )}
                    {updateMut.isError && (
                      <span className="text-xs text-destructive">
                        {(updateMut.error as Error).message}
                      </span>
                    )}
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* Closed case banner */}
      {isClosed && (
        <div className="mb-4 rounded-xl border border-success/30 bg-success/5 p-4">
          <div className="flex items-center gap-3">
            <XCircle className="size-5 text-success" />
            <div>
              <p className="text-sm font-medium text-foreground">
                Case closed as <span className="font-bold">{inv.resolution}</span>
                {inv.closedBy && <> by {inv.closedBy}</>}
                {inv.closedAt && <> — {timeAgo(inv.closedAt)}</>}
              </p>
              {inv.closureNotes && (
                <p className="mt-0.5 text-xs text-muted-foreground">{inv.closureNotes}</p>
              )}
            </div>
          </div>
        </div>
      )}

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
