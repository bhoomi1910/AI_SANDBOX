import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { useQuery } from "@tanstack/react-query";
import { AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from "recharts";
import { ShieldAlert, Radar, Timer, FlaskConical, ArrowUpRight, Cpu, Server, Rss, ChevronRight } from "lucide-react";
import { PageHeader } from "@/components/shared/PageHeader";
import { StatTile } from "@/components/shared/StatTile";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/badge";
import { cn, timeAgo } from "@/lib/utils";
import { api, USE_BACKEND } from "@/lib/api";
import {
  dashboardStats as mockStats,
  trendData,
  malwareFamilies,
  severityBreakdown as mockSeverity,
  threatFeed,
  systemHealth as mockHealth,
} from "@/data/dashboard";
import { investigations as mockRecent, statusMeta } from "@/data/investigations";

const chartTooltip = {
  contentStyle: {
    background: "rgba(17,26,46,0.96)",
    border: "1px solid rgba(148,163,184,0.18)",
    borderRadius: 10,
    fontSize: 12,
    color: "#e2e8f0",
    boxShadow: "0 12px 32px -12px rgba(0,0,0,0.8)",
  },
  labelStyle: { color: "#8b9ab5", marginBottom: 4 },
};

export default function Dashboard() {
  const navigate = useNavigate();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["dashboard-stats"],
    queryFn: () => api.dashboardStats(),
    retry: 1,
    refetchInterval: 15000,
    enabled: USE_BACKEND,
  });
  const usingDemo = !USE_BACKEND || isError;
  const stats = usingDemo ? null : data;

  const recent = stats?.recentInvestigations?.length ? stats.recentInvestigations : mockRecent.slice(0, 6);
  const severityBreakdown = stats?.severityBreakdown?.length ? stats.severityBreakdown : mockSeverity;
  const systemHealth = stats?.systemHealth?.length ? stats.systemHealth : mockHealth;
  const totalFamilies = malwareFamilies.reduce((s, f) => s + f.value, 0);

  const kpi = {
    total: stats?.totalInvestigations?.value ?? mockStats.totalInvestigations.value,
    active: stats?.activeAnalyses?.value ?? mockStats.activeDetonations.value,
    critical: stats?.criticalAlerts?.value ?? mockStats.criticalAlerts.value,
    completed: stats?.completedAnalyses?.value ?? 0,
  };

  return (
    <div>
      <PageHeader
        title="Security Operations Dashboard"
        subtitle="Live view of malware investigations, detections, and threat intelligence"
        icon={ShieldAlert}
        badge={
          isLoading && !usingDemo
            ? { label: "Loading…", tone: "neutral" }
            : usingDemo
              ? { label: "DEMO DATA", tone: "warning" }
              : { label: "LIVE", tone: "success" }
        }
        actions={
          <>
            <Button variant="outline" size="md" onClick={() => navigate("/queue")}>
              View queue
            </Button>
            <Button size="md" onClick={() => navigate("/upload")}>
              <FlaskConical className="size-4" /> New analysis
            </Button>
          </>
        }
      />

      {/* KPI row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile index={0} label="Total Investigations" value={kpi.total.toLocaleString()} icon={Radar} color="#22d3ee" />
        <StatTile index={1} label="Active Analyses" value={kpi.active} icon={FlaskConical} color="#6366f1" />
        <StatTile index={2} label="Critical Alerts" value={kpi.critical} icon={ShieldAlert} color="#f43f5e" />
        <StatTile index={3} label="Completed Analyses" value={kpi.completed} icon={Timer} color="#34d399" />
      </div>

      {/* Charts row */}
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Trend */}
        <Card className="xl:col-span-2">
          <CardHeader>
            <div>
              <CardTitle>Investigation & Detection Trend</CardTitle>
              <p className="mt-0.5 text-xs text-muted-foreground">Last 30 days · demo dataset</p>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <span className="flex items-center gap-1.5 text-muted-foreground"><span className="size-2 rounded-full bg-primary" /> Investigations</span>
              <span className="flex items-center gap-1.5 text-muted-foreground"><span className="size-2 rounded-full bg-critical" /> Malicious</span>
            </div>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gInv" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gMal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="#f43f5e" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" vertical={false} />
                  <XAxis dataKey="day" tick={{ fill: "#8b9ab5", fontSize: 10 }} tickLine={false} axisLine={false} interval={5} />
                  <YAxis tick={{ fill: "#8b9ab5", fontSize: 10 }} tickLine={false} axisLine={false} />
                  <Tooltip {...chartTooltip} />
                  <Area type="monotone" dataKey="investigations" stroke="#22d3ee" strokeWidth={2} fill="url(#gInv)" />
                  <Area type="monotone" dataKey="malicious" stroke="#f43f5e" strokeWidth={2} fill="url(#gMal)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Malware families donut */}
        <Card>
          <CardHeader>
            <CardTitle>Top Malware Families</CardTitle>
            <span className="text-xs text-muted-foreground">30 days · demo</span>
          </CardHeader>
          <CardContent>
            <div className="relative h-40">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={malwareFamilies} dataKey="value" nameKey="name" innerRadius={52} outerRadius={72} paddingAngle={2} stroke="none">
                    {malwareFamilies.map((f) => (
                      <Cell key={f.name} fill={f.color} />
                    ))}
                  </Pie>
                  <Tooltip {...chartTooltip} />
                </PieChart>
              </ResponsiveContainer>
              <div className="pointer-events-none absolute inset-0 grid place-content-center text-center">
                <div className="text-xl font-bold text-foreground">{totalFamilies.toLocaleString()}</div>
                <div className="text-[0.65rem] uppercase tracking-wide text-muted-foreground">Detections</div>
              </div>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5">
              {malwareFamilies.map((f) => (
                <div key={f.name} className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 text-muted-foreground">
                    <span className="size-2 rounded-full" style={{ background: f.color }} />
                    {f.name}
                  </span>
                  <span className="font-mono text-foreground">{f.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main grid */}
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Recent investigations */}
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Recent Investigations</CardTitle>
            <Link to="/queue" className="flex items-center gap-1 text-xs text-primary hover:underline">
              View all <ChevronRight className="size-3" />
            </Link>
          </CardHeader>
          <CardContent className="px-0 pb-0">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-y border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                    <th className="px-5 py-2.5 font-medium">Sample</th>
                    <th className="px-3 py-2.5 font-medium">Family</th>
                    <th className="px-3 py-2.5 font-medium">Severity</th>
                    <th className="px-3 py-2.5 font-medium">Status</th>
                    <th className="px-3 py-2.5 font-medium">Detections</th>
                    <th className="px-5 py-2.5 text-right font-medium">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((inv) => {
                    const meta = statusMeta[inv.status];
                    return (
                      <tr
                        key={inv.id}
                        onClick={() => navigate(`/investigation/${inv.id}/ai`)}
                        className="cursor-pointer border-b border-border/60 transition-colors last:border-0 hover:bg-surface-overlay/40"
                      >
                        <td className="px-5 py-3">
                          <div className="flex items-center gap-2.5">
                            <span className="grid size-8 place-items-center rounded-lg text-[0.6rem] font-bold uppercase" style={fileTint(inv.severity)}>
                              {inv.sample.fileType}
                            </span>
                            <div className="min-w-0">
                              <div className="max-w-[180px] truncate font-medium text-foreground">{inv.sample.filename}</div>
                              <div className="font-mono text-[0.7rem] text-muted-foreground">{inv.caseId}</div>
                            </div>
                          </div>
                        </td>
                        <td className="px-3 py-3 text-muted-foreground">{inv.malwareFamily}</td>
                        <td className="px-3 py-3"><SeverityBadge severity={inv.severity} /></td>
                        <td className="px-3 py-3">
                          <span className={cn("badge", meta.tone)}>
                            <span className={cn("size-1.5 rounded-full", meta.dot)} />
                            {meta.label}
                          </span>
                        </td>
                        <td className="px-3 py-3">
                          {inv.totalEngines ? (
                            <span className="font-mono text-xs"><span className={inv.detections > 30 ? "text-critical" : "text-medium"}>{inv.detections}</span><span className="text-muted-foreground">/{inv.totalEngines}</span></span>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </td>
                        <td className="px-5 py-3 text-right text-xs text-muted-foreground">{timeAgo(inv.createdAt)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* Severity + system health stacked */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Severity Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-36">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityBreakdown} layout="vertical" margin={{ left: 8, right: 16, top: 0, bottom: 0 }}>
                    <XAxis type="number" hide />
                    <YAxis type="category" dataKey="name" tick={{ fill: "#8b9ab5", fontSize: 11 }} tickLine={false} axisLine={false} width={56} />
                    <Tooltip {...chartTooltip} cursor={{ fill: "rgba(148,163,184,0.06)" }} />
                    <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={16}>
                      {severityBreakdown.map((s) => (
                        <Cell key={s.name} fill={s.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Server className="size-4 text-primary" /> System Health</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {systemHealth.map((s) => (
                <div key={s.name}>
                  <div className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-1.5 text-foreground">
                      <span className={cn("size-1.5 rounded-full", s.status === "operational" ? "bg-success" : "bg-medium")} />
                      {s.name}
                    </span>
                    <span className="font-mono text-muted-foreground">{s.load}%</span>
                  </div>
                  <div className="mt-1 h-1 overflow-hidden rounded-full bg-surface-overlay">
                    <div className={cn("h-full rounded-full", s.load > 85 ? "bg-critical" : s.load > 70 ? "bg-medium" : "bg-success")} style={{ width: `${s.load}%` }} />
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Threat feed */}
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Rss className="size-4 text-primary" /> Live Threat Intelligence Feed</CardTitle>
            <span className="badge border-medium/30 bg-medium/10 text-medium"><span className="size-1.5 rounded-full bg-medium" /> Demo feed</span>
          </CardHeader>
          <CardContent className="space-y-1">
            {threatFeed.map((f, i) => (
              <motion.div
                key={f.id}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
                className="flex items-start gap-3 rounded-lg px-2 py-2.5 transition-colors hover:bg-surface-overlay/40"
              >
                <SeverityBadge severity={f.severity} className="mt-0.5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <div className="text-sm text-foreground">{f.title}</div>
                  <div className="mt-0.5 flex items-center gap-2 text-[0.7rem] text-muted-foreground">
                    <span>{f.source}</span><span>·</span><span>{f.time}</span>
                  </div>
                </div>
                <ArrowUpRight className="mt-1 size-3.5 shrink-0 text-muted-foreground" />
              </motion.div>
            ))}
          </CardContent>
        </Card>

        {/* AI engine card */}
        <Card className="relative overflow-hidden">
          <div className="pointer-events-none absolute -right-8 -top-8 size-40 rounded-full bg-accent/10 blur-3xl" />
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Cpu className="size-4 text-accent" /> AI Analysis Engine</CardTitle>
            <span className="badge border-medium/30 bg-medium/10 text-medium">Ollama · not configured</span>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-xs leading-relaxed text-muted-foreground">
              The AI engine runs on Ollama with a local model (no API keys, no paid credits).
              It is wired into the pipeline as the final analysis stage and is not yet configured
              on this machine — install Ollama to enable it.
            </p>
            <div className="space-y-2.5">
              {[
                { k: "Provider", v: "Ollama (local)" },
                { k: "Model", v: "qwen3 (default)" },
                { k: "Status", v: "Not configured" },
                { k: "Static analysis", v: "Module pending" },
              ].map((r) => (
                <div key={r.k} className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{r.k}</span>
                  <span className="font-mono text-foreground">{r.v}</span>
                </div>
              ))}
            </div>
            <Button variant="subtle" className="w-full" onClick={() => navigate("/upload")}>
              Submit a sample <ChevronRight className="size-4" />
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// Inline tint since Tailwind can't see dynamic class names at build time.
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
