import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid } from "recharts";
import { ShieldAlert, Radar, Timer, FlaskConical, Cpu, Server, ChevronRight, Globe, FileCode, Hash, Target } from "lucide-react";
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
  severityBreakdown as mockSeverity,
  systemHealth as mockHealth,
  iocStatistics as mockIocs,
  yaraStatistics as mockYara,
  mitreStatistics as mockMitre,
  fileTypeDistribution as mockFileTypes,
  verdictDistribution as mockVerdicts,
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

const COLORS = ["#f43f5e", "#fb923c", "#facc15", "#22d3ee", "#6366f1", "#34d399", "#a78bfa", "#f472b6", "#e879f9", "#6ee7b7"];

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
  const highRisk = stats?.highRiskInvestigations ?? [];

  const kpi = {
    total: stats?.summary?.total ?? mockStats.totalInvestigations.value,
    active: stats?.summary?.active ?? mockStats.activeDetonations.value,
    critical: stats?.summary?.completed ?? 0,
    completed: stats?.summary?.completed ?? 0,
    failed: stats?.summary?.failed ?? 0,
    today: stats?.summary?.today ?? 0,
  };

  const timeline = stats?.timeline ?? trendData.map(d => ({ date: d.day, count: d.investigations }));
  const fileTypeDistribution = stats?.fileTypeDistribution?.length ? stats.fileTypeDistribution : mockFileTypes;
  const verdictDistribution = stats?.verdictDistribution?.length ? stats.verdictDistribution : mockVerdicts;
  const iocStats = stats?.iocStatistics ?? mockIocs;
  const yaraStats = stats?.yaraStatistics ?? mockYara;
  const mitreStats = stats?.mitreStatistics ?? mockMitre;
  const totalFamilies = (stats?.malwareFamilies ?? []).reduce((s, f) => s + f.value, 0);

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
        <StatTile index={2} label="Completed" value={kpi.completed} icon={Timer} color="#34d399" />
        <StatTile index={3} label="Failed" value={kpi.failed} icon={ShieldAlert} color="#f43f5e" />
      </div>

      {/* Second KPI row */}
      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile index={4} label="Analyzed Today" value={kpi.today} icon={Radar} color="#22d3ee" />
        <StatTile index={5} label="Total IOCs" value={iocStats.total} icon={Globe} color="#6366f1" />
        <StatTile index={6} label="YARA Matches" value={yaraStats.total_matches} icon={FileCode} color="#facc15" />
        <StatTile index={7} label="MITRE Techniques" value={mitreStats.unique_techniques} icon={Target} color="#f43f5e" />
      </div>

      {/* Charts row 1: Trend + Severity */}
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Trend */}
        <Card className="xl:col-span-2">
          <CardHeader>
            <div>
              <CardTitle>Investigation Activity</CardTitle>
              <p className="mt-0.5 text-xs text-muted-foreground">Last 30 days{usingDemo ? " · demo dataset" : ""}</p>
            </div>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gInv" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" vertical={false} />
                  <XAxis dataKey="date" tick={{ fill: "#8b9ab5", fontSize: 10 }} tickLine={false} axisLine={false} interval={4} tickFormatter={(v: string) => v.slice(5)} />
                  <YAxis tick={{ fill: "#8b9ab5", fontSize: 10 }} tickLine={false} axisLine={false} />
                  <Tooltip {...chartTooltip} />
                  <Area type="monotone" dataKey="count" stroke="#22d3ee" strokeWidth={2} fill="url(#gInv)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Severity donut */}
        <Card>
          <CardHeader>
            <CardTitle>Severity Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="relative h-40">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={severityBreakdown} dataKey="value" nameKey="name" innerRadius={52} outerRadius={72} paddingAngle={2} stroke="none">
                    {severityBreakdown.map((s) => (
                      <Cell key={s.name} fill={s.color} />
                    ))}
                  </Pie>
                  <Tooltip {...chartTooltip} />
                </PieChart>
              </ResponsiveContainer>
              <div className="pointer-events-none absolute inset-0 grid place-content-center text-center">
                <div className="text-xl font-bold text-foreground">{kpi.total}</div>
                <div className="text-[0.65rem] uppercase tracking-wide text-muted-foreground">Total</div>
              </div>
            </div>
            <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5">
              {severityBreakdown.map((s) => (
                <div key={s.name} className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 text-muted-foreground">
                    <span className="size-2 rounded-full" style={{ background: s.color }} />
                    {s.name}
                  </span>
                  <span className="font-mono text-foreground">{s.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts row 2: File type + Verdict + Malware families */}
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* File type distribution */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><FileCode className="size-4 text-primary" /> File Types</CardTitle>
          </CardHeader>
          <CardContent>
            {fileTypeDistribution.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">No file type data available.</p>
            ) : (
              <div className="space-y-2">
                {fileTypeDistribution.map((ft, i) => {
                  const maxVal = fileTypeDistribution[0]?.value || 1;
                  const pct = (ft.value / maxVal) * 100;
                  return (
                    <div key={ft.name} className="flex items-center gap-3">
                      <span className="w-12 text-right text-xs font-mono text-muted-foreground">{ft.name}</span>
                      <div className="flex-1">
                        <div className="h-2 overflow-hidden rounded-full bg-surface-overlay">
                          <div className="h-full rounded-full" style={{ width: `${pct}%`, background: COLORS[i % COLORS.length] }} />
                        </div>
                      </div>
                      <span className="w-8 text-right text-xs font-mono text-foreground">{ft.value}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Verdict distribution */}
        <Card>
          <CardHeader>
            <CardTitle>Verdict Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {verdictDistribution.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">No verdict data available.</p>
            ) : (
              <>
                <div className="relative h-36">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={verdictDistribution} dataKey="value" nameKey="name" innerRadius={42} outerRadius={62} paddingAngle={3} stroke="none">
                        {verdictDistribution.map((v) => (
                          <Cell key={v.name} fill={v.color} />
                        ))}
                      </Pie>
                      <Tooltip {...chartTooltip} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="mt-2 grid grid-cols-3 gap-2">
                  {verdictDistribution.map((v) => (
                    <div key={v.name} className="text-center">
                      <div className="text-lg font-bold text-foreground">{v.value}</div>
                      <div className="text-[0.65rem] text-muted-foreground">{v.name}</div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* Top malware families */}
        <Card>
          <CardHeader>
            <CardTitle>Top Malware Families</CardTitle>
          </CardHeader>
          <CardContent>
            {totalFamilies === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">No malware families detected.</p>
            ) : (
              <div className="relative h-36">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={stats?.malwareFamilies ?? []} dataKey="value" nameKey="name" innerRadius={42} outerRadius={62} paddingAngle={2} stroke="none">
                      {(stats?.malwareFamilies ?? []).map((f, i) => (
                        <Cell key={f.name} fill={COLORS[i % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip {...chartTooltip} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="pointer-events-none absolute inset-0 grid place-content-center text-center">
                  <div className="text-xl font-bold text-foreground">{totalFamilies}</div>
                  <div className="text-[0.65rem] uppercase tracking-wide text-muted-foreground">Families</div>
                </div>
              </div>
            )}
            <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5">
              {(stats?.malwareFamilies ?? []).slice(0, 6).map((f, i) => (
                <div key={f.name} className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 text-muted-foreground">
                    <span className="size-2 rounded-full" style={{ background: COLORS[i % COLORS.length] }} />
                    {f.name}
                  </span>
                  <span className="font-mono text-foreground">{f.value}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main grid: Recent + Sidebar */}
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

        {/* Sidebar: Severity + system health */}
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

      {/* IOC, YARA, MITRE overview */}
      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* IOC statistics */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Globe className="size-4 text-primary" /> IOC Overview</CardTitle>
            <span className="text-xs text-muted-foreground">{iocStats.total} total indicators extracted</span>
          </CardHeader>
          <CardContent>
            {iocStats.total === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">No IOCs extracted yet.</p>
            ) : (
              <div className="space-y-2">
                {iocStats.by_type.map((ioc, i) => {
                  const maxVal = iocStats.by_type[0]?.count || 1;
                  const pct = (ioc.count / maxVal) * 100;
                  return (
                    <div key={ioc.type} className="flex items-center gap-3">
                      <span className="w-20 text-right text-xs font-mono text-muted-foreground">{ioc.type}</span>
                      <div className="flex-1">
                        <div className="h-2 overflow-hidden rounded-full bg-surface-overlay">
                          <div className="h-full rounded-full" style={{ width: `${pct}%`, background: COLORS[i % COLORS.length] }} />
                        </div>
                      </div>
                      <span className="w-8 text-right text-xs font-mono text-foreground">{ioc.count}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* YARA statistics */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><FileCode className="size-4 text-accent" /> YARA Matches</CardTitle>
            <span className="text-xs text-muted-foreground">{yaraStats.investigations_with_matches} investigations with hits</span>
          </CardHeader>
          <CardContent>
            {yaraStats.total_matches === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">No YARA matches yet.</p>
            ) : (
              <div className="space-y-2">
                {yaraStats.top_rules.map((rule) => {
                  const maxVal = yaraStats.top_rules[0]?.count || 1;
                  const pct = (rule.count / maxVal) * 100;
                  return (
                    <div key={rule.rule} className="flex items-center gap-3">
                      <span className="w-32 truncate text-right text-xs font-mono text-muted-foreground">{rule.rule}</span>
                      <div className="flex-1">
                        <div className="h-2 overflow-hidden rounded-full bg-surface-overlay">
                          <div className="h-full rounded-full bg-accent" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                      <span className="w-8 text-right text-xs font-mono text-foreground">{rule.count}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* MITRE statistics */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Target className="size-4 text-critical" /> MITRE ATT&CK</CardTitle>
            <span className="text-xs text-muted-foreground">{mitreStats.investigations_with_mitre} investigations mapped</span>
          </CardHeader>
          <CardContent>
            {mitreStats.unique_techniques === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">No MITRE mappings yet.</p>
            ) : (
              <>
                <div className="mb-3 grid grid-cols-2 gap-2">
                  <div className="rounded-lg bg-surface-overlay/60 p-2 text-center">
                    <div className="text-lg font-bold text-foreground">{mitreStats.unique_techniques}</div>
                    <div className="text-[0.65rem] text-muted-foreground">Unique Techniques</div>
                  </div>
                  <div className="rounded-lg bg-surface-overlay/60 p-2 text-center">
                    <div className="text-lg font-bold text-foreground">{mitreStats.top_tactics.length}</div>
                    <div className="text-[0.65rem] text-muted-foreground">Tactics</div>
                  </div>
                </div>
                <div className="space-y-1.5">
                  {mitreStats.top_techniques.slice(0, 5).map((t) => (
                    <div key={t.technique} className="flex items-center justify-between text-xs">
                      <span className="flex items-center gap-1.5 text-muted-foreground">
                        <Hash className="size-3" />
                        {t.technique}
                      </span>
                      <span className="font-mono text-foreground">{t.count}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>

      {/* High-risk investigations */}
      {highRisk.length > 0 && (
        <div className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><ShieldAlert className="size-4 text-critical" /> High-Risk Investigations</CardTitle>
              <span className="text-xs text-muted-foreground">Recent critical and high severity cases</span>
            </CardHeader>
            <CardContent className="px-0 pb-0">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-y border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                      <th className="px-5 py-2.5 font-medium">Sample</th>
                      <th className="px-3 py-2.5 font-medium">Severity</th>
                      <th className="px-3 py-2.5 font-medium">Verdict</th>
                      <th className="px-3 py-2.5 font-medium">Risk Score</th>
                      <th className="px-3 py-2.5 font-medium">Family</th>
                      <th className="px-5 py-2.5 text-right font-medium">Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {highRisk.map((inv) => (
                      <tr
                        key={inv.id}
                        onClick={() => navigate(`/investigation/${inv.id}/ai`)}
                        className="cursor-pointer border-b border-border/60 transition-colors last:border-0 hover:bg-surface-overlay/40"
                      >
                        <td className="px-5 py-3">
                          <div className="min-w-0">
                            <div className="max-w-[200px] truncate font-medium text-foreground">{inv.sample.filename}</div>
                            <div className="font-mono text-[0.7rem] text-muted-foreground">{inv.caseId}</div>
                          </div>
                        </td>
                        <td className="px-3 py-3"><SeverityBadge severity={inv.severity} /></td>
                        <td className="px-3 py-3">
                          <span className={cn("badge", inv.verdict === "malicious" ? "text-critical bg-critical/10 border-critical/30" : "text-medium bg-medium/10 border-medium/30")}>
                            {inv.verdict}
                          </span>
                        </td>
                        <td className="px-3 py-3">
                          <span className={cn("font-mono text-xs font-bold", inv.riskScore >= 80 ? "text-critical" : inv.riskScore >= 50 ? "text-medium" : "text-success")}>
                            {inv.riskScore}
                          </span>
                        </td>
                        <td className="px-3 py-3 text-muted-foreground">{inv.malwareFamily}</td>
                        <td className="px-5 py-3 text-right text-xs text-muted-foreground">{timeAgo(inv.createdAt)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* AI engine card */}
      <div className="mt-4">
        <Card className="relative overflow-hidden">
          <div className="pointer-events-none absolute -right-8 -top-8 size-40 rounded-full bg-accent/10 blur-3xl" />
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Cpu className="size-4 text-accent" /> AI Analysis Engine</CardTitle>
            <span className="badge border-medium/30 bg-medium/10 text-medium">Ollama · local inference</span>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-xs leading-relaxed text-muted-foreground">
              The AI engine runs on Ollama with a local model (no API keys, no paid credits).
              It is wired into the pipeline as the final analysis stage and interprets
              deterministic findings into human-readable summaries.
            </p>
            <div className="space-y-2.5">
              {[
                { k: "Provider", v: "Ollama (local)" },
                { k: "Model", v: "qwen3 (default)" },
                { k: "Static analysis", v: "Operational" },
                { k: "MITRE mapping", v: `${mitreStats.unique_techniques} techniques` },
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
