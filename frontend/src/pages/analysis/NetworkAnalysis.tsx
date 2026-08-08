import { motion } from "framer-motion";
import {
  AreaChart,
  Area,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";
import { Network, Globe, Server, ArrowDownUp } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { SeverityBadge } from "@/components/ui/badge";
import { networkAnalysis as n } from "@/data/deepdive";
import { cn, formatBytes } from "@/lib/utils";
import { WorldMap } from "@/components/shared/WorldMap";

export default function NetworkAnalysis() {
  const maliciousConns = n.connections.filter((c) => c.malicious).length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
      {/* Summary tiles */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          { k: n.totalPackets.toLocaleString(), v: "Packets captured", icon: ArrowDownUp, c: "#22d3ee" },
          { k: formatBytes(n.totalBytes), v: "Total transferred", icon: Server, c: "#6366f1" },
          { k: n.connections.length, v: "Unique endpoints", icon: Globe, c: "#facc15" },
          { k: maliciousConns, v: "Malicious endpoints", icon: Network, c: "#f43f5e" },
        ].map((s) => (
          <Card key={s.v}>
            <CardContent className="flex items-center gap-3 pt-5">
              <div className="grid size-10 place-items-center rounded-lg" style={{ background: `${s.c}1a`, color: s.c }}>
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

      {/* Map + packet timeline */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Globe className="size-4 text-primary" /> C2 Infrastructure Map</CardTitle>
            <span className="text-xs text-muted-foreground">geolocated outbound connections</span>
          </CardHeader>
          <CardContent>
            <WorldMap connections={n.connections} />
            <div className="mt-3 flex flex-wrap gap-3 text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-critical" /> Malicious</span>
              <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-success" /> Benign</span>
              <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-primary" /> Sandbox origin</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Packet Timeline</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={n.packetTimeline} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
                  <defs>
                    <linearGradient id="gOut" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#f43f5e" stopOpacity={0.4} />
                      <stop offset="100%" stopColor="#f43f5e" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="gIn" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.08)" vertical={false} />
                  <XAxis dataKey="t" tick={{ fill: "#8b9ab5", fontSize: 9 }} tickLine={false} axisLine={false} tickFormatter={(v) => `${v}s`} interval={5} />
                  <YAxis tick={{ fill: "#8b9ab5", fontSize: 9 }} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ background: "rgba(17,26,46,0.96)", border: "1px solid rgba(148,163,184,0.18)", borderRadius: 10, fontSize: 12 }} labelFormatter={(v) => `t = ${v}s`} />
                  <Area type="monotone" dataKey="inbound" stroke="#22d3ee" strokeWidth={1.5} fill="url(#gIn)" />
                  <Area type="monotone" dataKey="outbound" stroke="#f43f5e" strokeWidth={1.5} fill="url(#gOut)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div className="mt-2 flex gap-3 text-xs text-muted-foreground">
              <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-primary" /> Inbound</span>
              <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-critical" /> Outbound</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tables */}
      <Tabs defaultValue="connections">
        <TabsList className="mb-4">
          <TabsTrigger value="connections">Connections</TabsTrigger>
          <TabsTrigger value="dns">DNS</TabsTrigger>
          <TabsTrigger value="http">HTTP / HTTPS</TabsTrigger>
        </TabsList>

        <TabsContent value="connections">
          <Card className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[820px] text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                    <th className="px-5 py-3 font-medium">Destination</th>
                    <th className="px-3 py-3 font-medium">Port</th>
                    <th className="px-3 py-3 font-medium">Location</th>
                    <th className="px-3 py-3 font-medium">ASN / Org</th>
                    <th className="px-3 py-3 font-medium">Data</th>
                    <th className="px-3 py-3 font-medium">Role</th>
                    <th className="px-5 py-3 text-right font-medium">Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {n.connections.map((c) => (
                    <tr key={c.destIp} className="border-b border-border/50 last:border-0 hover:bg-surface-overlay/30">
                      <td className="px-5 py-3 font-mono text-foreground">{c.destIp}</td>
                      <td className="px-3 py-3 font-mono text-muted-foreground">{c.destPort}</td>
                      <td className="px-3 py-3">
                        <span className="flex items-center gap-1.5 text-muted-foreground"><span className="font-mono text-[0.7rem]">{c.countryCode}</span>{c.city}, {c.country}</span>
                      </td>
                      <td className="px-3 py-3 text-muted-foreground"><span className="font-mono text-xs">{c.asn}</span> · {c.org}</td>
                      <td className="px-3 py-3 font-mono text-muted-foreground">{formatBytes(c.bytes)}</td>
                      <td className="px-3 py-3 text-xs text-muted-foreground">{c.role}</td>
                      <td className="px-5 py-3 text-right">{c.malicious ? <SeverityBadge severity="critical" label="malicious" /> : <SeverityBadge severity="clean" label="benign" />}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </TabsContent>

        <TabsContent value="dns">
          <Card className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px] text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                    <th className="px-5 py-3 font-medium">Domain</th>
                    <th className="px-3 py-3 font-medium">Type</th>
                    <th className="px-3 py-3 font-medium">Response</th>
                    <th className="px-3 py-3 font-medium">Category</th>
                    <th className="px-5 py-3 text-right font-medium">Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {n.dns.map((q) => (
                    <tr key={q.domain} className="border-b border-border/50 last:border-0 hover:bg-surface-overlay/30">
                      <td className={cn("px-5 py-3 font-mono", q.malicious ? "text-critical" : "text-foreground")}>{q.domain}</td>
                      <td className="px-3 py-3 font-mono text-muted-foreground">{q.type}</td>
                      <td className="px-3 py-3 font-mono text-muted-foreground">{q.response}</td>
                      <td className="px-3 py-3 text-xs text-muted-foreground">{q.category}</td>
                      <td className="px-5 py-3 text-right">{q.malicious ? <SeverityBadge severity="high" label="malicious" /> : <SeverityBadge severity="clean" label="benign" />}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </TabsContent>

        <TabsContent value="http">
          <Card className="overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
                    <th className="px-5 py-3 font-medium">Method</th>
                    <th className="px-3 py-3 font-medium">Host</th>
                    <th className="px-3 py-3 font-medium">URI</th>
                    <th className="px-3 py-3 font-medium">Status</th>
                    <th className="px-3 py-3 font-medium">Content-Type</th>
                    <th className="px-5 py-3 text-right font-medium">Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {n.http.map((h, i) => (
                    <tr key={i} className="border-b border-border/50 last:border-0 hover:bg-surface-overlay/30">
                      <td className="px-5 py-3"><span className="rounded bg-surface-overlay/70 px-1.5 py-0.5 font-mono text-[0.7rem] text-foreground">{h.method}</span></td>
                      <td className="px-3 py-3">
                        <span className="flex items-center gap-1.5">
                          <span className={cn("rounded px-1 py-0.5 font-mono text-[0.6rem] uppercase", h.scheme === "https" ? "bg-success/10 text-success" : "bg-medium/10 text-medium")}>{h.scheme}</span>
                          <span className={cn("font-mono", h.suspicious ? "text-critical" : "text-foreground")}>{h.host}</span>
                        </span>
                      </td>
                      <td className="px-3 py-3 max-w-[200px] truncate font-mono text-xs text-muted-foreground">{h.uri}</td>
                      <td className="px-3 py-3 font-mono text-success">{h.status}</td>
                      <td className="px-3 py-3 font-mono text-xs text-muted-foreground">{h.contentType}</td>
                      <td className="px-5 py-3 text-right">{h.suspicious ? <SeverityBadge severity="high" label="suspicious" /> : <SeverityBadge severity="clean" label="benign" />}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
