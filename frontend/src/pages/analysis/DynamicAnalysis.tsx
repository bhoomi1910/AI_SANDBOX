import { useState } from "react";
import { motion } from "framer-motion";
import {
  Activity,
  Monitor,
  Play,
  Cpu,
  HardDrive,
  KeyRound,
  Lock,
  Repeat,
  GitBranch,
  ChevronRight,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { SeverityBadge } from "@/components/ui/badge";
import { dynamicAnalysis as d } from "@/data/deepdive";
import { cn } from "@/lib/utils";

const catColor: Record<string, string> = {
  process: "#22d3ee",
  file: "#38bdf8",
  registry: "#facc15",
  network: "#f43f5e",
  persistence: "#fb923c",
  evasion: "#a78bfa",
};

export default function DynamicAnalysis() {
  const [selected, setSelected] = useState<number | null>(3);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-4">
      {/* VM + timeline */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Simulated VM */}
        <Card className="overflow-hidden">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Monitor className="size-4 text-primary" /> Sandbox VM</CardTitle>
            <span className="badge border-success/30 bg-success/10 text-success"><span className="size-1.5 animate-pulse rounded-full bg-success" /> Detonated</span>
          </CardHeader>
          <CardContent>
            {/* Fake VM screen */}
            <div className="relative aspect-video overflow-hidden rounded-lg border border-border bg-[#0a1020] scanlines">
              <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(34,211,238,0.06),transparent_70%)]" />
              {/* taskbar */}
              <div className="absolute inset-x-0 top-0 flex items-center gap-2 border-b border-white/5 bg-black/30 px-3 py-1.5">
                <div className="flex gap-1">
                  <span className="size-2 rounded-full bg-critical/70" />
                  <span className="size-2 rounded-full bg-medium/70" />
                  <span className="size-2 rounded-full bg-success/70" />
                </div>
                <span className="font-mono text-[0.65rem] text-white/50">{d.vmName} · {d.os}</span>
              </div>
              {/* desktop content */}
              <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 p-4 text-center">
                <motion.div animate={{ opacity: [0.4, 1, 0.4] }} transition={{ duration: 2, repeat: Infinity }} className="grid size-12 place-items-center rounded-lg bg-critical/20 ring-1 ring-critical/40">
                  <Play className="size-5 text-critical" />
                </motion.div>
                <div className="font-mono text-xs text-white/70">Invoice_scan_04829.exe running</div>
                <div className="font-mono text-[0.65rem] text-white/40">6 processes spawned · 3 injections detected</div>
              </div>
              {/* scan line */}
              <div className="pointer-events-none absolute inset-x-0 top-0 h-16 bg-gradient-to-b from-primary/10 to-transparent animate-scan" />
            </div>
            <div className="mt-3 grid grid-cols-3 gap-2 text-center">
              {[
                { k: `${d.detonationTime}s`, v: "Runtime" },
                { k: d.processes.length, v: "Processes" },
                { k: d.screenshotFrames, v: "Screenshots" },
              ].map((x) => (
                <div key={x.v} className="rounded-lg border border-border bg-surface/40 py-2">
                  <div className="font-mono text-sm font-bold text-foreground">{x.k}</div>
                  <div className="text-[0.65rem] text-muted-foreground">{x.v}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Behaviour timeline */}
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Activity className="size-4 text-primary" /> Behaviour Timeline</CardTitle>
            <span className="text-xs text-muted-foreground">{d.timeline.length} events · click to inspect</span>
          </CardHeader>
          <CardContent className="max-h-[420px] overflow-y-auto">
            <div className="relative pl-6">
              <div className="absolute left-[9px] top-1 bottom-1 w-px bg-border" />
              {d.timeline.map((ev, i) => (
                <button
                  key={i}
                  onClick={() => setSelected(selected === i ? null : i)}
                  className={cn(
                    "group relative mb-1 flex w-full items-start gap-3 rounded-lg py-2 pl-4 pr-2 text-left transition-colors cursor-pointer",
                    selected === i ? "bg-surface-overlay/50" : "hover:bg-surface-overlay/30"
                  )}
                >
                  <span className="absolute -left-[15px] top-3 grid size-3.5 place-items-center rounded-full ring-4 ring-canvas" style={{ background: catColor[ev.category] }} />
                  <span className="mt-0.5 w-10 shrink-0 font-mono text-[0.7rem] text-muted-foreground">+{ev.offset}s</span>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-foreground">{ev.action}</span>
                      <SeverityBadge severity={ev.severity} withDot={false} className="scale-90" />
                      {ev.mitre && <span className="rounded bg-accent/10 px-1.5 py-0.5 font-mono text-[0.6rem] text-accent">{ev.mitre}</span>}
                    </div>
                    <div className="mt-0.5 text-xs text-muted-foreground">{ev.detail}</div>
                  </div>
                  <span className="rounded px-1.5 py-0.5 text-[0.6rem] uppercase" style={{ background: `${catColor[ev.category]}1f`, color: catColor[ev.category] }}>{ev.category}</span>
                </button>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Detail tabs */}
      <Tabs defaultValue="processes">
        <TabsList className="mb-4 flex-wrap">
          <TabsTrigger value="processes"><Cpu className="mr-1.5 inline size-3.5" />Processes</TabsTrigger>
          <TabsTrigger value="registry"><KeyRound className="mr-1.5 inline size-3.5" />Registry</TabsTrigger>
          <TabsTrigger value="files"><HardDrive className="mr-1.5 inline size-3.5" />Filesystem</TabsTrigger>
          <TabsTrigger value="persistence"><Repeat className="mr-1.5 inline size-3.5" />Persistence</TabsTrigger>
          <TabsTrigger value="mutexes"><Lock className="mr-1.5 inline size-3.5" />Mutexes</TabsTrigger>
          <TabsTrigger value="api"><GitBranch className="mr-1.5 inline size-3.5" />API Calls</TabsTrigger>
        </TabsList>

        <TabsContent value="processes">
          <Card>
            <CardContent className="pt-5">
              <div className="space-y-1">
                {d.processes.map((p) => {
                  const depth = p.ppid === 3820 ? 0 : p.ppid === 4128 ? 1 : 2;
                  return (
                    <div key={p.pid} className="flex items-start gap-2 rounded-lg py-2 pr-2 transition-colors hover:bg-surface-overlay/40" style={{ paddingLeft: `${depth * 24 + 8}px` }}>
                      {depth > 0 && <ChevronRight className="mt-1 size-3.5 shrink-0 text-muted-foreground/50" />}
                      <div className={cn("mt-0.5 grid size-7 shrink-0 place-items-center rounded-md", p.suspicious ? "bg-critical/10 text-critical" : "bg-surface-overlay text-muted-foreground")}>
                        <Cpu className="size-3.5" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm text-foreground">{p.name}</span>
                          <span className="font-mono text-[0.65rem] text-muted-foreground">PID {p.pid}</span>
                          {p.suspicious && <SeverityBadge severity="high" label="suspicious" withDot={false} className="scale-90" />}
                        </div>
                        <div className="mt-0.5 break-all font-mono text-[0.7rem] text-muted-foreground">{p.commandLine}</div>
                      </div>
                      <span className="shrink-0 rounded bg-surface-overlay/70 px-1.5 py-0.5 text-[0.65rem] text-muted-foreground">{p.integrity}</span>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="registry">
          <BehaviourTable
            head={["Op", "Key", "Value / Data", "Persistence"]}
            rows={d.registry.map((r) => [
              <OpBadge op={r.operation} />,
              <span className="break-all font-mono text-xs text-foreground">{r.key}{r.value ? <span className="text-muted-foreground"> \ {r.value}</span> : ""}</span>,
              <span className="break-all font-mono text-xs text-muted-foreground">{r.data ?? "—"}</span>,
              r.persistence ? <SeverityBadge severity="high" label="yes" withDot={false} /> : <span className="text-xs text-muted-foreground">no</span>,
            ])}
          />
        </TabsContent>

        <TabsContent value="files">
          <BehaviourTable
            head={["Op", "Path", "Detail", "Flag"]}
            rows={d.files.map((f) => [
              <OpBadge op={f.operation} />,
              <span className="break-all font-mono text-xs text-foreground">{f.path}</span>,
              <span className="text-xs text-muted-foreground">{f.detail}</span>,
              f.suspicious ? <SeverityBadge severity="high" label="suspicious" withDot={false} /> : <SeverityBadge severity="clean" label="ok" withDot={false} />,
            ])}
          />
        </TabsContent>

        <TabsContent value="persistence">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {d.persistence.map((p) => (
              <Card key={p.technique}>
                <CardContent className="pt-5">
                  <div className="grid size-9 place-items-center rounded-lg bg-high/10 text-high"><Repeat className="size-4" /></div>
                  <div className="mt-3 text-sm font-semibold text-foreground">{p.technique}</div>
                  <div className="mt-1 break-all font-mono text-[0.7rem] text-muted-foreground">{p.location}</div>
                  <span className="mt-3 inline-block rounded bg-accent/10 px-1.5 py-0.5 font-mono text-[0.65rem] text-accent">{p.mitre}</span>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="mutexes">
          <Card>
            <CardContent className="space-y-2 pt-5">
              {d.mutexes.map((m) => (
                <div key={m} className="flex items-center gap-3 rounded-lg border border-border bg-surface/40 px-3 py-2.5">
                  <Lock className="size-4 text-medium" />
                  <span className="font-mono text-sm text-foreground">{m}</span>
                  <span className="ml-auto text-[0.7rem] text-muted-foreground">single-instance guard</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="api">
          <Card>
            <CardContent className="pt-5">
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {d.apiCalls.map((a) => (
                  <div key={a.api} className="flex items-center gap-3 rounded-lg border border-border bg-surface/40 px-3 py-2.5">
                    <div className={cn("grid size-8 place-items-center rounded-md", a.suspicious ? "bg-critical/10 text-critical" : "bg-surface-overlay text-muted-foreground")}>
                      <GitBranch className="size-3.5" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="font-mono text-sm text-foreground">{a.api}</div>
                      <div className="text-[0.7rem] text-muted-foreground">{a.category}</div>
                    </div>
                    <span className="font-mono text-sm font-bold text-foreground">×{a.count}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}

function BehaviourTable({ head, rows }: { head: string[]; rows: React.ReactNode[][] }) {
  return (
    <Card className="overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-sm">
          <thead>
            <tr className="border-b border-border text-left text-[0.7rem] uppercase tracking-wide text-muted-foreground">
              {head.map((h) => (
                <th key={h} className="px-5 py-3 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className="border-b border-border/50 last:border-0 hover:bg-surface-overlay/30">
                {r.map((c, j) => (
                  <td key={j} className="px-5 py-3 align-top">{c}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function OpBadge({ op }: { op: string }) {
  const colors: Record<string, string> = {
    create: "#34d399",
    modify: "#facc15",
    write: "#38bdf8",
    delete: "#f43f5e",
    rename: "#a78bfa",
    query: "#64748b",
    read: "#64748b",
  };
  return (
    <span className="rounded px-1.5 py-0.5 font-mono text-[0.65rem] uppercase" style={{ background: `${colors[op]}1f`, color: colors[op] }}>
      {op}
    </span>
  );
}
