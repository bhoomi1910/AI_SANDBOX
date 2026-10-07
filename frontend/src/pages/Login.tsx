import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Activity,
  ArrowRight,
  Cloud,
  Eye,
  Globe2,
  Info,
  Loader2,
  Lock,
  Monitor,
  User,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/misc";

export default function Login() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"online" | "offline">("online");
  const [email, setEmail] = useState("j.okafor@aegis-soc.io");
  const [password, setPassword] = useState("demo123");
  const [loading, setLoading] = useState(false);

  const accessConsole = () => {
    setLoading(true);
    setTimeout(() => {
      sessionStorage.setItem("aegis-auth", "true");
      navigate("/dashboard", { replace: true });
    }, 700);
  };

  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    accessConsole();
  };

  return (
    <main className="login-shell min-h-screen overflow-hidden text-foreground">
      <div className="mx-auto grid min-h-screen max-w-[1500px] grid-cols-1 lg:grid-cols-[1.05fr_0.95fr]">
        <section className="relative flex min-h-[560px] flex-col justify-between overflow-hidden border-b border-border/70 px-6 py-8 sm:px-10 lg:min-h-screen lg:border-b-0 lg:border-r-0 lg:px-12 lg:py-10">
          <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(rgba(56,189,248,0.025)_1px,transparent_1px),linear-gradient(90deg,rgba(56,189,248,0.025)_1px,transparent_1px)] bg-[44px_44px]" />
          <div className="pointer-events-none absolute -right-32 top-1/2 size-[31rem] -translate-y-1/2 sm:size-[40rem]">
            <div className="login-world absolute inset-[15%]" />
            <div className="login-orbit absolute inset-0" />
            <div className="login-orbit absolute inset-[8%] rotate-45 opacity-60" />
          </div>
          <div className="relative z-10 flex items-center gap-3">
            <img src="/aegis.svg" alt="" className="size-11" />
            <div className="leading-tight"><div className="text-lg font-bold tracking-tight">Aegis <span className="text-gradient">Sandbox AI</span></div><div className="mt-1 text-[0.65rem] uppercase tracking-[0.2em] text-muted-foreground">Threat investigation platform</div></div>
          </div>
          <div className="relative z-10 max-w-xl py-12 lg:py-0">
            <motion.p initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="mb-4 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-primary"><span className="size-1.5 rounded-full bg-primary shadow-[0_0_12px_2px_rgba(34,211,238,0.8)]" /> Threat intelligence platform</motion.p>
            <motion.h1 initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} className="max-w-lg text-4xl font-bold leading-[1.08] tracking-tight sm:text-5xl">Detonate. Analyse.<br /><span className="text-gradient">Understand every threat.</span></motion.h1>
            <motion.p initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="mt-5 max-w-md text-sm leading-6 text-muted-foreground">AI-powered interactive malware analysis from static triage and sandbox detonation to threat-intel enrichment, MITRE ATT&CK mapping, and a fully reasoned investigation report.</motion.p>
            <div className="mt-8 grid max-w-md grid-cols-1 gap-2.5 sm:grid-cols-3">
              {[{ value: "1.2K+", label: "Samples analysed" }, { value: "6.4 min", label: "Mean time to verdict" }, { value: "96%", label: "AI verdict accuracy" }].map((stat, index) => <motion.div key={stat.label} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.16 + index * 0.08 }} className="rounded-lg border border-primary/15 bg-surface/65 p-3 backdrop-blur-sm"><div className="font-mono text-lg font-bold text-primary">{stat.value}</div><div className="mt-1 text-[0.68rem] text-muted-foreground">{stat.label}</div></motion.div>)}
            </div>
          </div>
          <div className="relative z-10 flex items-center gap-2 text-xs text-muted-foreground"><Activity className="size-3.5 text-success" /> All analysis runs in isolated sandbox VMs - no sample leaves the enclave</div>
        </section>

        <section className="flex items-center justify-center px-4 py-10 sm:px-8 lg:min-h-screen lg:px-12 lg:py-12">
          <motion.div initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} className="w-full max-w-[430px] rounded-xl border border-border bg-surface/75 p-5 shadow-card backdrop-blur-xl sm:p-8">
            <div className="mb-6"><h2 className="text-2xl font-bold tracking-tight">Sign in to the console</h2><p className="mt-1 text-sm text-muted-foreground">Choose how you want to access the SOC workspace.</p></div>
            <div className="grid grid-cols-2 rounded-lg border border-border bg-canvas/50 p-1">
              <button type="button" onClick={() => setMode("online")} className={`flex h-10 items-center justify-center gap-2 rounded-md text-sm font-semibold transition-colors ${mode === "online" ? "border border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground"}`}><Cloud className="size-4" /> Online</button>
              <button type="button" onClick={() => setMode("offline")} className={`flex h-10 items-center justify-center gap-2 rounded-md text-sm font-semibold transition-colors ${mode === "offline" ? "border border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground"}`}><Monitor className="size-4" /> Offline Demo</button>
            </div>
            {mode === "online" ? (
              <div className="mt-5 rounded-lg border border-primary/25 bg-primary/5 p-4"><div className="flex items-center gap-2 text-sm font-semibold text-primary"><Cloud className="size-4" /> Sign in with Google</div><p className="mt-2 text-xs leading-5 text-muted-foreground">Use your organization's Google account to access the cloud-based SOC workspace.</p><Button type="button" onClick={accessConsole} className="mt-4 h-11 w-full justify-between bg-white px-4 text-slate-900 hover:bg-slate-100"><span className="flex items-center gap-3"><span className="text-lg font-bold text-[#4285f4]">G</span> Continue with Google</span><ArrowRight className="size-4" /></Button><p className="mt-3 text-center text-[0.68rem] text-muted-foreground">Demo prototype: Google access is simulated locally.</p></div>
            ) : (
              <form onSubmit={submit} className="mt-5 rounded-lg border border-success/25 bg-success/5 p-4"><div className="flex items-center gap-2 text-sm font-semibold text-success"><Monitor className="size-4" /> Offline Demo Login</div><p className="mt-2 text-xs leading-5 text-muted-foreground">Use demo credentials to explore the platform without an internet connection.</p><div className="relative mt-4"><User className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" /><Input id="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="Enter username" className="h-11 pl-9" autoComplete="username" /></div><div className="relative mt-2"><Lock className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" /><Input id="password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Enter password" className="h-11 pl-9" autoComplete="current-password" /></div><Button type="submit" size="lg" className="mt-4 w-full justify-between" disabled={loading}>{loading ? <><Loader2 className="size-4 animate-spin" /> Authenticating...</> : <>Access Offline Console <ArrowRight className="size-4" /></>}</Button><div className="mt-4 flex gap-2 rounded-md border border-border bg-canvas/40 p-3 text-xs text-muted-foreground"><Info className="mt-0.5 size-4 shrink-0 text-primary" /><span>Demo credentials<br /><strong className="font-medium text-foreground">Username:</strong> analyst<br /><strong className="font-medium text-foreground">Password:</strong> demo123</span></div></form>
            )}
            <div className="mt-5 flex items-center justify-center gap-4 text-[0.68rem] text-muted-foreground"><span className="flex items-center gap-1"><Globe2 className="size-3.5 text-primary" /> Protected workspace</span><span className="flex items-center gap-1"><Eye className="size-3.5 text-primary" /> Static analysis only</span></div>
          </motion.div>
        </section>
      </div>
    </main>
  );
}
