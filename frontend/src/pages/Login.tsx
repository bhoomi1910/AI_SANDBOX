import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldCheck, Lock, User, Loader2, ArrowRight, Activity } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/misc";

export default function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("j.okafor@aegis-soc.io");
  const [password, setPassword] = useState("••••••••••");
  const [loading, setLoading] = useState(false);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setTimeout(() => {
      sessionStorage.setItem("aegis-auth", "true");
      navigate("/dashboard");
    }, 1100);
  };

  return (
    <div className="relative grid min-h-screen lg:grid-cols-2">
      {/* Left — brand / value panel */}
      <div className="relative hidden flex-col justify-between overflow-hidden border-r border-border bg-surface/40 p-12 lg:flex">
        <div className="absolute inset-0 -z-10 opacity-70 scanlines" />
        <div className="flex items-center gap-3">
          <div className="grid size-11 place-items-center rounded-xl bg-gradient-to-br from-primary/25 to-accent/25 ring-1 ring-primary/40">
            <ShieldCheck className="size-6 text-primary" />
          </div>
          <div>
            <div className="text-lg font-bold tracking-tight">
              Aegis <span className="text-gradient">Sandbox AI</span>
            </div>
            <div className="text-xs uppercase tracking-[0.16em] text-muted-foreground">
              Threat Investigation Platform
            </div>
          </div>
        </div>

        <div className="max-w-md">
          <motion.h1
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-4xl font-bold leading-tight tracking-tight"
          >
            Detonate. Analyse.
            <br />
            <span className="text-gradient">Understand every threat.</span>
          </motion.h1>
          <motion.p
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="mt-4 text-sm leading-relaxed text-muted-foreground"
          >
            AI-powered interactive malware analysis — from static triage and sandbox detonation to
            threat-intel enrichment, MITRE ATT&CK mapping, and a fully reasoned investigation report.
          </motion.p>

          <div className="mt-8 grid grid-cols-3 gap-3">
            {[
              { k: "1.2k+", v: "Samples analysed" },
              { k: "6.4 min", v: "Mean time to verdict" },
              { k: "96%", v: "AI verdict accuracy" },
            ].map((s, i) => (
              <motion.div
                key={s.v}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.15 + i * 0.08 }}
                className="rounded-lg border border-border bg-surface/60 p-3"
              >
                <div className="font-mono text-lg font-bold text-primary">{s.k}</div>
                <div className="text-[0.7rem] text-muted-foreground">{s.v}</div>
              </motion.div>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Activity className="size-3.5 text-success" />
          All analysis runs in isolated sandbox VMs · No sample leaves the enclave
        </div>
      </div>

      {/* Right — sign-in */}
      <div className="flex items-center justify-center p-6">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="w-full max-w-sm"
        >
          <div className="mb-8 lg:hidden">
            <div className="flex items-center gap-3">
              <div className="grid size-10 place-items-center rounded-xl bg-primary/15 ring-1 ring-primary/40">
                <ShieldCheck className="size-5 text-primary" />
              </div>
              <div className="text-lg font-bold">
                Aegis <span className="text-gradient">Sandbox AI</span>
              </div>
            </div>
          </div>

          <h2 className="text-2xl font-bold tracking-tight">Sign in to the console</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Enter your analyst credentials to access the SOC workspace.
          </p>

          <form onSubmit={submit} className="mt-8 space-y-4">
            <div>
              <label htmlFor="email" className="mb-1.5 block text-xs font-medium text-muted-foreground">
                Work email
              </label>
              <div className="relative">
                <User className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input id="email" value={email} onChange={(e) => setEmail(e.target.value)} className="pl-9" autoComplete="username" />
              </div>
            </div>
            <div>
              <label htmlFor="password" className="mb-1.5 block text-xs font-medium text-muted-foreground">
                Password
              </label>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="pl-9" autoComplete="current-password" />
              </div>
            </div>

            <div className="flex items-center justify-between text-xs">
              <label className="flex items-center gap-2 text-muted-foreground cursor-pointer">
                <input type="checkbox" defaultChecked className="size-3.5 accent-primary" />
                Keep me signed in
              </label>
              <a className="text-primary hover:underline cursor-pointer">Forgot password?</a>
            </div>

            <Button type="submit" size="lg" className="w-full" disabled={loading}>
              {loading ? (
                <>
                  <Loader2 className="size-4 animate-spin" /> Authenticating…
                </>
              ) : (
                <>
                  Access console <ArrowRight className="size-4" />
                </>
              )}
            </Button>
          </form>

          <div className="mt-6 rounded-lg border border-border bg-surface/40 p-3 text-center text-xs text-muted-foreground">
            Demo prototype — credentials are pre-filled. Just click{" "}
            <span className="font-medium text-foreground">Access console</span>.
          </div>

          <p className="mt-6 text-center text-[0.7rem] text-muted-foreground">
            Protected by SSO · SAML 2.0 · MFA enforced — MSc demonstration prototype
          </p>
        </motion.div>
      </div>
    </div>
  );
}
