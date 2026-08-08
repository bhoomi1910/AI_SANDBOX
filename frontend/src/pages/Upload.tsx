import { useCallback, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import {
  UploadCloud,
  FileCheck2,
  ShieldCheck,
  Loader2,
  CheckCircle2,
  XCircle,
  FileText,
  Boxes,
  Binary,
  ArrowRight,
  Cpu,
  Lock,
} from "lucide-react";
import { PageHeader } from "@/components/shared/PageHeader";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { cn, formatBytes } from "@/lib/utils";
import { api } from "@/lib/api";

const supported = [
  { ext: "EXE", desc: "Windows executable", icon: Binary },
  { ext: "DLL", desc: "Dynamic library", icon: Binary },
  { ext: "PDF", desc: "Document", icon: FileText },
  { ext: "DOCX", desc: "Office / maldoc", icon: FileText },
  { ext: "ZIP", desc: "Archive", icon: Boxes },
  { ext: "ISO", desc: "Disk image", icon: Boxes },
];

const pipeline = [
  "Uploading to secure enclave",
  "Computing hashes (SHA-256 / MD5 / SHA-1)",
  "Storing sample & creating investigation",
  "Queued for static analysis",
];

type Stage = "idle" | "uploading" | "queued" | "error";

export default function Upload() {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [stage, setStage] = useState<Stage>("idle");
  const [progress, setProgress] = useState(0);
  const [file, setFile] = useState<{ name: string; size: number; type: string } | null>(null);
  const [stepIndex, setStepIndex] = useState(0);
  const [caseId, setCaseId] = useState<string>("");
  const [error, setError] = useState<string>("");

  const start = useCallback(async (f: { name: string; size: number; type: string; raw?: File }) => {
    setFile(f);
    setStage("uploading");
    setProgress(0);
    setStepIndex(0);
    setError("");

    // Animate progress while the upload request is in flight; the endpoint
    // returns once the file is stored and the investigation is queued.
    let p = 0;
    const timer = setInterval(() => {
      p += Math.random() * 9 + 4;
      setProgress(Math.min(90, p));
      setStepIndex(Math.min(pipeline.length - 1, Math.floor((p / 100) * pipeline.length)));
    }, 180);

    try {
      if (!f.raw) throw new Error("No file selected");
      const result = await api.uploadSample(f.raw);
      clearInterval(timer);
      setProgress(100);
      setStepIndex(pipeline.length - 1);
      setCaseId(result.investigation.caseId);
      setTimeout(() => setStage("queued"), 400);
    } catch (err) {
      clearInterval(timer);
      setError(err instanceof Error ? err.message : "Upload failed");
      setStage("error");
    }
  }, []);

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const raw = e.dataTransfer.files?.[0];
    if (raw) start({ name: raw.name, size: raw.size, type: raw.name.split(".").pop()?.toUpperCase() ?? "BIN", raw });
  };

  const onPick = (e: React.ChangeEvent<HTMLInputElement>) => {
    const raw = e.target.files?.[0];
    if (raw) start({ name: raw.name, size: raw.size, type: raw.name.split(".").pop()?.toUpperCase() ?? "BIN", raw });
  };

  const reset = () => {
    setStage("idle");
    setFile(null);
    setProgress(0);
    setStepIndex(0);
    if (inputRef.current) inputRef.current.value = "";
  };

  return (
    <div>
      <PageHeader
        title="Submit Sample for Analysis"
        subtitle="Upload a suspicious file to generate a secure static-analysis investigation with an AI verdict"
        icon={UploadCloud}
      />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Dropzone / progress */}
        <Card className="lg:col-span-2">
          <CardContent className="pt-6">
            <AnimatePresence mode="wait">
              {stage === "idle" && (
                <motion.div key="drop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                  <div
                    onDragOver={(e) => {
                      e.preventDefault();
                      setDragging(true);
                    }}
                    onDragLeave={() => setDragging(false)}
                    onDrop={onDrop}
                    onClick={() => inputRef.current?.click()}
                    className={cn(
                      "relative grid cursor-pointer place-items-center rounded-xl border-2 border-dashed px-6 py-16 text-center transition-all",
                      dragging
                        ? "border-primary bg-primary/5 shadow-glow"
                        : "border-border hover:border-primary/40 hover:bg-surface-overlay/30"
                    )}
                  >
                    {dragging && <div className="pointer-events-none absolute inset-x-0 top-0 h-full overflow-hidden rounded-xl"><div className="h-1/3 w-full bg-gradient-to-b from-primary/20 to-transparent animate-scan" /></div>}
                    <input ref={inputRef} type="file" className="hidden" onChange={onPick} accept=".exe,.dll,.pdf,.docx,.zip,.iso" />
                    <motion.div
                      animate={{ y: dragging ? -6 : 0 }}
                      className="grid size-16 place-items-center rounded-2xl bg-gradient-to-br from-primary/20 to-accent/20 ring-1 ring-primary/30"
                    >
                      <UploadCloud className="size-8 text-primary" />
                    </motion.div>
                    <h3 className="mt-5 text-lg font-semibold text-foreground">
                      {dragging ? "Release to submit" : "Drag & drop a file here"}
                    </h3>
                    <p className="mt-1 text-sm text-muted-foreground">
                      or <span className="text-primary">browse your computer</span> · max 100 MB
                    </p>
                    <div className="mt-6 flex flex-wrap justify-center gap-1.5">
                      {supported.map((s) => (
                        <span key={s.ext} className="rounded-md border border-border bg-surface/60 px-2 py-1 font-mono text-[0.7rem] text-muted-foreground">
                          .{s.ext.toLowerCase()}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="mt-4 flex items-center gap-2 rounded-lg border border-border bg-surface/40 px-4 py-3">
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <Lock className="size-3.5 text-success" /> Samples are stored in a secure enclave and analysed with static tools — nothing is executed on your host.
                    </div>
                  </div>
                </motion.div>
              )}

              {stage === "uploading" && file && (
                <motion.div key="up" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="py-4">
                  <div className="flex items-center gap-3 rounded-lg border border-border bg-surface/50 p-4">
                    <div className="grid size-11 place-items-center rounded-lg bg-primary/10 text-primary ring-1 ring-primary/20">
                      <FileCheck2 className="size-5" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium text-foreground">{file.name}</div>
                      <div className="text-xs text-muted-foreground">{formatBytes(file.size)} · {file.type}</div>
                    </div>
                    <div className="font-mono text-sm font-semibold text-primary">{Math.round(progress)}%</div>
                  </div>
                  <Progress value={progress} className="mt-4" />
                  <div className="mt-6 space-y-2.5">
                    {pipeline.map((step, i) => {
                      const done = i < stepIndex;
                      const active = i === stepIndex;
                      return (
                        <div key={step} className="flex items-center gap-3 text-sm">
                          {done ? (
                            <CheckCircle2 className="size-4 text-success" />
                          ) : active ? (
                            <Loader2 className="size-4 animate-spin text-primary" />
                          ) : (
                            <div className="size-4 rounded-full border border-border" />
                          )}
                          <span className={cn(done ? "text-muted-foreground line-through" : active ? "text-foreground" : "text-muted-foreground/60")}>
                            {step}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </motion.div>
              )}

              {stage === "queued" && file && (
                <motion.div key="done" initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} className="py-8 text-center">
                  <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", damping: 12 }} className="mx-auto grid size-16 place-items-center rounded-2xl bg-success/10 ring-1 ring-success/30">
                    <CheckCircle2 className="size-8 text-success" />
                  </motion.div>
                  <h3 className="mt-5 text-lg font-semibold text-foreground">Sample submitted successfully</h3>
                  <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">
                    <span className="font-medium text-foreground">{file.name}</span> has been queued for static
                    analysis. A new investigation has been created.
                  </p>
                  <div className="mx-auto mt-5 inline-flex items-center gap-2 rounded-lg border border-border bg-surface/50 px-4 py-2 font-mono text-sm">
                    <span className="text-muted-foreground">Case ID</span>
                    <span className="font-semibold text-primary">{caseId}</span>
                  </div>
                  <div className="mt-6 flex justify-center gap-3">
                    <Button variant="outline" onClick={reset}>Submit another</Button>
                    <Button onClick={() => navigate("/queue")}>
                      Go to queue <ArrowRight className="size-4" />
                    </Button>
                  </div>
                </motion.div>
              )}

              {stage === "error" && file && (
                <motion.div key="err" initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} className="py-8 text-center">
                  <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", damping: 12 }} className="mx-auto grid size-16 place-items-center rounded-2xl bg-critical/10 ring-1 ring-critical/30">
                    <XCircle className="size-8 text-critical" />
                  </motion.div>
                  <h3 className="mt-5 text-lg font-semibold text-foreground">Upload failed</h3>
                  <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">{error}</p>
                  <div className="mt-6 flex justify-center gap-3">
                    <Button variant="outline" onClick={reset}>Try again</Button>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </CardContent>
        </Card>

        {/* Side panel */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><ShieldCheck className="size-4 text-primary" /> Supported Formats</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {supported.map((s) => (
                <div key={s.ext} className="flex items-center gap-3 rounded-lg px-2 py-2 transition-colors hover:bg-surface-overlay/40">
                  <div className="grid size-8 place-items-center rounded-lg bg-surface-overlay/60 ring-1 ring-border">
                    <s.icon className="size-4 text-muted-foreground" />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-foreground">.{s.ext.toLowerCase()}</div>
                    <div className="text-[0.7rem] text-muted-foreground">{s.desc}</div>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card className="relative overflow-hidden">
            <div className="pointer-events-none absolute -right-6 -top-6 size-32 rounded-full bg-accent/10 blur-3xl" />
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Cpu className="size-4 text-accent" /> What happens next</CardTitle>
            </CardHeader>
            <CardContent>
              <ol className="space-y-3">
                {["File hashes (SHA-256 / MD5 / SHA-1) are computed and the sample is stored securely", "Static analysis extracts strings, imports & YARA hits", "Threat intel enrichment + MITRE ATT&CK mapping", "AI produces a reasoned verdict and full report"].map((t, i) => (
                  <li key={i} className="flex gap-3 text-sm">
                    <span className="grid size-5 shrink-0 place-items-center rounded-full bg-primary/15 text-[0.7rem] font-bold text-primary">{i + 1}</span>
                    <span className="text-muted-foreground">{t}</span>
                  </li>
                ))}
              </ol>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
