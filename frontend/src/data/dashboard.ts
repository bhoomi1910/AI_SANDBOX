import type { Severity } from "./types";

export interface FeedItem {
  id: string;
  time: string;
  title: string;
  source: string;
  severity: Severity;
}

export const dashboardStats = {
  totalInvestigations: { value: 1284, delta: +12.4, spark: [8, 12, 9, 14, 11, 18, 22, 19, 24, 28] },
  activeDetonations: { value: 7, delta: +2, spark: [3, 4, 2, 5, 6, 4, 5, 7, 6, 7] },
  criticalAlerts: { value: 23, delta: +5, spark: [10, 12, 14, 11, 16, 18, 15, 20, 21, 23] },
  meanTimeToVerdict: { value: 6.4, unit: "min", delta: -18.2, spark: [12, 11, 10, 9, 8.5, 8, 7.2, 7, 6.8, 6.4] },
};

// 30-day investigation trend (used as fallback when backend unavailable)
export const trendData = Array.from({ length: 30 }, (_, i) => {
  const base = 28 + Math.sin(i / 3) * 8 + i * 0.6;
  return {
    day: `Jul ${i + 1}`,
    investigations: Math.round(base + Math.random() * 6),
    malicious: Math.round(base * 0.42 + Math.random() * 5),
    clean: Math.round(base * 0.31 + Math.random() * 4),
  };
});

export const severityBreakdown: { name: string; value: number; color: string }[] = [
  { name: "Critical", value: 187, color: "#f43f5e" },
  { name: "High", value: 342, color: "#fb923c" },
  { name: "Medium", value: 468, color: "#facc15" },
  { name: "Low", value: 201, color: "#38bdf8" },
  { name: "Clean", value: 86, color: "#34d399" },
];

export const verdictDistribution: { name: string; value: number; color: string }[] = [
  { name: "Malicious", value: 529, color: "#f43f5e" },
  { name: "Suspicious", value: 669, color: "#facc15" },
  { name: "Clean", value: 86, color: "#34d399" },
];

export const fileTypeDistribution: { name: string; value: number; color: string }[] = [
  { name: "exe", value: 412, color: "#f43f5e" },
  { name: "pdf", value: 287, color: "#facc15" },
  { name: "docx", value: 234, color: "#22d3ee" },
  { name: "dll", value: 156, color: "#fb923c" },
  { name: "zip", value: 98, color: "#34d399" },
  { name: "iso", value: 52, color: "#a78bfa" },
  { name: "script", value: 45, color: "#6366f1" },
];

export const iocStatistics = {
  total: 3842,
  by_type: [
    { type: "url", count: 1245 },
    { type: "ip", count: 876 },
    { type: "domain", count: 654 },
    { type: "hash", count: 432 },
    { type: "email", count: 287 },
    { type: "registry", count: 198 },
    { type: "command", count: 98 },
    { type: "windows_path", count: 52 },
  ],
};

export const yaraStatistics = {
  total_matches: 847,
  investigations_with_matches: 423,
  top_rules: [
    { rule: "Emotet_Loader", count: 124 },
    { rule: "Packed_PE", count: 98 },
    { rule: "Cobalt_Strike_Beacon", count: 67 },
    { rule: "PDF_Phishing", count: 54 },
    { rule: "VBA_Downloader", count: 43 },
    { rule: "Ransomware_Indicators", count: 38 },
    { rule: "PowerShell_Obfuscation", count: 32 },
  ],
};

export const mitreStatistics = {
  total_techniques: 2156,
  unique_techniques: 18,
  investigations_with_mitre: 654,
  top_techniques: [
    { technique: "T1566", count: 234 },
    { technique: "T1055", count: 187 },
    { technique: "T1059", count: 156 },
    { technique: "T1071", count: 134 },
    { technique: "T1547", count: 98 },
    { technique: "T1204", count: 87 },
    { technique: "T1105", count: 76 },
    { technique: "T1486", count: 54 },
  ],
  top_tactics: [
    { tactic: "Execution", count: 456 },
    { tactic: "Defense Evasion", count: 345 },
    { tactic: "Command and Control", count: 287 },
    { tactic: "Initial Access", count: 234 },
    { tactic: "Persistence", count: 198 },
    { tactic: "Collection", count: 123 },
  ],
};

export const systemHealth = [
  { name: "Analysis API", detail: "FastAPI + SQLite", status: "operational" as const, load: 23 },
  { name: "Static Analysis", detail: "PE/PDF/Office/Script + YARA-lite", status: "operational" as const, load: 34 },
  { name: "AI Inference (LLM)", detail: "Ollama local", status: "degraded" as const, load: 0 },
  { name: "Threat Intel Feeds", detail: "Module not yet implemented", status: "degraded" as const, load: 0 },
];

export const topAnalysts = [
  { name: "J. Okafor", cases: 47, avatar: "JO", accuracy: 98.2 },
  { name: "S. Nakamura", cases: 41, avatar: "SN", accuracy: 97.6 },
  { name: "A. Petrov", cases: 38, avatar: "AP", accuracy: 96.9 },
  { name: "M. Silva", cases: 29, avatar: "MS", accuracy: 95.4 },
];
