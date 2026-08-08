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

// 30-day investigation vs detection trend
export const trendData = Array.from({ length: 30 }, (_, i) => {
  const base = 28 + Math.sin(i / 3) * 8 + i * 0.6;
  return {
    day: `Jul ${i + 1}`,
    investigations: Math.round(base + Math.random() * 6),
    malicious: Math.round(base * 0.42 + Math.random() * 5),
    clean: Math.round(base * 0.31 + Math.random() * 4),
  };
});

export const malwareFamilies: { name: string; value: number; color: string }[] = [
  { name: "Emotet", value: 284, color: "#f43f5e" },
  { name: "Qakbot", value: 212, color: "#fb923c" },
  { name: "LockBit", value: 176, color: "#facc15" },
  { name: "RedLine", value: 148, color: "#22d3ee" },
  { name: "Cobalt Strike", value: 121, color: "#6366f1" },
  { name: "AgentTesla", value: 98, color: "#34d399" },
  { name: "Other", value: 245, color: "#64748b" },
];

export const severityBreakdown: { name: string; value: number; color: string }[] = [
  { name: "Critical", value: 187, color: "#f43f5e" },
  { name: "High", value: 342, color: "#fb923c" },
  { name: "Medium", value: 468, color: "#facc15" },
  { name: "Low", value: 201, color: "#38bdf8" },
  { name: "Clean", value: 86, color: "#34d399" },
];

// Live threat intel feed
export const threatFeed: FeedItem[] = [
  { id: "f1", time: "2m ago", title: "New Emotet C2 cluster observed — 14 IPs added to blocklist", source: "AlienVault OTX", severity: "critical" },
  { id: "f2", time: "8m ago", title: "CVE-2026-21882 actively exploited in the wild (Win32k EoP)", source: "CISA KEV", severity: "high" },
  { id: "f3", time: "15m ago", title: "LockBit 3.0 affiliate targeting healthcare — new TTPs", source: "MITRE ATT&CK", severity: "critical" },
  { id: "f4", time: "24m ago", title: "Phishing kit 'EvilProxy' bypassing MFA — 2FA session theft", source: "VirusTotal", severity: "high" },
  { id: "f5", time: "38m ago", title: "RedLine Stealer distributed via cracked-software SEO poisoning", source: "AbuseIPDB", severity: "medium" },
  { id: "f6", time: "51m ago", title: "Qakbot resurfaces with OneNote delivery after takedown", source: "AlienVault OTX", severity: "high" },
  { id: "f7", time: "1h ago", title: "Cobalt Strike watermark 0x5f2a3b1c linked to APT29 infra", source: "Threat Intel", severity: "high" },
];

export const systemHealth = [
  { name: "Sandbox Cluster", detail: "8 / 12 VMs active", status: "operational" as const, load: 67 },
  { name: "Analysis Engine", detail: "Static + Dynamic workers", status: "operational" as const, load: 54 },
  { name: "AI Inference (LLM)", detail: "RAG + FAISS index warm", status: "operational" as const, load: 71 },
  { name: "Threat Intel Feeds", detail: "5 / 5 sources syncing", status: "operational" as const, load: 33 },
  { name: "PCAP Processor", detail: "Zeek + Suricata pipeline", status: "degraded" as const, load: 88 },
  { name: "Report Generator", detail: "PDF export service", status: "operational" as const, load: 21 },
];

export const topAnalysts = [
  { name: "J. Okafor", cases: 47, avatar: "JO", accuracy: 98.2 },
  { name: "S. Nakamura", cases: 41, avatar: "SN", accuracy: 97.6 },
  { name: "A. Petrov", cases: 38, avatar: "AP", accuracy: 96.9 },
  { name: "M. Silva", cases: 29, avatar: "MS", accuracy: 95.4 },
];
