import type { Severity } from "@/components/ui/badge";

export type { Severity };

export type InvestigationStatus =
  | "queued"
  | "running"
  | "analysing"
  | "ai-processing"
  | "completed"
  | "failed"
  | "closed";

export type FileType = "exe" | "dll" | "pdf" | "docx" | "zip" | "iso";

export interface Sample {
  id: string;
  filename: string;
  fileType: FileType;
  size: number;
  sha256: string;
  md5: string;
  sha1: string;
  submittedAt: string;
  submittedBy: string;
}

export interface Investigation {
  id: string;
  caseId: string; // e.g. AGS-2026-0412
  sample: Sample;
  status: InvestigationStatus;
  progress: number; // 0-100
  severity: Severity;
  riskScore: number; // 0-100
  malwareFamily: string;
  classification: string;
  verdict: "malicious" | "suspicious" | "clean";
  aiConfidence: number;
  detections: number; // AV vendor hits
  totalEngines: number;
  createdAt: string;
  completedAt?: string;
  closedAt?: string;
  closedBy?: string;
  resolution?: "true-positive" | "false-positive" | "escalated";
  closureNotes?: string;
  assignedTo: string;
  tags: string[];
  mitreTechniques: string[]; // technique IDs
  currentStage?: string;
}

export interface StaticAnalysis {
  entropy: number;
  compiler: string;
  packer: string | null;
  arch: string;
  subsystem: string;
  timestamp: string;
  imphash: string;
  signatureStatus: "valid" | "invalid" | "unsigned" | "revoked";
  sections: PeSection[];
  imports: ImportGroup[];
  strings: ExtractedString[];
  yara: YaraMatch[];
  capabilities: string[];
}

export interface PeSection {
  name: string;
  virtualSize: number;
  rawSize: number;
  entropy: number;
  flags: string;
  suspicious: boolean;
}

export interface ImportGroup {
  dll: string;
  functions: string[];
  suspicious: string[];
}

export interface ExtractedString {
  value: string;
  type: "url" | "ip" | "registry" | "path" | "command" | "mutex" | "api" | "generic";
  offset: string;
  interesting: boolean;
}

export interface YaraMatch {
  rule: string;
  description: string;
  severity: Severity;
  tags: string[];
  author: string;
}

export interface ProcessEvent {
  pid: number;
  ppid: number;
  name: string;
  commandLine: string;
  integrity: string;
  suspicious: boolean;
  startOffset: number; // seconds into detonation
}

export interface TimelineEvent {
  offset: number; // seconds
  category: "process" | "file" | "registry" | "network" | "persistence" | "evasion";
  action: string;
  detail: string;
  severity: Severity;
  mitre?: string;
}

export interface RegistryEvent {
  operation: "create" | "modify" | "delete" | "query";
  key: string;
  value?: string;
  data?: string;
  persistence: boolean;
}

export interface FileEvent {
  operation: "create" | "write" | "delete" | "rename" | "read";
  path: string;
  detail: string;
  suspicious: boolean;
}

export interface ApiCall {
  category: string;
  api: string;
  count: number;
  suspicious: boolean;
}

export interface DynamicAnalysis {
  vmName: string;
  os: string;
  detonationTime: number; // seconds
  screenshotFrames: number;
  processes: ProcessEvent[];
  timeline: TimelineEvent[];
  registry: RegistryEvent[];
  files: FileEvent[];
  mutexes: string[];
  persistence: { technique: string; location: string; mitre: string }[];
  apiCalls: ApiCall[];
}

export interface DnsQuery {
  domain: string;
  type: string;
  response: string;
  malicious: boolean;
  category: string;
}

export interface HttpRequest {
  method: string;
  host: string;
  uri: string;
  status: number;
  scheme: "http" | "https";
  contentType: string;
  suspicious: boolean;
}

export interface NetworkConnection {
  protocol: string;
  destIp: string;
  destPort: number;
  country: string;
  countryCode: string;
  city: string;
  lat: number;
  lon: number;
  asn: string;
  org: string;
  bytes: number;
  malicious: boolean;
  role: string; // e.g. "C2 Server", "Payload host"
}

export interface NetworkAnalysis {
  dns: DnsQuery[];
  http: HttpRequest[];
  connections: NetworkConnection[];
  packetTimeline: { t: number; inbound: number; outbound: number }[];
  totalPackets: number;
  totalBytes: number;
}

export interface ThreatIntelSource {
  source: string;
  verdict: string;
  score: number;
  detail: string;
  link: string;
  lastSeen: string;
  tone: "danger" | "warn" | "neutral" | "success";
}

export interface IoC {
  type: "hash" | "domain" | "ip" | "url" | "mutex" | "registry" | "filename";
  value: string;
  context: string;
  severity: Severity;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  severity: Severity;
  evidence: string;
}

export interface AiInvestigation {
  summary: string;
  whatItDoes: string[];
  whyDangerous: string[];
  attackChain: { stage: string; technique: string; detail: string; mitre: string }[];
  businessImpact: string[];
  family: string;
  familyConfidence: number;
  severity: Severity;
  confidence: number;
  recommendations: { priority: "immediate" | "high" | "medium"; action: string }[];
  reasoning: string[];
}
