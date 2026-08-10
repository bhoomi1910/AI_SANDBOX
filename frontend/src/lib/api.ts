import type { Investigation } from "@/data/types";

const API_URL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8000/api";

/** Set VITE_USE_BACKEND=false to force the demo (mock) dataset. */
export const USE_BACKEND = (import.meta.env.VITE_USE_BACKEND ?? "true") !== "false";

export interface DashboardStats {
  totalInvestigations: { value: number; delta: number | null; spark: number[] };
  activeAnalyses: { value: number; delta: number | null; spark: number[] };
  criticalAlerts: { value: number; delta: number | null; spark: number[] };
  completedAnalyses: { value: number; delta: number | null; spark: number[] };
  statusDistribution: Record<string, number>;
  severityBreakdown: { name: string; value: number; color: string }[];
  recentInvestigations: Investigation[];
  malwareFamilies: { name: string; value: number; color: string }[];
  threatFeed: { id: string; time: string; title: string; source: string; severity: string }[];
  systemHealth: { name: string; detail: string; status: "operational" | "degraded"; load: number }[];
  topAnalysts: { name: string; cases: number; avatar: string; accuracy: number }[];
  note: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, init);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body?.detail ?? detail;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail || `Request failed (${res.status})`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string }>("/health"),

  dashboardStats: () => request<DashboardStats>("/dashboard/stats"),

  listInvestigations: (status?: string) =>
    request<Investigation[]>(
      `/investigations${status && status !== "all" ? `?status=${status}` : ""}`
    ),

  getInvestigation: (id: string) => request<Investigation>(`/investigations/${id}`),

  getStaticAnalysis: (id: string) =>
    request<{ status: string; result?: Record<string, unknown> }>(
      `/investigations/${id}/static`
    ),

  getFindings: (id: string) =>
    request<{ status: string; findings?: unknown[] }>(`/investigations/${id}/findings`),

  getIocs: (id: string) =>
    request<{ status: string; iocs?: unknown[] }>(`/investigations/${id}/iocs`),

  getMitre: (id: string) =>
    request<{ status: string; techniques?: unknown[] }>(`/investigations/${id}/mitre`),

  getGraph: (id: string) =>
    request<{ status: string; graph?: { nodes: unknown[]; edges: unknown[] } }>(
      `/investigations/${id}/graph`
    ),

  getAiAnalysis: (id: string) =>
    request<Record<string, unknown>>(`/investigations/${id}/ai`),

  /** Download the server-generated PDF report for an investigation. */
  getReportPdf: async (id: string) => {
    const res = await fetch(`${API_URL}/investigations/${id}/report/pdf`);
    if (!res.ok) {
      let detail = res.statusText;
      try {
        const body = await res.json();
        detail = body?.detail ?? detail;
      } catch {
        /* non-JSON error body */
      }
      throw new Error(detail || `Report generation failed (${res.status})`);
    }
    return res.blob();
  },

  uploadSample: async (file: File) => {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch(`${API_URL}/samples/upload`, { method: "POST", body: form });
    let body: { message?: string; investigation?: Investigation; detail?: string } | null = null;
    try {
      body = await res.json();
    } catch {
      /* non-JSON body */
    }
    if (!res.ok || !body?.investigation) {
      throw new Error(body?.detail ?? `Upload failed (${res.status})`);
    }
    return body as { message: string; investigation: Investigation };
  },
};

/** Is the backend reachable? Used to decide live vs demo data. */
export async function probeBackend(): Promise<boolean> {
  if (!USE_BACKEND) return false;
  try {
    await api.health();
    return true;
  } catch {
    return false;
  }
}
