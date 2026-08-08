import {
  LayoutDashboard,
  UploadCloud,
  ListChecks,
  FileSearch,
  Activity,
  Network,
  Radar,
  Crosshair,
  Sparkles,
  FileText,
  type LucideIcon,
} from "lucide-react";

export interface NavItem {
  label: string;
  to: string;
  icon: LucideIcon;
  group: "Operations" | "Analysis" | "Intelligence";
  badge?: string;
  hero?: boolean;
}

/** Primary navigation — mirrors the SOC analyst workflow order. */
export const navItems: NavItem[] = [
  { label: "Dashboard", to: "/dashboard", icon: LayoutDashboard, group: "Operations" },
  { label: "Upload Sample", to: "/upload", icon: UploadCloud, group: "Operations" },
  { label: "Investigation Queue", to: "/queue", icon: ListChecks, group: "Operations", badge: "7" },
  { label: "Static Analysis", to: "/investigation/inv-0412/static", icon: FileSearch, group: "Analysis" },
  { label: "Dynamic Analysis", to: "/investigation/inv-0412/dynamic", icon: Activity, group: "Analysis" },
  { label: "Network Analysis", to: "/investigation/inv-0412/network", icon: Network, group: "Analysis" },
  { label: "Threat Intelligence", to: "/investigation/inv-0412/intel", icon: Radar, group: "Intelligence" },
  { label: "MITRE ATT&CK", to: "/investigation/inv-0412/mitre", icon: Crosshair, group: "Intelligence" },
  { label: "AI Investigation", to: "/investigation/inv-0412/ai", icon: Sparkles, group: "Intelligence", hero: true },
  { label: "Investigation Report", to: "/investigation/inv-0412/report", icon: FileText, group: "Intelligence" },
];

export const navGroups = ["Operations", "Analysis", "Intelligence"] as const;
