import { useNavigate } from "react-router-dom";
import { Search, Bell, Menu, Command, ShieldAlert, LogOut } from "lucide-react";
import { Input } from "@/components/ui/misc";
import { Button } from "@/components/ui/button";
import { useState } from "react";

export function Topbar({ onMenu, onLogout }: { onMenu: () => void; onLogout: () => void }) {
  const navigate = useNavigate();
  const [q, setQ] = useState("");

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-border bg-canvas/70 px-4 backdrop-blur-xl lg:px-6">
      <Button variant="ghost" size="icon" className="lg:hidden" onClick={onMenu} aria-label="Open menu">
        <Menu className="size-5" />
      </Button>

      {/* Global search */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (q.trim()) navigate("/queue");
        }}
        className="relative hidden max-w-md flex-1 sm:block"
      >
        <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search hash, IP, domain, case ID…"
          className="h-9 pl-9 pr-16"
          aria-label="Global search"
        />
        <kbd className="pointer-events-none absolute right-2.5 top-1/2 hidden -translate-y-1/2 items-center gap-0.5 rounded border border-border bg-surface px-1.5 py-0.5 text-[0.65rem] text-muted-foreground md:inline-flex">
          <Command className="size-3" />K
        </kbd>
      </form>

      <div className="flex-1 sm:hidden" />

      {/* Right cluster */}
      <div className="flex items-center gap-1.5">
        <div className="hidden items-center gap-2 rounded-lg border border-critical/25 bg-critical/10 px-3 py-1.5 md:flex">
          <ShieldAlert className="size-4 text-critical" />
          <span className="text-xs font-medium text-critical">Threat level: Elevated</span>
        </div>

        <Button variant="ghost" size="icon" className="relative" aria-label="Notifications">
          <Bell className="size-5" />
          <span className="absolute right-1.5 top-1.5 size-2 rounded-full bg-critical ring-2 ring-canvas" />
        </Button>

        <div className="mx-1 h-6 w-px bg-border" />

        <button className="flex items-center gap-2.5 rounded-lg px-1.5 py-1 transition-colors hover:bg-surface-overlay/60 cursor-pointer">
          <div className="grid size-8 place-items-center rounded-full bg-gradient-to-br from-primary/30 to-accent/30 text-xs font-bold text-primary ring-1 ring-primary/30">
            JO
          </div>
          <div className="hidden text-left leading-tight lg:block">
            <div className="text-xs font-medium text-foreground">J. Okafor</div>
            <div className="text-[0.65rem] text-muted-foreground">SOC Analyst · Tier 2</div>
          </div>
        </button>

        <Button variant="ghost" size="icon" onClick={onLogout} aria-label="Sign out" title="Sign out">
          <LogOut className="size-[18px]" />
        </Button>
      </div>
    </header>
  );
}
