import { NavLink } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldCheck, ChevronRight, Circle } from "lucide-react";
import { navItems, navGroups } from "@/lib/nav";
import { cn } from "@/lib/utils";

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <aside className="flex h-full w-[264px] flex-col border-r border-border bg-surface/60 backdrop-blur-xl">
      {/* Brand */}
      <div className="flex h-16 items-center gap-3 border-b border-border px-5">
        <div className="relative grid size-9 place-items-center rounded-lg bg-gradient-to-br from-primary/25 to-accent/25 ring-1 ring-primary/40">
          <ShieldCheck className="size-5 text-primary" />
          <span className="absolute -right-0.5 -top-0.5 size-2 animate-pulse rounded-full bg-success ring-2 ring-surface" />
        </div>
        <div className="leading-tight">
          <div className="text-sm font-bold tracking-tight text-foreground">
            Aegis <span className="text-gradient">Sandbox AI</span>
          </div>
          <div className="text-[0.65rem] uppercase tracking-[0.16em] text-muted-foreground">
            Threat Investigation
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-6 overflow-y-auto px-3 py-5">
        {navGroups.map((group) => (
          <div key={group}>
            <div className="mb-2 px-3 text-[0.65rem] font-semibold uppercase tracking-[0.16em] text-muted-foreground/70">
              {group}
            </div>
            <div className="space-y-0.5">
              {navItems
                .filter((i) => i.group === group)
                .map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    onClick={onNavigate}
                    className={({ isActive }) =>
                      cn(
                        "group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                        isActive
                          ? "bg-primary/10 text-foreground"
                          : "text-muted-foreground hover:bg-surface-overlay/60 hover:text-foreground"
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && (
                          <motion.span
                            layoutId="nav-active"
                            className="absolute inset-y-1 left-0 w-0.5 rounded-full bg-primary shadow-[0_0_8px_1px_rgba(34,211,238,0.7)]"
                          />
                        )}
                        <item.icon
                          className={cn(
                            "size-[18px] shrink-0 transition-colors",
                            isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground",
                            item.hero && !isActive && "text-accent"
                          )}
                        />
                        <span className={cn("flex-1 truncate", item.hero && "font-medium")}>
                          {item.label}
                        </span>
                        {item.badge && (
                          <span className="rounded-full bg-primary/15 px-1.5 py-0.5 text-[0.65rem] font-semibold text-primary">
                            {item.badge}
                          </span>
                        )}
                        {item.hero && !item.badge && (
                          <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[0.6rem] font-bold uppercase tracking-wide text-accent">
                            AI
                          </span>
                        )}
                        {!item.badge && !item.hero && (
                          <ChevronRight className="size-3.5 -translate-x-1 text-muted-foreground/0 transition-all group-hover:translate-x-0 group-hover:text-muted-foreground/60" />
                        )}
                      </>
                    )}
                  </NavLink>
                ))}
            </div>
          </div>
        ))}
      </nav>

      {/* System status footer */}
      <div className="border-t border-border p-3">
        <div className="flex items-center gap-2 rounded-lg bg-surface-overlay/40 px-3 py-2.5">
          <span className="relative flex size-2">
            <span className="absolute inline-flex size-full animate-ping rounded-full bg-success/60" />
            <Circle className="size-2 fill-success text-success" />
          </span>
          <div className="flex-1 leading-tight">
            <div className="text-xs font-medium text-foreground">All systems operational</div>
            <div className="text-[0.65rem] text-muted-foreground">8 / 12 sandbox VMs active</div>
          </div>
        </div>
      </div>
    </aside>
  );
}
