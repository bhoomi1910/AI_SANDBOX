import { motion } from "framer-motion";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

const badgeTones: Record<string, string> = {
  success: "border-success/30 bg-success/10 text-success",
  warning: "border-medium/40 bg-medium/10 text-medium",
  danger: "border-critical/30 bg-critical/10 text-critical",
  neutral: "border-border bg-surface/60 text-muted-foreground",
};

export function PageHeader({
  title,
  subtitle,
  icon: Icon,
  actions,
  badge,
}: {
  title: string;
  subtitle?: string;
  icon?: React.ComponentType<{ className?: string }>;
  actions?: ReactNode;
  badge?: { label: string; tone: "success" | "warning" | "danger" | "neutral" };
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: -6 }}
      animate={{ opacity: 1, y: 0 }}
      className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
    >
      <div className="flex items-center gap-3">
        {Icon && (
          <div className="grid size-10 place-items-center rounded-xl bg-primary/10 ring-1 ring-primary/20">
            <Icon className="size-5 text-primary" />
          </div>
        )}
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-foreground lg:text-2xl">{title}</h1>
            {badge && (
              <span className={cn("rounded-full border px-2.5 py-0.5 text-[0.65rem] font-semibold tracking-wide", badgeTones[badge.tone])}>
                {badge.label}
              </span>
            )}
          </div>
          {subtitle && <p className="mt-0.5 text-sm text-muted-foreground">{subtitle}</p>}
        </div>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </motion.div>
  );
}
