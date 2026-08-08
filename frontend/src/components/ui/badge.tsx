import * as React from "react";
import { cn } from "@/lib/utils";

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "clean";

const severityStyles: Record<Severity, string> = {
  critical: "border-critical/30 bg-critical/10 text-critical",
  high: "border-high/30 bg-high/10 text-high",
  medium: "border-medium/30 bg-medium/10 text-medium",
  low: "border-low/30 bg-low/10 text-low",
  info: "border-info/30 bg-info/10 text-info",
  clean: "border-success/30 bg-success/10 text-success",
};

export function SeverityBadge({
  severity,
  label,
  className,
  withDot = true,
}: {
  severity: Severity;
  label?: string;
  className?: string;
  withDot?: boolean;
}) {
  const dotColor: Record<Severity, string> = {
    critical: "bg-critical",
    high: "bg-high",
    medium: "bg-medium",
    low: "bg-low",
    info: "bg-info",
    clean: "bg-success",
  };
  return (
    <span className={cn("badge uppercase tracking-wide", severityStyles[severity], className)}>
      {withDot && <span className={cn("size-1.5 rounded-full", dotColor[severity])} />}
      {label ?? severity}
    </span>
  );
}

export function Badge({
  className,
  tone = "neutral",
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & {
  tone?: "neutral" | "primary" | "success" | "warn" | "danger";
}) {
  const tones = {
    neutral: "border-border bg-surface-overlay/60 text-muted-foreground",
    primary: "border-primary/30 bg-primary/10 text-primary",
    success: "border-success/30 bg-success/10 text-success",
    warn: "border-medium/30 bg-medium/10 text-medium",
    danger: "border-critical/30 bg-critical/10 text-critical",
  };
  return <span className={cn("badge", tones[tone], className)} {...props} />;
}
