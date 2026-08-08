import * as React from "react";
import { cn } from "@/lib/utils";

/** Skeleton shimmer block. */
export function Skeleton({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-md bg-surface-overlay/60",
        "before:absolute before:inset-0 before:-translate-x-full before:animate-shimmer",
        "before:bg-gradient-to-r before:from-transparent before:via-white/5 before:to-transparent",
        className
      )}
    />
  );
}

/** Text input. */
export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-9 w-full rounded-md border border-input bg-surface/60 px-3 text-sm text-foreground placeholder:text-muted-foreground/70",
        "focus:border-primary/50 focus:outline-none focus:ring-2 focus:ring-ring/30 transition-colors",
        className
      )}
      {...props}
    />
  )
);
Input.displayName = "Input";

/** Section separator label with hairline. */
export function SectionLabel({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("flex items-center gap-3", className)}>
      <span className="text-[0.7rem] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
        {children}
      </span>
      <span className="h-px flex-1 bg-border" />
    </div>
  );
}

/** Small labelled key/value row used across analysis panels. */
export function DataRow({
  label,
  children,
  mono = false,
  className,
}: {
  label: string;
  children: React.ReactNode;
  mono?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("flex items-center justify-between gap-4 py-2.5", className)}>
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className={cn("text-sm text-foreground text-right", mono && "font-mono text-[0.8125rem]")}>
        {children}
      </span>
    </div>
  );
}

/** Copyable inline hash / value chip. */
export function CopyChip({ value, className }: { value: string; className?: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard?.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
      title="Copy to clipboard"
      className={cn(
        "group inline-flex max-w-full items-center gap-1.5 rounded-md border border-border bg-surface/50 px-2 py-1 font-mono text-[0.75rem] text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground cursor-pointer",
        className
      )}
    >
      <span className="truncate">{copied ? "Copied!" : value}</span>
    </button>
  );
}
