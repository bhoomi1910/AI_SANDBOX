import { motion } from "framer-motion";
import { TrendingUp, TrendingDown } from "lucide-react";
import { cn } from "@/lib/utils";

export function Sparkline({ data, color = "#22d3ee" }: { data: number[]; color?: string }) {
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const w = 100;
  const h = 32;
  const points = data
    .map((v, i) => `${(i / (data.length - 1)) * w},${h - ((v - min) / range) * h}`)
    .join(" ");
  const id = `spark-${color.replace("#", "")}`;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="h-8 w-full">
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.28" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polyline points={`0,${h} ${points} ${w},${h}`} fill={`url(#${id})`} stroke="none" />
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.75" vectorEffect="non-scaling-stroke" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function StatTile({
  label,
  value,
  unit,
  delta,
  spark,
  color = "#22d3ee",
  icon: Icon,
  invertDelta = false,
  index = 0,
}: {
  label: string;
  value: string | number;
  unit?: string;
  delta?: number;
  spark?: number[];
  color?: string;
  icon?: React.ComponentType<{ className?: string; style?: React.CSSProperties }>;
  invertDelta?: boolean;
  index?: number;
}) {
  const positive = delta !== undefined && (invertDelta ? delta < 0 : delta > 0);
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.06 }}
      className="stat-tile hairline-top group"
    >
      <div className="flex items-start justify-between">
        <div>
          <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</div>
          <div className="mt-2 flex items-baseline gap-1">
            <span className="text-2xl font-bold tracking-tight text-foreground lg:text-[1.75rem]">{value}</span>
            {unit && <span className="text-sm text-muted-foreground">{unit}</span>}
          </div>
        </div>
        {Icon && (
          <div className="grid size-9 place-items-center rounded-lg bg-surface-overlay/60 ring-1 ring-border transition-colors group-hover:ring-primary/30">
            <Icon className="size-[18px]" style={{ color }} />
          </div>
        )}
      </div>
      <div className="mt-3 flex items-end justify-between gap-3">
        {delta !== undefined && (
          <div
            className={cn(
              "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-semibold",
              positive ? "bg-success/10 text-success" : "bg-critical/10 text-critical"
            )}
          >
            {positive ? <TrendingUp className="size-3" /> : <TrendingDown className="size-3" />}
            {Math.abs(delta)}%
          </div>
        )}
        {spark && (
          <div className="w-24">
            <Sparkline data={spark} color={color} />
          </div>
        )}
      </div>
    </motion.div>
  );
}
