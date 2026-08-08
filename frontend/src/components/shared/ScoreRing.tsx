import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

/** Circular risk/confidence gauge. */
export function ScoreRing({
  value,
  size = 120,
  stroke = 9,
  label,
  sublabel,
  color,
}: {
  value: number;
  size?: number;
  stroke?: number;
  label?: string;
  sublabel?: string;
  color?: string;
}) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.min(100, Math.max(0, value));
  const offset = c - (pct / 100) * c;

  const auto =
    pct >= 80 ? "#f43f5e" : pct >= 60 ? "#fb923c" : pct >= 40 ? "#facc15" : pct >= 20 ? "#38bdf8" : "#34d399";
  const ringColor = color ?? auto;

  return (
    <div className="relative inline-grid place-items-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(148,163,184,0.12)" strokeWidth={stroke} />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={ringColor}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          initial={{ strokeDashoffset: c }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.1, ease: "easeOut" }}
          style={{ filter: `drop-shadow(0 0 6px ${ringColor}88)` }}
        />
      </svg>
      <div className="absolute inset-0 grid place-content-center text-center">
        <div className={cn("font-bold tracking-tight text-foreground", size > 100 ? "text-3xl" : "text-xl")} style={{ color: ringColor }}>
          {label ?? pct}
        </div>
        {sublabel && <div className="mt-0.5 text-[0.65rem] uppercase tracking-wide text-muted-foreground">{sublabel}</div>}
      </div>
    </div>
  );
}
