import { motion } from "framer-motion";
import type { NetworkConnection } from "@/data/types";

/**
 * Lightweight world map. A simplified continent silhouette (as an SVG path)
 * with connections plotted via equirectangular projection and animated
 * "attack arcs" from the sandbox origin to each endpoint.
 */
const SANDBOX_ORIGIN = { lat: 51.5, lon: -0.12 }; // London (analysis enclave)

// Equirectangular projection into a 360 x 180 viewBox
function project(lat: number, lon: number) {
  return { x: (lon + 180) * (360 / 360), y: (90 - lat) * (180 / 180) };
}

export function WorldMap({ connections }: { connections: NetworkConnection[] }) {
  const origin = project(SANDBOX_ORIGIN.lat, SANDBOX_ORIGIN.lon);

  return (
    <div className="relative aspect-[2/1] w-full overflow-hidden rounded-lg border border-border bg-[#070d1a]">
      <svg viewBox="0 0 360 180" className="h-full w-full" preserveAspectRatio="xMidYMid slice">
        {/* graticule */}
        <defs>
          <pattern id="grid" width="15" height="15" patternUnits="userSpaceOnUse">
            <path d="M15 0 L0 0 0 15" fill="none" stroke="rgba(148,163,184,0.06)" strokeWidth="0.4" />
          </pattern>
          <radialGradient id="glow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="rgba(34,211,238,0.15)" />
            <stop offset="100%" stopColor="transparent" />
          </radialGradient>
        </defs>
        <rect width="360" height="180" fill="url(#grid)" />
        <rect width="360" height="180" fill="url(#glow)" />

        {/* Stylised landmasses (simplified silhouettes) */}
        <g fill="rgba(99,116,148,0.14)" stroke="rgba(148,163,184,0.18)" strokeWidth="0.4">
          {/* North America */}
          <path d="M40 40 L90 34 L100 55 L85 78 L70 74 L58 88 L48 70 L44 52 Z" />
          {/* South America */}
          <path d="M92 96 L108 92 L112 112 L100 140 L90 128 L88 108 Z" />
          {/* Europe */}
          <path d="M168 40 L192 36 L200 50 L188 60 L172 58 L166 48 Z" />
          {/* Africa */}
          <path d="M170 66 L200 64 L208 96 L192 128 L178 116 L172 90 Z" />
          {/* Asia */}
          <path d="M204 34 L280 30 L300 58 L280 82 L240 76 L214 62 L206 46 Z" />
          {/* Australia */}
          <path d="M286 116 L316 112 L322 132 L300 140 L288 128 Z" />
        </g>

        {/* Attack arcs */}
        {connections.map((c, i) => {
          const dest = project(c.lat, c.lon);
          const mx = (origin.x + dest.x) / 2;
          const my = (origin.y + dest.y) / 2 - 30;
          const color = c.malicious ? "#f43f5e" : "#34d399";
          return (
            <g key={c.destIp}>
              <motion.path
                d={`M${origin.x} ${origin.y} Q${mx} ${my} ${dest.x} ${dest.y}`}
                fill="none"
                stroke={color}
                strokeWidth="0.6"
                strokeOpacity="0.5"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 1.4, delay: i * 0.15 }}
              />
              {/* travelling pulse */}
              <motion.circle
                r="1.2"
                fill={color}
                initial={{ offsetDistance: "0%" }}
                animate={{ offsetDistance: "100%" }}
                transition={{ duration: 2.4, delay: i * 0.15, repeat: Infinity, repeatDelay: 0.6, ease: "easeInOut" }}
                style={{ offsetPath: `path("M${origin.x} ${origin.y} Q${mx} ${my} ${dest.x} ${dest.y}")` } as React.CSSProperties}
              />
            </g>
          );
        })}

        {/* Endpoint markers */}
        {connections.map((c) => {
          const dest = project(c.lat, c.lon);
          const color = c.malicious ? "#f43f5e" : "#34d399";
          return (
            <g key={`m-${c.destIp}`}>
              <motion.circle cx={dest.x} cy={dest.y} r="4" fill={color} fillOpacity="0.15" animate={{ r: [3, 6, 3], fillOpacity: [0.25, 0, 0.25] }} transition={{ duration: 2, repeat: Infinity }} />
              <circle cx={dest.x} cy={dest.y} r="1.6" fill={color} />
            </g>
          );
        })}

        {/* Origin */}
        <g>
          <circle cx={origin.x} cy={origin.y} r="2" fill="#22d3ee" />
          <motion.circle cx={origin.x} cy={origin.y} r="3" fill="none" stroke="#22d3ee" animate={{ r: [3, 7], opacity: [0.7, 0] }} transition={{ duration: 1.8, repeat: Infinity }} />
        </g>
      </svg>

      {/* Endpoint legend chips */}
      <div className="absolute bottom-2 left-2 flex flex-wrap gap-1.5">
        {connections.filter((c) => c.malicious).slice(0, 3).map((c) => (
          <span key={c.destIp} className="rounded border border-critical/30 bg-black/50 px-1.5 py-0.5 font-mono text-[0.6rem] text-critical backdrop-blur">
            {c.countryCode} · {c.destIp}
          </span>
        ))}
      </div>
    </div>
  );
}
