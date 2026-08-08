/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: { "2xl": "1400px" },
    },
    extend: {
      colors: {
        // Base surfaces — deep slate/navy SOC console
        canvas: "#060a14",
        surface: {
          DEFAULT: "#0b1120",
          raised: "#111a2e",
          overlay: "#16213b",
        },
        border: "rgba(148, 163, 184, 0.12)",
        input: "rgba(148, 163, 184, 0.18)",
        ring: "#22d3ee",
        // Primary brand accent — cyan (Aegis)
        primary: {
          DEFAULT: "#22d3ee",
          foreground: "#04121a",
          muted: "rgba(34, 211, 238, 0.14)",
        },
        accent: {
          DEFAULT: "#6366f1",
          foreground: "#eef2ff",
        },
        // Severity scale — SOC standard
        critical: { DEFAULT: "#f43f5e", muted: "rgba(244, 63, 94, 0.14)" },
        high: { DEFAULT: "#fb923c", muted: "rgba(251, 146, 60, 0.14)" },
        medium: { DEFAULT: "#facc15", muted: "rgba(250, 204, 21, 0.14)" },
        low: { DEFAULT: "#38bdf8", muted: "rgba(56, 189, 248, 0.14)" },
        info: { DEFAULT: "#818cf8", muted: "rgba(129, 140, 248, 0.14)" },
        success: { DEFAULT: "#34d399", muted: "rgba(52, 211, 153, 0.14)" },
        // Text
        foreground: "#e2e8f0",
        muted: {
          DEFAULT: "#16213b",
          foreground: "#8b9ab5",
        },
        destructive: {
          DEFAULT: "#f43f5e",
          foreground: "#fff1f2",
        },
        card: {
          DEFAULT: "#0b1120",
          foreground: "#e2e8f0",
        },
        popover: {
          DEFAULT: "#111a2e",
          foreground: "#e2e8f0",
        },
        secondary: {
          DEFAULT: "#16213b",
          foreground: "#cbd5e1",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "'Fira Code'", "ui-monospace", "monospace"],
      },
      borderRadius: {
        lg: "0.75rem",
        md: "0.5rem",
        sm: "0.375rem",
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(34,211,238,0.25), 0 0 24px -4px rgba(34,211,238,0.35)",
        card: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.7)",
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
        "pulse-ring": {
          "0%": { boxShadow: "0 0 0 0 rgba(34,211,238,0.4)" },
          "70%": { boxShadow: "0 0 0 10px rgba(34,211,238,0)" },
          "100%": { boxShadow: "0 0 0 0 rgba(34,211,238,0)" },
        },
        "fade-up": {
          from: { opacity: "0", transform: "translateY(8px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        },
      },
      animation: {
        shimmer: "shimmer 2s infinite",
        "pulse-ring": "pulse-ring 2s infinite",
        "fade-up": "fade-up 0.4s ease-out",
        scan: "scan 3s linear infinite",
      },
    },
  },
  plugins: [],
};
