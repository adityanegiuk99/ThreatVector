import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}", "./**/*.tsx"],
  theme: {
    extend: {
      colors: {
        overlay: "#090b11",
        panel: "#10141d",
        panelr: "#161b26",
        edge: "#232a3a",
        muted: "#8b94a7",
        accent: "#3b82f6",
        accenthover: "#2563eb",
        good: "#10b981",
        warn: "#f59e0b",
        crit: "#ef4444",
      },
    },
  },
  plugins: [],
};
export default config;
