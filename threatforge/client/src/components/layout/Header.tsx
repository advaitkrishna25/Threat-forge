import React, { useState, useEffect, useRef } from "react";
import { Shield, Palette, Command, Radio, X } from "lucide-react";
import { useAppStore } from "../../store/useAppStore";
import { AppTheme } from "../../types";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:3001";

/* ── All 7 themes with preview swatches ─────────────────────── */
interface ThemeMeta {
  id: AppTheme;
  name: string;
  label: string;
  mode: "dark" | "light";
  bg: string;        // preview card bg
  surface: string;   // inner card swatch
  accent: string;    // primary accent dot
  secondary: string; // secondary accent dot
  text: string;
  emoji: string;
}

const THEMES: ThemeMeta[] = [
  {
    id: "ocean",
    name: "Ocean Forge",
    label: "Deep teal · dark",
    mode: "dark",
    bg: "#001219",
    surface: "#002840",
    accent: "#0a9396",
    secondary: "#94d2bd",
    text: "#f0ead6",
    emoji: "🌊",
  },
  {
    id: "crimson",
    name: "Crimson Intel",
    label: "Iron red · dark",
    mode: "dark",
    bg: "#0f0005",
    surface: "#25000e",
    accent: "#ae2012",
    secondary: "#ee9b00",
    text: "#fce8e8",
    emoji: "🔴",
  },
  {
    id: "violet",
    name: "Violet Phantom",
    label: "Arcane purple · dark",
    mode: "dark",
    bg: "#06040f",
    surface: "#150d2e",
    accent: "#7c3aed",
    secondary: "#a78bfa",
    text: "#ede9fe",
    emoji: "⚡",
  },
  {
    id: "amber",
    name: "Amber Foundry",
    label: "Forge fire · dark",
    mode: "dark",
    bg: "#0f0800",
    surface: "#261800",
    accent: "#ee9b00",
    secondary: "#f5c842",
    text: "#fff4d6",
    emoji: "🔥",
  },
  {
    id: "jade",
    name: "Jade Matrix",
    label: "Bioluminescent · dark",
    mode: "dark",
    bg: "#00100a",
    surface: "#002418",
    accent: "#059669",
    secondary: "#34d399",
    text: "#e8fdf5",
    emoji: "🌿",
  },
  {
    id: "arctic",
    name: "Arctic Protocol",
    label: "Ice precision · light",
    mode: "light",
    bg: "#e8f4f8",
    surface: "#ffffff",
    accent: "#0369a1",
    secondary: "#0ea5e9",
    text: "#0c1a2e",
    emoji: "❄️",
  },
  {
    id: "sand",
    name: "Sand Dusk",
    label: "Warm parchment · light",
    mode: "light",
    bg: "#f6efd9",
    surface: "#ffffff",
    accent: "#005f73",
    secondary: "#ca6702",
    text: "#001219",
    emoji: "🏜️",
  },
];

/* ── Mini preview card for each theme ───────────────────────── */
const ThemeCard: React.FC<{
  meta: ThemeMeta;
  selected: boolean;
  onClick: () => void;
}> = ({ meta, selected, onClick }) => (
  <button
    onClick={onClick}
    title={meta.name}
    className="group relative flex flex-col gap-1.5 rounded-xl p-0 overflow-hidden border-2 transition-all duration-200 cursor-pointer focus:outline-none"
    style={{
      borderColor: selected ? meta.accent : "transparent",
      boxShadow: selected
        ? `0 0 0 1px ${meta.accent}55, 0 4px 20px ${meta.accent}30`
        : "none",
    }}
  >
    {/* Mini color preview card */}
    <div
      className="relative w-full h-16 rounded-lg overflow-hidden"
      style={{ background: meta.bg }}
    >
      {/* Simulated surface block */}
      <div
        className="absolute left-2 top-2 right-2 bottom-6 rounded-md opacity-80"
        style={{ background: meta.surface }}
      />
      {/* Accent bar at bottom */}
      <div
        className="absolute bottom-0 left-0 right-0 h-2 opacity-90"
        style={{
          background: `linear-gradient(90deg, ${meta.accent}, ${meta.secondary})`,
        }}
      />
      {/* Emoji badge */}
      <span className="absolute top-1 right-1.5 text-xs leading-none">
        {meta.emoji}
      </span>
      {/* Selected tick */}
      {selected && (
        <div
          className="absolute top-1 left-1.5 w-4 h-4 rounded-full flex items-center justify-center text-white text-[10px] font-bold shadow"
          style={{ background: meta.accent }}
        >
          ✓
        </div>
      )}
    </div>

    {/* Label */}
    <div className="px-1 pb-1">
      <div
        className="text-[11px] font-semibold leading-tight truncate"
        style={{ color: "var(--text-primary)" }}
      >
        {meta.name}
      </div>
      <div
        className="text-[10px] opacity-60 truncate"
        style={{ color: "var(--text-secondary)" }}
      >
        {meta.label}
      </div>
    </div>
  </button>
);

/* ── Main Header ─────────────────────────────────────────────── */
export const Header: React.FC = () => {
  const { theme, setTheme, setCommandPaletteOpen, setActiveTab } = useAppStore();

  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const btnRef = useRef<HTMLButtonElement>(null);

  /* health poll */
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch(`${API_BASE}/health`, {
          signal: AbortSignal.timeout(2500),
        });
        setBackendOnline(res.ok);
      } catch {
        setBackendOnline(false);
      }
    };
    checkHealth();
    const id = setInterval(checkHealth, 15_000);
    return () => clearInterval(id);
  }, []);

  /* close panel on outside click */
  useEffect(() => {
    if (!paletteOpen) return;
    const handler = (e: MouseEvent) => {
      if (
        panelRef.current &&
        !panelRef.current.contains(e.target as Node) &&
        !btnRef.current?.contains(e.target as Node)
      ) {
        setPaletteOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [paletteOpen]);

  const currentMeta = THEMES.find((t) => t.id === theme) ?? THEMES[0];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-[var(--border-theme)] backdrop-blur-md bg-[var(--bg-base)]/85 px-4 md:px-8 py-3">
      <div className="flex items-center justify-between mx-auto max-w-7xl">

        {/* Brand */}
        <div
          onClick={() => setActiveTab("scan")}
          className="flex items-center gap-3 cursor-pointer group select-none"
        >
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl shadow-lg group-hover:scale-105 transition-transform"
            style={{
              background: `linear-gradient(135deg, ${currentMeta.accent}, ${currentMeta.secondary})`,
              boxShadow: `0 4px 14px ${currentMeta.accent}40`,
            }}
          >
            <Shield className="w-5 h-5" style={{ color: currentMeta.bg }} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span
                className="text-xl font-bold tracking-tight bg-clip-text text-transparent"
                style={{
                  backgroundImage: `linear-gradient(90deg, var(--text-primary), var(--accent-secondary))`,
                }}
              >
                ThreatForge
              </span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-[var(--bg-surface-2)] text-[var(--accent-primary)] border border-[var(--border-theme)] font-semibold">
                v2.0
              </span>
            </div>
            <p className="text-[11px] text-[var(--text-muted)] tracking-wide hidden sm:block">
              Static PE Malware Intelligence
            </p>
          </div>
        </div>

        {/* Right controls */}
        <div className="flex items-center gap-2 sm:gap-3">

          {/* Engine status */}
          <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-mono border border-[var(--border-theme)] bg-[var(--bg-surface-1)]">
            <Radio
              className={`w-3.5 h-3.5 ${
                backendOnline === true
                  ? "animate-pulse"
                  : backendOnline === false
                  ? "opacity-50"
                  : "animate-spin"
              }`}
              style={{
                color:
                  backendOnline === true
                    ? "#22c55e"
                    : backendOnline === false
                    ? "#f87171"
                    : "#fbbf24",
              }}
            />
            <span className="text-[11px] text-[var(--text-secondary)]">
              {backendOnline === true
                ? "Engine Ready"
                : backendOnline === false
                ? "Engine Offline"
                : "Connecting..."}
            </span>
          </div>

          {/* Command palette */}
          <button
            onClick={() => setCommandPaletteOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 text-xs rounded-lg border border-[var(--border-theme)] bg-[var(--bg-surface-1)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--accent-primary)] cursor-pointer shadow-sm"
            title="Open Command Palette (Ctrl+K)"
          >
            <Command className="w-3.5 h-3.5" />
            <span className="hidden md:inline font-mono">Quick Actions</span>
            <kbd className="hidden md:inline text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-surface-2)] border border-[var(--border-theme)] text-[var(--text-muted)]">
              ⌘K
            </kbd>
          </button>

          {/* ── Theme Picker ── */}
          <div className="relative">
            <button
              ref={btnRef}
              id="theme-picker-btn"
              onClick={() => setPaletteOpen((o) => !o)}
              className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-[var(--border-theme)] bg-[var(--bg-surface-1)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--accent-primary)] cursor-pointer transition-all"
              title="Change Theme"
            >
              <Palette className="w-4 h-4" style={{ color: "var(--accent-primary)" }} />
              {/* Active theme swatch */}
              <span
                className="hidden sm:flex items-center gap-1.5 text-[11px] font-medium"
                style={{ color: "var(--text-secondary)" }}
              >
                <span
                  className="w-3 h-3 rounded-full border border-black/10"
                  style={{
                    background: `linear-gradient(135deg, ${currentMeta.accent}, ${currentMeta.secondary})`,
                  }}
                />
                {currentMeta.name}
              </span>
            </button>

            {/* ── Theme Panel ── */}
            {paletteOpen && (
              <div
                ref={panelRef}
                id="theme-panel"
                className="absolute right-0 mt-2 w-80 rounded-2xl border border-[var(--border-theme-strong)] bg-[var(--bg-surface-2)] shadow-2xl z-50 overflow-hidden"
                style={{ boxShadow: "var(--shadow-card)" }}
              >
                {/* Panel header */}
                <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-theme)] bg-[var(--bg-surface-1)]">
                  <div className="flex items-center gap-2">
                    <Palette className="w-4 h-4" style={{ color: "var(--accent-primary)" }} />
                    <span className="text-[13px] font-semibold" style={{ color: "var(--text-primary)" }}>
                      Choose Theme
                    </span>
                  </div>
                  <button
                    onClick={() => setPaletteOpen(false)}
                    className="p-1 rounded-lg hover:bg-[var(--bg-surface-3)] cursor-pointer"
                    style={{ color: "var(--text-muted)" }}
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>

                {/* Dark section */}
                <div className="px-3 pt-3 pb-2">
                  <p className="text-[10px] uppercase font-semibold tracking-widest mb-2 px-1"
                    style={{ color: "var(--text-muted)" }}>
                    Dark Themes
                  </p>
                  <div className="grid grid-cols-3 gap-2">
                    {THEMES.filter((t) => t.mode === "dark").map((t) => (
                      <ThemeCard
                        key={t.id}
                        meta={t}
                        selected={theme === t.id}
                        onClick={() => {
                          setTheme(t.id);
                          setPaletteOpen(false);
                        }}
                      />
                    ))}
                  </div>
                </div>

                {/* Divider */}
                <div className="mx-3 border-t border-[var(--border-theme)]" />

                {/* Light section */}
                <div className="px-3 pt-2 pb-3">
                  <p className="text-[10px] uppercase font-semibold tracking-widest mb-2 px-1"
                    style={{ color: "var(--text-muted)" }}>
                    Light Themes
                  </p>
                  <div className="grid grid-cols-3 gap-2">
                    {THEMES.filter((t) => t.mode === "light").map((t) => (
                      <ThemeCard
                        key={t.id}
                        meta={t}
                        selected={theme === t.id}
                        onClick={() => {
                          setTheme(t.id);
                          setPaletteOpen(false);
                        }}
                      />
                    ))}
                  </div>
                </div>

                {/* Footer hint */}
                <div
                  className="px-4 py-2 text-center text-[10px] border-t border-[var(--border-theme)] bg-[var(--bg-surface-1)]"
                  style={{ color: "var(--text-muted)" }}
                >
                  Tip: also accessible via{" "}
                  <kbd className="font-mono px-1 py-0.5 rounded bg-[var(--bg-surface-2)] border border-[var(--border-theme)]">
                    ⌘K
                  </kbd>{" "}
                  → Change Theme
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
