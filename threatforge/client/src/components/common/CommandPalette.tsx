import React, { useState, useEffect } from "react";
import { Search, Radar, LayoutDashboard, History, Info, Palette, X } from "lucide-react";
import { useAppStore } from "../../store/useAppStore";
import { AppTheme } from "../../types";

const THEME_LABELS: Record<AppTheme, string> = {
  ocean:   "🌊 Ocean Forge — Deep teal · dark",
  crimson: "🔴 Crimson Intel — Iron red · dark",
  violet:  "⚡ Violet Phantom — Arcane purple · dark",
  amber:   "🔥 Amber Foundry — Forge fire · dark",
  jade:    "🌿 Jade Matrix — Bioluminescent · dark",
  arctic:  "❄️ Arctic Protocol — Ice · light",
  sand:    "🏜️ Sand Dusk — Warm parchment · light",
};

export const CommandPalette: React.FC = () => {
  const {
    commandPaletteOpen,
    setCommandPaletteOpen,
    setActiveTab,
    setTheme,
  } = useAppStore();

  const [search, setSearch] = useState("");

  // Keyboard shortcut listener (Cmd/Ctrl + K and Esc)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCommandPaletteOpen(!commandPaletteOpen);
      }
      if (e.key === "Escape" && commandPaletteOpen) {
        setCommandPaletteOpen(false);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [commandPaletteOpen, setCommandPaletteOpen]);

  if (!commandPaletteOpen) return null;

  const actions = [
    {
      category: "Navigation",
      items: [
        {
          label: "Go to Scan Engine",
          icon: Radar,
          action: () => {
            setActiveTab("scan");
            setCommandPaletteOpen(false);
          },
        },
        {
          label: "Go to Analytics Dashboard",
          icon: LayoutDashboard,
          action: () => {
            setActiveTab("dashboard");
            setCommandPaletteOpen(false);
          },
        },
        {
          label: "View Scan History",
          icon: History,
          action: () => {
            setActiveTab("history");
            setCommandPaletteOpen(false);
          },
        },
        {
          label: "View Architecture & Model Info",
          icon: Info,
          action: () => {
            setActiveTab("about");
            setCommandPaletteOpen(false);
          },
        },
      ],
    },
    {
      category: "Themes",
      items: (Object.keys(THEME_LABELS) as AppTheme[]).map((id) => ({
        label: `Theme: ${THEME_LABELS[id]}`,
        icon: Palette,
        action: () => {
          setTheme(id);
          setCommandPaletteOpen(false);
        },
      })),
    },
  ];

  const filteredCategories = actions
    .map((cat) => ({
      ...cat,
      items: cat.items.filter((item) =>
        item.label.toLowerCase().includes(search.toLowerCase())
      ),
    }))
    .filter((cat) => cat.items.length > 0);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-150">
      <div
        className="w-full max-w-lg rounded-2xl border border-[var(--border-theme-strong)] bg-[var(--bg-surface-2)] shadow-2xl overflow-hidden animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search Input Bar */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-[var(--border-theme)]">
          <Search className="w-5 h-5 text-[var(--accent-primary)]" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Type a command or jump to page..."
            autoFocus
            className="flex-1 bg-transparent text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] outline-none"
          />
          <button
            onClick={() => setCommandPaletteOpen(false)}
            className="p-1 rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-surface-3)] transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Action List */}
        <div className="max-h-80 overflow-y-auto p-2">
          {filteredCategories.length === 0 ? (
            <div className="p-6 text-center text-xs text-[var(--text-muted)]">
              No matching commands found.
            </div>
          ) : (
            filteredCategories.map((cat) => (
              <div key={cat.category} className="mb-2 last:mb-0">
                <div className="px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-[var(--text-muted)]">
                  {cat.category}
                </div>
                {cat.items.map((item, idx) => {
                  const Icon = item.icon;
                  return (
                    <button
                      key={idx}
                      onClick={item.action}
                      className="flex items-center gap-3 w-full px-3 py-2 rounded-xl text-xs text-[var(--text-primary)] hover:bg-[var(--accent-primary)]/15 hover:text-[var(--accent-primary)] transition-all cursor-pointer group text-left"
                    >
                      <Icon className="w-4 h-4 text-[var(--text-muted)] group-hover:text-[var(--accent-primary)]" />
                      <span className="flex-1 font-medium">{item.label}</span>
                    </button>
                  );
                })}
              </div>
            ))
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="flex items-center justify-between px-4 py-2 border-t border-[var(--border-theme)] bg-[var(--bg-surface-1)] text-[11px] font-mono text-[var(--text-muted)]">
          <span>Navigate with mouse or keyboard</span>
          <span>[ESC] to dismiss</span>
        </div>
      </div>
    </div>
  );
};
