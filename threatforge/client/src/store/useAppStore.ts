import { create } from "zustand";
import { AppTheme, ThemeMode, AccentPreset, NavigationTab, AnalysisRecord } from "../types";

interface AppState {
  theme: AppTheme;
  // legacy shims so any existing code referencing these doesn't break
  themeMode: ThemeMode;
  accentPreset: AccentPreset;

  activeTab: NavigationTab;
  currentAnalysis: AnalysisRecord | null;
  commandPaletteOpen: boolean;

  setTheme: (theme: AppTheme) => void;
  /** @deprecated use setTheme */
  setThemeMode: (mode: ThemeMode) => void;
  /** @deprecated use setTheme */
  setAccentPreset: (preset: AccentPreset) => void;
  setActiveTab: (tab: NavigationTab) => void;
  setCurrentAnalysis: (analysis: AnalysisRecord | null) => void;
  setCommandPaletteOpen: (open: boolean) => void;
}

const LIGHT_THEMES: AppTheme[] = ["arctic", "sand"];

function getInitialTheme(): AppTheme {
  const saved = localStorage.getItem("threatforge_theme_v2") as AppTheme | null;
  if (saved) return saved;
  // migrate from old system
  const oldTheme = localStorage.getItem("threatforge_theme");
  return oldTheme === "light" ? "arctic" : "ocean";
}

export function applyTheme(theme: AppTheme) {
  const root = document.documentElement;
  // set data-theme drives all CSS variable blocks
  root.setAttribute("data-theme", theme);
  // keep color-scheme in sync for browser chrome (scrollbars, inputs, etc.)
  if (LIGHT_THEMES.includes(theme)) {
    root.setAttribute("data-color-scheme", "light");
    root.classList.remove("dark");
  } else {
    root.setAttribute("data-color-scheme", "dark");
    root.classList.add("dark");
  }
}

/** Legacy shim — not called by new code */
export function applyAccent(_preset: AccentPreset) {
  // no-op: accent is now baked into the full theme
}

export const useAppStore = create<AppState>((set) => {
  const initialTheme = getInitialTheme();
  // Apply on store creation (SSR-safe guard)
  if (typeof window !== "undefined") applyTheme(initialTheme);

  return {
    theme: initialTheme,
    themeMode: LIGHT_THEMES.includes(initialTheme) ? "light" : "dark",
    accentPreset: "teal",

    activeTab: "scan",
    currentAnalysis: null,
    commandPaletteOpen: false,

    setTheme: (theme) => {
      localStorage.setItem("threatforge_theme_v2", theme);
      applyTheme(theme);
      set({
        theme,
        themeMode: LIGHT_THEMES.includes(theme) ? "light" : "dark",
      });
    },

    /** @deprecated */
    setThemeMode: (themeMode) => {
      const mapped: AppTheme = themeMode === "light" ? "arctic" : "ocean";
      localStorage.setItem("threatforge_theme_v2", mapped);
      applyTheme(mapped);
      set({ theme: mapped, themeMode });
    },

    /** @deprecated */
    setAccentPreset: (accentPreset) => set({ accentPreset }),

    setActiveTab: (activeTab) => set({ activeTab }),
    setCurrentAnalysis: (currentAnalysis) => set({ currentAnalysis }),
    setCommandPaletteOpen: (commandPaletteOpen) => set({ commandPaletteOpen }),
  };
});
