import React from "react";
import { Radar, LayoutDashboard, History, Info, Sparkles } from "lucide-react";
import { useAppStore } from "../../store/useAppStore";
import { NavigationTab } from "../../types";

export const Sidebar: React.FC = () => {
  const { activeTab, setActiveTab } = useAppStore();

  const navItems: Array<{ id: NavigationTab; label: string; icon: React.ComponentType<{ className?: string }> }> = [
    { id: "scan", label: "Scan Engine", icon: Radar },
    { id: "dashboard", label: "Analytics", icon: LayoutDashboard },
    { id: "history", label: "Scan History", icon: History },
    { id: "about", label: "Architecture", icon: Info },
  ];

  return (
    <>
      {/* Desktop Sidebar */}
      <aside className="hidden md:flex flex-col w-64 border-r border-[var(--border-theme)] bg-[var(--bg-surface-1)]/70 backdrop-blur-md p-4 min-h-[calc(100vh-61px)] select-none shrink-0">
        <div className="text-[11px] font-mono uppercase tracking-wider text-[var(--text-muted)] px-3 mb-2 font-semibold">
          Navigation
        </div>

        <nav className="flex flex-col gap-1.5 flex-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center gap-3.5 px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer relative group ${
                  isActive
                    ? "bg-[var(--accent-primary)]/15 text-[var(--text-primary)] border border-[var(--border-theme-strong)] shadow-sm"
                    : "text-[var(--text-secondary)] hover:bg-[var(--bg-surface-2)] hover:text-[var(--text-primary)]"
                }`}
              >
                <div
                  className={`p-1.5 rounded-lg transition-colors ${
                    isActive
                      ? "bg-[var(--accent-primary)] text-white shadow-sm"
                      : "text-[var(--text-muted)] group-hover:text-[var(--accent-secondary)]"
                  }`}
                >
                  <Icon className="w-4 h-4" />
                </div>
                <span>{item.label}</span>

                {isActive && (
                  <span className="absolute right-2.5 w-1.5 h-4 rounded-full bg-[var(--accent-primary)]" />
                )}
              </button>
            );
          })}
        </nav>

        {/* Bottom System Card */}
        <div className="mt-auto p-3.5 rounded-2xl border border-[var(--border-theme)] bg-[var(--bg-surface-2)]/60 text-xs">
          <div className="flex items-center gap-2 text-[var(--text-primary)] font-semibold mb-1">
            <Sparkles className="w-3.5 h-3.5 text-[#ee9b00]" />
            <span>EMBER 2018 Model</span>
          </div>
          <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
            24 static PE features evaluated without sandboxed dynamic execution.
          </p>
        </div>
      </aside>

      {/* Mobile Bottom Navigation Bar */}
      <nav className="md:hidden fixed bottom-0 left-0 right-0 z-50 border-t border-[var(--border-theme)] bg-[var(--bg-base)]/95 backdrop-blur-lg px-2 py-2 flex items-center justify-around">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex flex-col items-center gap-1 py-1 px-3 rounded-lg text-xs transition-colors cursor-pointer ${
                isActive
                  ? "text-[var(--accent-primary)] font-semibold"
                  : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}
            >
              <Icon className="w-5 h-5" />
              <span className="text-[10px] tracking-tight">{item.label}</span>
            </button>
          );
        })}
      </nav>
    </>
  );
};
