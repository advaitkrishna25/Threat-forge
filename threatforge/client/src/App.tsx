import React from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "sonner";
import { useAppStore } from "./store/useAppStore";
import { Header } from "./components/layout/Header";
import { Sidebar } from "./components/layout/Sidebar";
import { CommandPalette } from "./components/common/CommandPalette";
import { ScanPage } from "./pages/ScanPage";
import { ResultView } from "./components/result/ResultView";
import { DashboardPage } from "./pages/DashboardPage";
import { HistoryPage } from "./pages/HistoryPage";
import { AboutPage } from "./pages/AboutPage";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      staleTime: 5000,
    },
  },
});

export const AppContent: React.FC = () => {
  const { theme, activeTab, currentAnalysis } = useAppStore();
  const isLight = theme === "arctic" || theme === "sand";

  const renderContent = () => {
    switch (activeTab) {
      case "scan":
        return currentAnalysis ? (
          <ResultView analysis={currentAnalysis} />
        ) : (
          <ScanPage />
        );
      case "dashboard":
        return <DashboardPage />;
      case "history":
        return <HistoryPage />;
      case "about":
        return <AboutPage />;
      default:
        return <ScanPage />;
    }
  };

  return (
    <div className="min-h-screen bg-[var(--bg-base)] text-[var(--text-primary)] flex flex-col font-sans transition-colors duration-200">
      <Header />

      <div className="flex flex-1 pb-16 md:pb-0">
        <Sidebar />
        <main className="flex-1 overflow-y-auto bg-ambient-glow">
          {renderContent()}
        </main>
      </div>

      <CommandPalette />
      <Toaster
        position="bottom-right"
        theme={isLight ? "light" : "dark"}
        richColors
      />
    </div>
  );
};

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
}
