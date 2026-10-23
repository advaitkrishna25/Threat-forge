import React from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ShieldAlert,
  ShieldCheck,
  Radar,
  Percent,
  Clock,
  ArrowRight,
  TrendingUp,
  PieChart as PieChartIcon,
} from "lucide-react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";
import { getStats } from "../api/client";
import { useAppStore } from "../store/useAppStore";
import { AnalysisRecord } from "../types";

export const DashboardPage: React.FC = () => {
  const { setCurrentAnalysis, setActiveTab } = useAppStore();

  const { data: stats, isLoading, error } = useQuery({
    queryKey: ["stats"],
    queryFn: getStats,
    refetchInterval: 10000,
  });

  if (isLoading) {
    return (
      <div className="w-full max-w-6xl mx-auto py-10 px-4 space-y-6">
        <div className="h-8 w-48 bg-[var(--bg-surface-2)] rounded-xl animate-pulse" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-28 rounded-2xl bg-[var(--bg-surface-2)] animate-pulse" />
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="h-72 rounded-3xl bg-[var(--bg-surface-2)] animate-pulse" />
          <div className="h-72 rounded-3xl bg-[var(--bg-surface-2)] animate-pulse" />
        </div>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div className="w-full max-w-6xl mx-auto py-16 px-4 text-center">
        <div className="p-8 rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] max-w-md mx-auto space-y-3">
          <ShieldAlert className="w-10 h-10 text-rose-500 mx-auto" />
          <h3 className="text-lg font-bold text-[var(--text-primary)]">Unable to load analytics</h3>
          <p className="text-xs text-[var(--text-muted)]">Check that the ThreatForge gateway is running.</p>
        </div>
      </div>
    );
  }

  const donutData = [
    { name: "Benign", value: stats.benign_count, color: "#94d2bd" },
    { name: "Malicious", value: stats.malicious_count, color: "#ae2012" },
    { name: "Unknown", value: stats.unknown_count, color: "#005f73" },
  ].filter((d) => d.value > 0);

  const timelineData = stats.scans_per_day.map((day) => ({
    date: day.date.slice(5), // MM-DD
    total: day.total,
    malicious: day.malicious,
    benign: day.benign,
  }));

  const handleSelectRecent = (analysis: AnalysisRecord) => {
    setCurrentAnalysis(analysis);
    setActiveTab("scan"); // Will render result view if currentAnalysis is set
  };

  return (
    <div className="w-full max-w-6xl mx-auto py-6 md:py-10 px-4 space-y-8">
      {/* Page Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-[var(--text-primary)]">
            Intelligence Overview
          </h1>
          <p className="text-xs md:text-sm text-[var(--text-muted)]">
            Global scan metrics, verdict ratios, and heuristic detection telemetry
          </p>
        </div>
        <span className="text-xs font-mono text-[var(--accent-secondary)] px-3 py-1 rounded-full border border-[var(--border-theme)] bg-[var(--bg-surface-1)]">
          Live SQLite Database
        </span>
      </div>

      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Scans */}
        <div className="p-5 rounded-2xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] shadow-lg relative overflow-hidden group">
          <div className="flex items-center justify-between text-xs font-mono text-[var(--text-muted)]">
            <span>Total Evaluated</span>
            <Radar className="w-4 h-4 text-[var(--accent-primary)]" />
          </div>
          <div className="text-3xl font-extrabold font-mono text-[var(--text-primary)] mt-2">
            {stats.total_scans.toLocaleString()}
          </div>
          <span className="text-[11px] text-[var(--text-muted)] mt-1 block">
            Uploaded PE Executables
          </span>
        </div>

        {/* Malicious */}
        <div className="p-5 rounded-2xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] shadow-lg relative overflow-hidden group">
          <div className="flex items-center justify-between text-xs font-mono text-[#ff6b6b]">
            <span>Malicious Files</span>
            <ShieldAlert className="w-4 h-4 text-[#ae2012]" />
          </div>
          <div className="text-3xl font-extrabold font-mono text-[#ae2012] mt-2">
            {stats.malicious_count.toLocaleString()}
          </div>
          <span className="text-[11px] text-[var(--text-muted)] mt-1 block">
            Flagged anomalous binaries
          </span>
        </div>

        {/* Benign */}
        <div className="p-5 rounded-2xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] shadow-lg relative overflow-hidden group">
          <div className="flex items-center justify-between text-xs font-mono text-[#94d2bd]">
            <span>Benign Software</span>
            <ShieldCheck className="w-4 h-4 text-[#94d2bd]" />
          </div>
          <div className="text-3xl font-extrabold font-mono text-[#94d2bd] mt-2">
            {stats.benign_count.toLocaleString()}
          </div>
          <span className="text-[11px] text-[var(--text-muted)] mt-1 block">
            Passed static checks
          </span>
        </div>

        {/* Detection Rate */}
        <div className="p-5 rounded-2xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] shadow-lg relative overflow-hidden group">
          <div className="flex items-center justify-between text-xs font-mono text-[#ee9b00]">
            <span>Detection Rate</span>
            <Percent className="w-4 h-4 text-[#ee9b00]" />
          </div>
          <div className="text-3xl font-extrabold font-mono text-[#ee9b00] mt-2">
            {stats.detection_rate}%
          </div>
          <span className="text-[11px] text-[var(--text-muted)] mt-1 block">
            Malicious ratio of total
          </span>
        </div>
      </div>

      {/* Visual Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Verdict Distribution Donut */}
        <div className="rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border-theme)]">
            <div className="flex items-center gap-2">
              <PieChartIcon className="w-5 h-5 text-[var(--accent-primary)]" />
              <h3 className="text-base font-bold text-[var(--text-primary)]">
                Verdict Distribution
              </h3>
            </div>
            <span className="text-xs font-mono text-[var(--text-muted)]">Split</span>
          </div>

          {donutData.length === 0 ? (
            <div className="h-64 flex items-center justify-center text-xs text-[var(--text-muted)]">
              No scan data recorded yet.
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={donutData}
                    cx="50%"
                    cy="50%"
                    innerRadius={65}
                    outerRadius={95}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {donutData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "var(--bg-surface-2)",
                      borderColor: "var(--border-theme)",
                      borderRadius: "12px",
                      color: "var(--text-primary)",
                      fontSize: "12px",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Donut Legend */}
          <div className="flex items-center justify-center gap-6 pt-2">
            <div className="flex items-center gap-2 text-xs">
              <span className="w-3 h-3 rounded-full bg-[#94d2bd]" />
              <span className="text-[var(--text-secondary)]">Benign ({stats.benign_count})</span>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="w-3 h-3 rounded-full bg-[#ae2012]" />
              <span className="text-[var(--text-secondary)]">Malicious ({stats.malicious_count})</span>
            </div>
            {stats.unknown_count > 0 && (
              <div className="flex items-center gap-2 text-xs">
                <span className="w-3 h-3 rounded-full bg-[#005f73]" />
                <span className="text-[var(--text-secondary)]">Unknown ({stats.unknown_count})</span>
              </div>
            )}
          </div>
        </div>

        {/* Daily Scan Velocity Area Chart */}
        <div className="rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border-theme)]">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-[#ee9b00]" />
              <h3 className="text-base font-bold text-[var(--text-primary)]">
                Scan Velocity Over Time
              </h3>
            </div>
            <span className="text-xs font-mono text-[var(--text-muted)]">Activity</span>
          </div>

          {timelineData.length === 0 ? (
            <div className="h-64 flex items-center justify-center text-xs text-[var(--text-muted)]">
              No temporal data recorded yet.
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <defs>
                    <linearGradient id="colorTotal" x1="0%" y1="0%" x2="0%" y2="100%">
                      <stop offset="5%" stopColor="#0a9396" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#0a9396" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="colorMal" x1="0%" y1="0%" x2="0%" y2="100%">
                      <stop offset="5%" stopColor="#ae2012" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#ae2012" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-theme)" vertical={false} />
                  <XAxis dataKey="date" stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                  <YAxis stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "var(--bg-surface-2)",
                      borderColor: "var(--border-theme)",
                      borderRadius: "12px",
                      color: "var(--text-primary)",
                      fontSize: "12px",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="total"
                    stroke="#0a9396"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorTotal)"
                    name="Total Scans"
                  />
                  <Area
                    type="monotone"
                    dataKey="malicious"
                    stroke="#ae2012"
                    strokeWidth={2}
                    fillOpacity={1}
                    fill="url(#colorMal)"
                    name="Malicious"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}

          <div className="flex items-center justify-center gap-6 pt-2">
            <div className="flex items-center gap-2 text-xs">
              <span className="w-3 h-3 rounded-full bg-[#0a9396]" />
              <span className="text-[var(--text-secondary)]">Total Scans</span>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="w-3 h-3 rounded-full bg-[#ae2012]" />
              <span className="text-[var(--text-secondary)]">Malicious Detections</span>
            </div>
          </div>
        </div>
      </div>

      {/* 5 Most Recent Scans */}
      <div className="rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] p-6 shadow-xl space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[var(--border-theme)]">
          <div className="flex items-center gap-2">
            <Clock className="w-5 h-5 text-[var(--accent-primary)]" />
            <h3 className="text-base font-bold text-[var(--text-primary)]">
              Recent Analyses
            </h3>
          </div>
          <button
            onClick={() => setActiveTab("history")}
            className="flex items-center gap-1.5 text-xs text-[var(--accent-secondary)] hover:text-[var(--text-primary)] transition-colors cursor-pointer font-medium"
          >
            <span>Full History</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {stats.recent_scans.length === 0 ? (
          <div className="p-8 text-center text-xs text-[var(--text-muted)]">
            No analyses recorded yet. Drop an executable in the Scan engine to begin.
          </div>
        ) : (
          <div className="divide-y divide-[var(--border-theme)]">
            {stats.recent_scans.map((item) => (
              <div
                key={item.id}
                onClick={() => handleSelectRecent(item)}
                className="flex items-center justify-between py-3 px-2 rounded-xl hover:bg-[var(--bg-surface-2)] transition-colors cursor-pointer group"
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`w-2.5 h-2.5 rounded-full ${
                      item.verdict === "MALICIOUS"
                        ? "bg-[#ae2012]"
                        : item.verdict === "BENIGN"
                        ? "bg-[#94d2bd]"
                        : "bg-[var(--text-muted)]"
                    }`}
                  />
                  <div>
                    <h4 className="text-xs font-bold font-mono text-[var(--text-primary)] group-hover:text-[var(--accent-primary)]">
                      {item.filename}
                    </h4>
                    <span className="text-[10px] font-mono text-[var(--text-muted)]">
                      {item.sha256.slice(0, 16)}... • {new Date(item.analyzed_at).toLocaleTimeString()}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <span
                      className={`text-xs font-mono font-bold ${
                        item.verdict === "MALICIOUS"
                          ? "text-[#ff6b6b]"
                          : item.verdict === "BENIGN"
                          ? "text-[#94d2bd]"
                          : "text-[var(--text-muted)]"
                      }`}
                    >
                      {item.verdict}
                    </span>
                    <span className="text-[10px] font-mono text-[var(--text-muted)] block">
                      Score: {Math.round(item.model_score * 100)}%
                    </span>
                  </div>
                  <ArrowRight className="w-4 h-4 text-[var(--text-muted)] group-hover:text-[var(--text-primary)] group-hover:translate-x-1 transition-all" />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
