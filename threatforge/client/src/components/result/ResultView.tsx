import React, { useState } from "react";
import {
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  Copy,
  Check,
  FileCode,
  Clock,
  HardDrive,
  Hash,
  ArrowLeft,
  AlertOctagon,
  Info,
  TrendingUp,
} from "lucide-react";
import { toast } from "sonner";
import { AnalysisRecord } from "../../types";
import { useAppStore } from "../../store/useAppStore";
import { ScoreGauge } from "./ScoreGauge";
import { FeatureTable } from "./FeatureTable";
import { ArchiveResultView } from "./ArchiveResultView";

interface ResultViewProps {
  analysis: AnalysisRecord;
}

export const ResultView: React.FC<ResultViewProps> = ({ analysis }) => {
  if (analysis.file_type === "archive" || analysis.archive_data) {
    return <ArchiveResultView analysis={analysis} />;
  }

  const { setCurrentAnalysis, setActiveTab } = useAppStore();
  const [copiedSha, setCopiedSha] = useState(false);

  const handleCopySha = () => {
    navigator.clipboard.writeText(analysis.sha256);
    setCopiedSha(true);
    toast.success("SHA-256 hash copied to clipboard.");
    setTimeout(() => setCopiedSha(false), 2000);
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const formatDate = (iso: string) => {
    try {
      const d = new Date(iso);
      return d.toLocaleString(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      });
    } catch {
      return iso;
    }
  };

  const getVerdictStyle = () => {
    if (analysis.verdict === "MALICIOUS") {
      return {
        bg: "bg-gradient-to-r from-[#9b2226] via-[#ae2012] to-[#bb3e03]",
        text: "text-white",
        border: "border-[#ae2012]",
        icon: AlertTriangle,
        label: "MALICIOUS",
        subtext: "High-confidence anomalous indicators detected matching malware patterns.",
      };
    }
    if (analysis.verdict === "SUSPICIOUS") {
      return {
        bg: "bg-gradient-to-r from-[#bb3e03] via-[#ca6702] to-[#ee9b00]",
        text: "text-white",
        border: "border-[#ee9b00]",
        icon: AlertTriangle,
        label: "SUSPICIOUS",
        subtext: "Elevated risk indicators or borderline anomaly scores detected.",
      };
    }
    if (analysis.verdict === "BENIGN" || analysis.verdict === "NO_MALWARE_DETECTED") {
      return {
        bg: "bg-gradient-to-r from-[#005f73] via-[#0a9396] to-[#94d2bd]",
        text: "text-white",
        border: "border-[#0a9396]",
        icon: CheckCircle2,
        label: analysis.verdict === "NO_MALWARE_DETECTED" ? "NO MALWARE DETECTED" : "BENIGN",
        subtext: "No strong static malware anomalies observed across tested feature vectors.",
      };
    }
    return {
      bg: "bg-gradient-to-r from-[var(--bg-surface-3)] to-[var(--bg-surface-2)]",
      text: "text-[var(--text-primary)]",
      border: "border-[var(--border-theme)]",
      icon: HelpCircle,
      label: analysis.verdict || "UNKNOWN",
      subtext: analysis.error || "PE binary parsing failed or ML microservice unavailable.",
    };
  };

  const verdictStyle = getVerdictStyle();
  const VerdictIcon = verdictStyle.icon;

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-[#ae2012]/20 text-[#ff6b6b] border-[#ae2012]";
      case "high":
        return "bg-[#bb3e03]/20 text-[#ee9b00] border-[#bb3e03]";
      case "medium":
        return "bg-[#ee9b00]/20 text-[#ee9b00] border-[#ee9b00]/40";
      case "low":
      default:
        return "bg-[var(--accent-primary)]/20 text-[var(--accent-secondary)] border-[var(--accent-primary)]/40";
    }
  };

  return (
    <div className="w-full max-w-6xl mx-auto py-6 md:py-8 px-4 space-y-6">
      {/* Top action bar */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => {
            setCurrentAnalysis(null);
            setActiveTab("scan");
          }}
          className="flex items-center gap-2 px-3.5 py-2 text-xs rounded-xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--accent-primary)] transition-all cursor-pointer font-medium"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Analyze Another Binary</span>
        </button>

        <span className="text-xs font-mono text-[var(--text-muted)]">
          ID: {analysis.id.slice(0, 8)}...
        </span>
      </div>

      {/* Main Verdict Banner */}
      <div
        className={`rounded-3xl p-6 md:p-8 shadow-2xl border ${verdictStyle.border} ${verdictStyle.bg} ${verdictStyle.text} relative overflow-hidden`}
      >
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 relative z-10">
          <div className="flex items-center gap-4">
            <div className="p-3.5 rounded-2xl bg-black/25 backdrop-blur-md border border-white/20 shadow-inner">
              <VerdictIcon className="w-10 h-10" />
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <span className="text-xs font-mono uppercase tracking-widest opacity-80">
                  Classifier Verdict
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-black/30 border border-white/20 uppercase font-bold">
                  {analysis.threat_level}
                </span>
              </div>
              <h2 className="text-3xl md:text-5xl font-black tracking-tight mt-0.5 font-mono">
                {verdictStyle.label}
              </h2>
            </div>
          </div>

          <div className="max-w-md text-xs md:text-sm opacity-90 leading-relaxed font-sans">
            {verdictStyle.subtext}
          </div>
        </div>
      </div>

      {/* Grid: Gauge + Metadata Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Score Gauge */}
        <div className="lg:col-span-1">
          <ScoreGauge
            score={analysis.model_score}
            verdict={analysis.verdict}
            threatLevel={analysis.threat_level}
          />
        </div>

        {/* Right: File Metadata & Cryptographic Identity */}
        <div className="lg:col-span-2 rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] p-6 shadow-xl flex flex-col justify-between space-y-6">
          <div>
            <div className="flex items-center justify-between pb-4 border-b border-[var(--border-theme)]">
              <div className="flex items-center gap-2.5">
                <FileCode className="w-5 h-5 text-[var(--accent-primary)]" />
                <h3 className="text-base font-bold text-[var(--text-primary)]">
                  Binary Metadata
                </h3>
              </div>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-[var(--bg-surface-2)] text-[var(--text-muted)] border border-[var(--border-theme)]">
                PE32 / PE32+
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-5">
              <div className="p-3.5 rounded-2xl bg-[var(--bg-surface-2)] border border-[var(--border-theme)]">
                <div className="flex items-center gap-2 text-xs font-mono text-[var(--text-muted)] mb-1">
                  <FileCode className="w-3.5 h-3.5" />
                  <span>File Name</span>
                </div>
                <div className="text-sm font-semibold font-mono text-[var(--text-primary)] truncate" title={analysis.filename}>
                  {analysis.filename}
                </div>
              </div>

              <div className="p-3.5 rounded-2xl bg-[var(--bg-surface-2)] border border-[var(--border-theme)]">
                <div className="flex items-center gap-2 text-xs font-mono text-[var(--text-muted)] mb-1">
                  <HardDrive className="w-3.5 h-3.5" />
                  <span>File Size</span>
                </div>
                <div className="text-sm font-semibold font-mono text-[var(--text-primary)]">
                  {formatSize(analysis.file_size)} <span className="text-xs font-normal text-[var(--text-muted)]">({analysis.file_size.toLocaleString()} bytes)</span>
                </div>
              </div>

              <div className="p-3.5 rounded-2xl bg-[var(--bg-surface-2)] border border-[var(--border-theme)] sm:col-span-2">
                <div className="flex items-center justify-between text-xs font-mono text-[var(--text-muted)] mb-1">
                  <div className="flex items-center gap-2">
                    <Hash className="w-3.5 h-3.5 text-[var(--accent-primary)]" />
                    <span>SHA-256 Checksum</span>
                  </div>
                  <button
                    onClick={handleCopySha}
                    className="flex items-center gap-1 text-[11px] text-[var(--accent-secondary)] hover:text-[var(--text-primary)] transition-colors cursor-pointer"
                  >
                    {copiedSha ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedSha ? "Copied" : "Copy"}</span>
                  </button>
                </div>
                <div className="text-xs font-mono font-medium text-[var(--text-primary)] break-all select-all bg-[var(--bg-surface-3)]/50 p-2 rounded-xl">
                  {analysis.sha256}
                </div>
              </div>

              <div className="p-3.5 rounded-2xl bg-[var(--bg-surface-2)] border border-[var(--border-theme)] sm:col-span-2">
                <div className="flex items-center gap-2 text-xs font-mono text-[var(--text-muted)] mb-1">
                  <Clock className="w-3.5 h-3.5" />
                  <span>Analyzed At</span>
                </div>
                <div className="text-sm font-semibold font-mono text-[var(--text-secondary)]">
                  {formatDate(analysis.analyzed_at)}
                </div>
              </div>
            </div>
          </div>

          {/* Permanent Disclaimer Box */}
          <div className="p-4 rounded-2xl border border-[var(--border-theme-strong)] bg-[var(--bg-surface-2)]/80 flex items-start gap-3">
            <Info className="w-5 h-5 text-[#ee9b00] shrink-0 mt-0.5" />
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
              <strong className="text-[var(--text-primary)]">Permanent Advisory:</strong> Score is a model output from static features, not a calibrated probability. Treat it as one signal, not a final verdict.
            </p>
          </div>
        </div>
      </div>

      {/* Heuristic Indicators & Top Contributors */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Indicators Card */}
        <div className="rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border-theme)]">
            <div className="flex items-center gap-2">
              <AlertOctagon className="w-5 h-5 text-[var(--accent-primary)]" />
              <h3 className="text-base font-bold text-[var(--text-primary)]">
                Heuristic Indicators ({analysis.indicators.length})
              </h3>
            </div>
            <span className="text-xs font-mono text-[var(--text-muted)]">Rule Engine</span>
          </div>

          {analysis.indicators.length === 0 ? (
            <div className="p-6 text-center text-xs text-[var(--text-muted)]">
              No anomalous PE characteristics flagged.
            </div>
          ) : (
            <div className="space-y-3">
              {analysis.indicators.map((ind, idx) => (
                <div
                  key={idx}
                  className="p-3.5 rounded-2xl bg-[var(--bg-surface-2)] border border-[var(--border-theme)] space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold text-[var(--text-primary)]">
                      {ind.title}
                    </h4>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded-full border uppercase font-bold ${getSeverityBadge(
                        ind.severity
                      )}`}
                    >
                      {ind.severity}
                    </span>
                  </div>
                  <p className="text-xs text-[var(--text-muted)] leading-relaxed">
                    {ind.detail}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Contributors Card */}
        <div className="rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[var(--border-theme)]">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-[#ee9b00]" />
              <h3 className="text-base font-bold text-[var(--text-primary)]">
                Feature Influence ({analysis.top_contributors.length})
              </h3>
            </div>
            <span className="text-xs font-mono text-[var(--text-muted)]">Weights</span>
          </div>

          {analysis.top_contributors.length === 0 ? (
            <div className="p-6 text-center text-xs text-[var(--text-muted)]">
              No outlier feature weights observed.
            </div>
          ) : (
            <div className="space-y-3">
              {analysis.top_contributors.map((tc, idx) => {
                const isMal = tc.direction.toLowerCase() === "malicious";
                return (
                  <div
                    key={idx}
                    className="p-3.5 rounded-2xl bg-[var(--bg-surface-2)] border border-[var(--border-theme)] flex items-center justify-between"
                  >
                    <div>
                      <span className="text-xs font-mono font-bold text-[var(--text-primary)] block">
                        {tc.feature}
                      </span>
                      <span className="text-[11px] text-[var(--text-muted)]">
                        Impact: {tc.impact}
                      </span>
                    </div>
                    <span
                      className={`text-[10px] font-mono font-bold px-2.5 py-1 rounded-full border uppercase ${
                        isMal
                          ? "bg-[#ae2012]/15 text-[#ff6b6b] border-[#ae2012]/50"
                          : "bg-emerald-500/15 text-emerald-400 border-emerald-500/50"
                      }`}
                    >
                      Leans {tc.direction}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* 24-Feature Vector Table */}
      <FeatureTable features={analysis.features} />
    </div>
  );
};
