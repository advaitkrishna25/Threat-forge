import React, { useState, useMemo } from "react";
import {
  Copy,
  Check,
  FolderArchive,
  Clock,
  HardDrive,
  Hash,
  ArrowLeft,
  AlertOctagon,
  AlertTriangle,
  Info,
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  FileCode,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { toast } from "sonner";
import { AnalysisRecord } from "../../types";
import { useAppStore } from "../../store/useAppStore";

interface ArchiveResultViewProps {
  analysis: AnalysisRecord;
}

export const ArchiveResultView: React.FC<ArchiveResultViewProps> = ({ analysis }) => {
  const { setCurrentAnalysis, setActiveTab } = useAppStore();
  const [copiedSha, setCopiedSha] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<string>("ALL");
  const [expandedFileIndex, setExpandedFileIndex] = useState<number | null>(null);

  const archive = analysis.archive_data || {
    archive_filename: analysis.filename,
    analyzed_at: analysis.analyzed_at,
    archive_sha256: analysis.sha256,
    archive_size: analysis.file_size,
    verdict: analysis.verdict,
    total_files: 0,
    scanned_files_count: 0,
    malicious_count: 0,
    suspicious_count: 0,
    clean_count: 0,
    unsupported_count: 0,
    error_count: 0,
    summary_notes: analysis.error || "",
    error: analysis.error || null,
    files: [],
  };

  const handleCopySha = () => {
    navigator.clipboard.writeText(analysis.sha256);
    setCopiedSha(true);
    toast.success("Archive SHA-256 hash copied to clipboard.");
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
    switch (archive.verdict) {
      case "MALICIOUS":
        return {
          bg: "bg-gradient-to-r from-[#9b2226] via-[#ae2012] to-[#bb3e03]",
          text: "text-white",
          border: "border-[#ae2012]",
          icon: AlertTriangle,
          label: "MALICIOUS ARCHIVE",
          subtext: "At least one executable inside this archive was classified as malicious malware.",
        };
      case "SUSPICIOUS":
        return {
          bg: "bg-gradient-to-r from-[#bb3e03] via-[#ca6702] to-[#ee9b00]",
          text: "text-white",
          border: "border-[#ee9b00]",
          icon: ShieldAlert,
          label: "SUSPICIOUS ARCHIVE",
          subtext: "No confirmed malicious binary, but one or more files exhibit elevated heuristic anomalies.",
        };
      case "INCONCLUSIVE":
        return {
          bg: "bg-gradient-to-r from-[#5c4d7d] via-[#6f5e8f] to-[#3d315b]",
          text: "text-white",
          border: "border-[#7c699f]",
          icon: AlertOctagon,
          label: "INCONCLUSIVE",
          subtext: archive.summary_notes || "Archive contains encrypted, corrupt, or unparseable members.",
        };
      case "NO_MALWARE_DETECTED":
      case "BENIGN":
      default:
        return {
          bg: "bg-gradient-to-r from-[#005f73] via-[#0a9396] to-[#94d2bd]",
          text: "text-white",
          border: "border-[#0a9396]",
          icon: ShieldCheck,
          label: "NO MALWARE DETECTED",
          subtext: "All supported executables were scanned and showed no malware patterns. Unsupported files disclosed below.",
        };
    }
  };

  const verdictStyle = getVerdictStyle();
  const VerdictIcon = verdictStyle.icon;

  const getFileVerdictBadge = (fileVerdict: string) => {
    switch (fileVerdict) {
      case "MALICIOUS":
        return "bg-[#ae2012]/15 text-[#ff6b6b] border-[#ae2012]/50";
      case "SUSPICIOUS":
        return "bg-[#ee9b00]/15 text-[#ee9b00] border-[#ee9b00]/50";
      case "BENIGN":
        return "bg-emerald-500/15 text-emerald-400 border-emerald-500/50";
      case "UNSUPPORTED":
        return "bg-[var(--accent-primary)]/15 text-[var(--accent-secondary)] border-[var(--accent-primary)]/40";
      case "INCONCLUSIVE":
      case "ERROR":
      default:
        return "bg-purple-500/15 text-purple-300 border-purple-500/40";
    }
  };

  // Filtered files list
  const filteredFiles = useMemo(() => {
    return (archive.files || []).filter((f) => {
      const matchesSearch =
        !searchTerm.trim() ||
        f.path.toLowerCase().includes(searchTerm.toLowerCase().trim());
      const matchesVerdict =
        verdictFilter === "ALL" || f.verdict === verdictFilter;
      return matchesSearch && matchesVerdict;
    });
  }, [archive.files, searchTerm, verdictFilter]);

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
          <span>Analyze Another Archive or Binary</span>
        </button>

        <span className="text-xs font-mono text-[var(--text-muted)]">
          Scan ID: {analysis.id.slice(0, 8)}...
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
                  Archive Threat Assessment
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-black/30 border border-white/20 uppercase font-bold">
                  ZIP ARCHIVE
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

      {/* Summary Stat Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="p-4 rounded-2xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)]">
          <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase block">
            Total Files
          </span>
          <span className="text-xl font-bold font-mono text-[var(--text-primary)]">
            {archive.total_files}
          </span>
        </div>

        <div className="p-4 rounded-2xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)]">
          <span className="text-[10px] font-mono text-[var(--text-muted)] uppercase block">
            PE Scanned
          </span>
          <span className="text-xl font-bold font-mono text-[var(--accent-primary)]">
            {archive.scanned_files_count}
          </span>
        </div>

        <div className="p-4 rounded-2xl border border-[#ae2012]/30 bg-[#ae2012]/5">
          <span className="text-[10px] font-mono text-[#ff6b6b] uppercase block">
            Malicious
          </span>
          <span className="text-xl font-bold font-mono text-[#ff6b6b]">
            {archive.malicious_count}
          </span>
        </div>

        <div className="p-4 rounded-2xl border border-[#ee9b00]/30 bg-[#ee9b00]/5">
          <span className="text-[10px] font-mono text-[#ee9b00] uppercase block">
            Suspicious
          </span>
          <span className="text-xl font-bold font-mono text-[#ee9b00]">
            {archive.suspicious_count}
          </span>
        </div>

        <div className="p-4 rounded-2xl border border-emerald-500/30 bg-emerald-500/5">
          <span className="text-[10px] font-mono text-emerald-400 uppercase block">
            Clean / Benign
          </span>
          <span className="text-xl font-bold font-mono text-emerald-400">
            {archive.clean_count}
          </span>
        </div>

        <div className="p-4 rounded-2xl border border-purple-500/30 bg-purple-500/5">
          <span className="text-[10px] font-mono text-purple-300 uppercase block">
            Unsupported / Error
          </span>
          <span className="text-xl font-bold font-mono text-purple-300">
            {archive.unsupported_count + archive.error_count}
          </span>
        </div>
      </div>

      {/* Archive Metadata & Cryptographic Identity */}
      <div className="rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] p-6 shadow-xl space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[var(--border-theme)]">
          <div className="flex items-center gap-2.5">
            <FolderArchive className="w-5 h-5 text-[var(--accent-primary)]" />
            <h3 className="text-base font-bold text-[var(--text-primary)]">
              Archive Specification & Hash
            </h3>
          </div>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-[var(--bg-surface-2)] text-[var(--text-muted)] border border-[var(--border-theme)]">
            ZIP Container
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-3.5 rounded-2xl bg-[var(--bg-surface-2)] border border-[var(--border-theme)]">
            <div className="flex items-center gap-2 text-xs font-mono text-[var(--text-muted)] mb-1">
              <FolderArchive className="w-3.5 h-3.5" />
              <span>Archive Filename</span>
            </div>
            <div className="text-sm font-semibold font-mono text-[var(--text-primary)] truncate" title={archive.archive_filename}>
              {archive.archive_filename}
            </div>
          </div>

          <div className="p-3.5 rounded-2xl bg-[var(--bg-surface-2)] border border-[var(--border-theme)]">
            <div className="flex items-center gap-2 text-xs font-mono text-[var(--text-muted)] mb-1">
              <HardDrive className="w-3.5 h-3.5" />
              <span>Archive Size</span>
            </div>
            <div className="text-sm font-semibold font-mono text-[var(--text-primary)]">
              {formatSize(archive.archive_size)} <span className="text-xs font-normal text-[var(--text-muted)]">({archive.archive_size.toLocaleString()} bytes)</span>
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
              {archive.archive_sha256}
            </div>
          </div>

          <div className="p-3.5 rounded-2xl bg-[var(--bg-surface-2)] border border-[var(--border-theme)] sm:col-span-2 lg:col-span-4">
            <div className="flex items-center gap-2 text-xs font-mono text-[var(--text-muted)] mb-1">
              <Clock className="w-3.5 h-3.5" />
              <span>Analyzed At</span>
            </div>
            <div className="text-xs font-semibold font-mono text-[var(--text-secondary)]">
              {formatDate(archive.analyzed_at)}
            </div>
          </div>
        </div>

        {/* Permanent Honest Disclosure Banner */}
        <div className="p-4 rounded-2xl border border-[var(--border-theme-strong)] bg-[var(--bg-surface-2)]/80 flex items-start gap-3">
          <Info className="w-5 h-5 text-[#ee9b00] shrink-0 mt-0.5" />
          <div className="space-y-1 text-xs text-[var(--text-secondary)] leading-relaxed">
            <p>
              <strong className="text-[var(--text-primary)]">Security Disclosure:</strong> A verdict of &quot;No malware detected&quot; confirms that zero tested Windows executables (.exe, .dll) matched trained malware features. It does <strong>not</strong> guarantee the archive is safe against unknown zero-days, script exploits, or non-PE payloads.
            </p>
            {archive.summary_notes && (
              <p className="font-mono text-[var(--text-primary)] pt-1 text-[11px]">
                {archive.summary_notes}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Archive Contents Inspection Table */}
      <div className="rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] shadow-xl overflow-hidden space-y-4 p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[var(--border-theme)]">
          <div>
            <h3 className="text-base font-bold text-[var(--text-primary)]">
              Archive Members ({archive.files.length})
            </h3>
            <p className="text-xs text-[var(--text-muted)]">
              Individual file-by-file results, nested path locations, and feature assessments
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-[var(--text-muted)]" />
              <input
                type="text"
                placeholder="Search archive path..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-8 pr-3 py-1.5 text-xs rounded-xl border border-[var(--border-theme)] bg-[var(--bg-surface-2)] text-[var(--text-primary)] outline-none focus:border-[var(--accent-primary)] font-mono"
              />
            </div>

            <div className="flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-[var(--text-muted)]" />
              <select
                value={verdictFilter}
                onChange={(e) => setVerdictFilter(e.target.value)}
                className="py-1.5 px-2.5 text-xs rounded-xl border border-[var(--border-theme)] bg-[var(--bg-surface-2)] text-[var(--text-primary)] outline-none focus:border-[var(--accent-primary)] cursor-pointer"
              >
                <option value="ALL">All Verdicts</option>
                <option value="MALICIOUS">Malicious Only</option>
                <option value="SUSPICIOUS">Suspicious Only</option>
                <option value="BENIGN">Benign Only</option>
                <option value="UNSUPPORTED">Unsupported Only</option>
                <option value="INCONCLUSIVE">Inconclusive / Errors</option>
              </select>
            </div>
          </div>
        </div>

        {/* Members List Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[var(--border-theme)] bg-[var(--bg-surface-2)] text-[var(--text-muted)] font-mono uppercase text-[10px]">
                <th className="py-3 px-4 font-semibold">Member Path</th>
                <th className="py-3 px-4 font-semibold">Size</th>
                <th className="py-3 px-4 font-semibold">Type</th>
                <th className="py-3 px-4 font-semibold">Verdict</th>
                <th className="py-3 px-4 font-semibold">Model Score</th>
                <th className="py-3 px-4 font-semibold text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-theme)]">
              {filteredFiles.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-xs text-[var(--text-muted)]">
                    No archive members found matching search filter.
                  </td>
                </tr>
              ) : (
                filteredFiles.map((file, idx) => {
                  const isExpanded = expandedFileIndex === idx;
                  const hasDetails = (file.indicators && file.indicators.length > 0) || file.error || file.sha256;

                  return (
                    <React.Fragment key={idx}>
                      <tr
                        onClick={() => hasDetails && setExpandedFileIndex(isExpanded ? null : idx)}
                        className={`transition-colors ${hasDetails ? "cursor-pointer hover:bg-[var(--bg-surface-2)]/60" : ""
                          }`}
                      >
                        <td className="py-3.5 px-4 font-mono font-medium text-[var(--text-primary)] flex items-center gap-2">
                          <FileCode className="w-4 h-4 text-[var(--text-muted)] shrink-0" />
                          <span className="truncate max-w-sm" title={file.path}>
                            {file.path}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 font-mono text-[var(--text-secondary)]">
                          {formatSize(file.size)}
                        </td>
                        <td className="py-3.5 px-4">
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--bg-surface-3)] text-[var(--text-secondary)] border border-[var(--border-theme)] uppercase">
                            {file.file_type}
                          </span>
                        </td>
                        <td className="py-3.5 px-4">
                          <span
                            className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border uppercase ${getFileVerdictBadge(
                              file.verdict
                            )}`}
                          >
                            {file.verdict}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 font-mono font-bold text-[var(--text-primary)]">
                          {typeof file.model_score === "number"
                            ? `${Math.round(file.model_score * 100)}%`
                            : "—"}
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          {hasDetails ? (
                            <button className="text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors p-1">
                              {isExpanded ? (
                                <ChevronUp className="w-4 h-4 inline" />
                              ) : (
                                <ChevronDown className="w-4 h-4 inline" />
                              )}
                            </button>
                          ) : (
                            <span className="text-[var(--text-muted)] text-[10px]">—</span>
                          )}
                        </td>
                      </tr>

                      {/* Expandable row */}
                      {isExpanded && (
                        <tr className="bg-[var(--bg-surface-2)]/80">
                          <td colSpan={6} className="p-4 space-y-3">
                            {file.sha256 && (
                              <div className="flex items-center gap-2 text-xs font-mono text-[var(--text-muted)]">
                                <Hash className="w-3.5 h-3.5 text-[var(--accent-primary)]" />
                                <span>SHA-256:</span>
                                <span className="text-[var(--text-primary)] select-all">
                                  {file.sha256}
                                </span>
                              </div>
                            )}

                            {file.error && (
                              <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-300 text-xs">
                                <strong>Inspection Note:</strong> {file.error}
                              </div>
                            )}

                            {file.indicators && file.indicators.length > 0 && (
                              <div className="space-y-2">
                                <span className="text-[10px] font-mono uppercase text-[var(--text-muted)] font-bold">
                                  Heuristic Indicators ({file.indicators.length})
                                </span>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                  {file.indicators.map((ind, i) => (
                                    <div
                                      key={i}
                                      className="p-2.5 rounded-xl bg-[var(--bg-surface-1)] border border-[var(--border-theme)] text-xs space-y-1"
                                    >
                                      <div className="flex items-center justify-between">
                                        <span className="font-bold text-[var(--text-primary)]">
                                          {ind.title}
                                        </span>
                                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded uppercase font-bold border border-[var(--border-theme)] text-[var(--accent-secondary)]">
                                          {ind.severity}
                                        </span>
                                      </div>
                                      <p className="text-[11px] text-[var(--text-muted)]">
                                        {ind.detail}
                                      </p>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
