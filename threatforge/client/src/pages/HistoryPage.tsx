import React, { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Search,
  Filter,
  Trash2,
  Download,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  ArrowUpDown,
  FileCode,
  FolderArchive,
  Shield,
  X,
} from "lucide-react";
import { toast } from "sonner";
import { getAnalyses, deleteAnalysis, clearAllAnalyses } from "../api/client";
import { useAppStore } from "../store/useAppStore";
import { AnalysisRecord } from "../types";

export const HistoryPage: React.FC = () => {
  const queryClient = useQueryClient();
  const { setCurrentAnalysis, setActiveTab } = useAppStore();

  const [search, setSearch] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("ALL");
  const [sortOrder, setSortOrder] = useState<"date_desc" | "date_asc" | "score_desc" | "score_asc">("date_desc");
  const [page, setPage] = useState(1);
  const [confirmClearOpen, setConfirmClearOpen] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ["analyses", { search, verdict: verdictFilter, sort: sortOrder, page }],
    queryFn: () =>
      getAnalyses({
        search,
        verdict: verdictFilter,
        sort: sortOrder,
        page,
        limit: 10,
      }),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteAnalysis(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["analyses"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
      toast.success("Analysis record deleted.");
    },
    onError: () => {
      toast.error("Failed to delete record.");
    },
  });

  const clearAllMutation = useMutation({
    mutationFn: clearAllAnalyses,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["analyses"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
      setConfirmClearOpen(false);
      toast.success("All scan history cleared.");
    },
    onError: () => {
      toast.error("Failed to clear history.");
    },
  });

  const handleExportCsv = () => {
    if (!data || data.items.length === 0) {
      toast.warning("No records available to export.");
      return;
    }

    const headers = ["ID", "Filename", "SHA256", "Size_Bytes", "Verdict", "Model_Score", "Threat_Level", "Analyzed_At"];
    const rows = data.items.map((r) => [
      r.id,
      `"${r.filename.replace(/"/g, '""')}"`,
      r.sha256,
      r.file_size,
      r.verdict,
      r.model_score,
      r.threat_level,
      r.analyzed_at,
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((e) => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `threatforge_export_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast.success("CSV export downloaded successfully.");
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const handleRowClick = (analysis: AnalysisRecord) => {
    setCurrentAnalysis(analysis);
    setActiveTab("scan");
  };

  return (
    <div className="w-full max-w-6xl mx-auto py-6 md:py-10 px-4 space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-[var(--text-primary)]">
            Scan History
          </h1>
          <p className="text-xs md:text-sm text-[var(--text-muted)]">
            Permanent SQLite log of analyzed PE binaries and structural assessments
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-2 px-3.5 py-2 text-xs rounded-xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--accent-primary)] transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>

          <button
            onClick={() => setConfirmClearOpen(true)}
            className="flex items-center gap-2 px-3.5 py-2 text-xs rounded-xl border border-rose-500/20 bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 transition-colors cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear History</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-3.5 rounded-2xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)]">
        {/* Search */}
        <div className="relative sm:col-span-2">
          <Search className="w-4 h-4 absolute left-3 top-3 text-[var(--text-muted)]" />
          <input
            type="text"
            placeholder="Search by binary name or SHA-256 hash..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
            className="w-full pl-9 pr-3 py-2 text-xs rounded-xl border border-[var(--border-theme)] bg-[var(--bg-surface-2)] text-[var(--text-primary)] placeholder-[var(--text-muted)] outline-none focus:border-[var(--accent-primary)] font-mono"
          />
        </div>

        {/* Verdict Filter */}
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-[var(--text-muted)] shrink-0" />
          <select
            value={verdictFilter}
            onChange={(e) => {
              setVerdictFilter(e.target.value);
              setPage(1);
            }}
            className="w-full py-2 px-3 text-xs rounded-xl border border-[var(--border-theme)] bg-[var(--bg-surface-2)] text-[var(--text-primary)] outline-none cursor-pointer focus:border-[var(--accent-primary)]"
          >
            <option value="ALL">All Verdicts</option>
            <option value="MALICIOUS">Malicious Only</option>
            <option value="SUSPICIOUS">Suspicious Only</option>
            <option value="BENIGN">Benign Only</option>
            <option value="NO_MALWARE_DETECTED">No Malware Detected</option>
            <option value="INCONCLUSIVE">Inconclusive / Corrupted</option>
          </select>
        </div>
      </div>

      {/* Table Card */}
      <div className="rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] shadow-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[var(--border-theme)] bg-[var(--bg-surface-2)] text-[var(--text-muted)] font-mono uppercase text-[10px]">
                <th className="py-3 px-4 font-semibold">Executable</th>
                <th className="py-3 px-4 font-semibold">SHA-256 Hash</th>
                <th className="py-3 px-4 font-semibold">Size</th>
                <th className="py-3 px-4 font-semibold">Verdict</th>
                <th
                  className="py-3 px-4 font-semibold cursor-pointer select-none hover:text-[var(--text-primary)]"
                  onClick={() =>
                    setSortOrder(sortOrder === "score_desc" ? "score_asc" : "score_desc")
                  }
                >
                  <div className="flex items-center gap-1">
                    <span>Model Score</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th
                  className="py-3 px-4 font-semibold cursor-pointer select-none hover:text-[var(--text-primary)]"
                  onClick={() =>
                    setSortOrder(sortOrder === "date_desc" ? "date_asc" : "date_desc")
                  }
                >
                  <div className="flex items-center gap-1">
                    <span>Timestamp</span>
                    <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-theme)]">
              {isLoading ? (
                [...Array(5)].map((_, i) => (
                  <tr key={i}>
                    <td colSpan={7} className="py-4 px-4">
                      <div className="h-6 bg-[var(--bg-surface-2)] rounded-lg animate-pulse" />
                    </td>
                  </tr>
                ))
              ) : !data || data.items.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-xs text-[var(--text-muted)]">
                    <Shield className="w-8 h-8 text-[var(--text-muted)] mx-auto mb-2 opacity-50" />
                    No analysis records found matching criteria.
                  </td>
                </tr>
              ) : (
                data.items.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => handleRowClick(row)}
                    className="hover:bg-[var(--bg-surface-2)]/60 transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4 font-mono font-medium text-[var(--text-primary)] group-hover:text-[var(--accent-primary)] flex items-center gap-2">
                      {row.file_type === "archive" ? (
                        <FolderArchive className="w-4 h-4 text-[#ee9b00] shrink-0" />
                      ) : (
                        <FileCode className="w-4 h-4 text-[var(--text-muted)] shrink-0" />
                      )}
                      <span className="truncate max-w-[160px] md:max-w-xs">{row.filename}</span>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[var(--text-muted)] select-all">
                      {row.sha256.slice(0, 12)}...
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[var(--text-secondary)]">
                      {formatSize(row.file_size)}
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border uppercase ${
                          row.verdict === "MALICIOUS"
                            ? "bg-[#ae2012]/15 text-[#ff6b6b] border-[#ae2012]"
                            : row.verdict === "SUSPICIOUS"
                            ? "bg-[#ee9b00]/15 text-[#ee9b00] border-[#ee9b00]"
                            : row.verdict === "BENIGN" || row.verdict === "NO_MALWARE_DETECTED"
                            ? "bg-emerald-500/15 text-emerald-400 border-emerald-500"
                            : "bg-[var(--bg-surface-3)] text-[var(--text-muted)] border-[var(--border-theme)]"
                        }`}
                      >
                        {row.verdict === "NO_MALWARE_DETECTED" ? "NO MALWARE" : row.verdict}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-mono font-bold text-[var(--text-primary)]">
                      {row.verdict === "UNKNOWN" ? "—" : `${Math.round(row.model_score * 100)}%`}
                    </td>
                    <td className="py-3.5 px-4 text-[var(--text-muted)] font-mono text-[11px]">
                      {new Date(row.analyzed_at).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          deleteMutation.mutate(row.id);
                        }}
                        className="p-1.5 rounded-lg text-[var(--text-muted)] hover:text-rose-400 hover:bg-rose-500/10 transition-colors cursor-pointer"
                        title="Delete Record"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {data && data.totalPages > 1 && (
          <div className="flex items-center justify-between p-4 border-t border-[var(--border-theme)] bg-[var(--bg-surface-2)]/40 text-xs">
            <span className="text-[var(--text-muted)] font-mono">
              Page {data.page} of {data.totalPages} ({data.total} records)
            </span>
            <div className="flex items-center gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                className="p-1.5 rounded-lg border border-[var(--border-theme)] bg-[var(--bg-surface-1)] disabled:opacity-30 disabled:cursor-not-allowed hover:bg-[var(--bg-surface-3)] text-[var(--text-primary)] transition-colors cursor-pointer"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                disabled={page >= data.totalPages}
                onClick={() => setPage((p) => p + 1)}
                className="p-1.5 rounded-lg border border-[var(--border-theme)] bg-[var(--bg-surface-1)] disabled:opacity-30 disabled:cursor-not-allowed hover:bg-[var(--bg-surface-3)] text-[var(--text-primary)] transition-colors cursor-pointer"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Clear All Confirmation Modal Dialog */}
      {confirmClearOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="w-full max-w-md rounded-3xl border border-[var(--border-theme-strong)] bg-[var(--bg-surface-2)] p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-rose-500">
                <AlertTriangle className="w-5 h-5" />
                <h3 className="text-base font-bold text-[var(--text-primary)]">
                  Clear All History?
                </h3>
              </div>
              <button
                onClick={() => setConfirmClearOpen(false)}
                className="p-1 rounded-lg text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-surface-3)] transition-colors cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-[var(--text-muted)] leading-relaxed">
              This action will permanently delete all analysis results and cryptographic hashes from the SQLite database. This cannot be undone.
            </p>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setConfirmClearOpen(false)}
                className="px-4 py-2 text-xs rounded-xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() => clearAllMutation.mutate()}
                className="px-4 py-2 text-xs rounded-xl bg-rose-600 text-white hover:bg-rose-700 transition-colors cursor-pointer font-medium shadow-md shadow-rose-600/20"
              >
                Yes, Clear Everything
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
