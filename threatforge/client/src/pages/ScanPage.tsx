import React, { useState, useCallback } from "react";
import { useDropzone } from "react-dropzone";
import { UploadCloud, ShieldAlert, FileCode2, Lock, Cpu, Sparkles, CheckCircle2, FolderArchive } from "lucide-react";
import { toast } from "sonner";
import { analyzeFile } from "../api/client";
import { useAppStore } from "../store/useAppStore";
import { StagedScanner } from "../components/scan/StagedScanner";

export const ScanPage: React.FC = () => {
  const { setCurrentAnalysis } = useAppStore();
  const [analyzingFile, setAnalyzingFile] = useState<{ name: string; size: number; isArchive: boolean } | null>(null);

  const onDrop = useCallback(
    async (acceptedFiles: File[], fileRejections: any[]) => {
      if (fileRejections.length > 0) {
        const error = fileRejections[0].errors[0];
        if (error.code === "file-too-large") {
          toast.error("File exceeds maximum allowable size (50 MB).");
        } else {
          toast.error("Invalid file: Only Windows executables (.exe, .dll) and ZIP archives (.zip) are allowed.");
        }
        return;
      }

      if (acceptedFiles.length === 0) return;

      const file = acceptedFiles[0];
      const ext = file.name.toLowerCase().split(".").pop();
      if (ext !== "exe" && ext !== "dll" && ext !== "zip") {
        toast.error("Only .exe, .dll, or .zip archives can be analyzed.");
        return;
      }

      const isArchive = ext === "zip";
      setAnalyzingFile({ name: file.name, size: file.size, isArchive });

      try {
        const result = await analyzeFile(file);
        if (result.verdict === "MALICIOUS") {
          toast.error(
            isArchive
              ? "Malicious executables detected inside archive!"
              : `Malicious indicators detected! Model score: ${Math.round(result.model_score * 100)}%`
          );
        } else if (result.verdict === "SUSPICIOUS") {
          toast.warning("Suspicious characteristics or elevated anomaly score detected.");
        } else if (result.verdict === "INCONCLUSIVE" || result.verdict === "UNKNOWN") {
          toast.warning(result.error || "Analysis incomplete: Non-PE or corrupted binary/archive.");
        } else if (result.verdict === "NO_MALWARE_DETECTED") {
          toast.success("No malware detected in scanned files (unsupported files disclosed).");
        } else {
          toast.success("Binary classified as Benign.");
        }
        setCurrentAnalysis(result);
      } catch (err: any) {
        toast.error(err.message || "Failed to analyze file");
      } finally {
        setAnalyzingFile(null);
      }
    },
    [setCurrentAnalysis]
  );

  const { getRootProps, getInputProps, isDragActive, isDragReject } = useDropzone({
    onDrop,
    maxFiles: 1,
    maxSize: 50 * 1024 * 1024,
    accept: {
      "application/x-msdownload": [".exe", ".dll"],
      "application/octet-stream": [".exe", ".dll"],
      "application/zip": [".zip"],
      "application/x-zip-compressed": [".zip"],
    },
  });

  return (
    <div className="w-full max-w-5xl mx-auto py-6 md:py-10 px-4">
      {analyzingFile ? (
        <StagedScanner
          fileName={analyzingFile.name}
          fileSize={analyzingFile.size}
          isArchive={analyzingFile.isArchive}
        />
      ) : (
        <div className="space-y-10">
          {/* Hero Section */}
          <div className="text-center space-y-3 relative">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono font-medium border border-[var(--border-theme-strong)] bg-[var(--bg-surface-2)] text-[var(--accent-secondary)] shadow-sm">
              <Sparkles className="w-3.5 h-3.5 text-[#ee9b00]" />
              <span>Static PE & Safe ZIP Archive ML Engine</span>
            </div>
            <h1 className="text-3xl md:text-5xl font-extrabold tracking-tight text-[var(--text-primary)]">
              Inspect Windows Binaries & Archives for <br className="hidden sm:inline" />
              <span className="bg-gradient-to-r from-[var(--accent-primary)] via-[var(--accent-secondary)] to-[#ee9b00] bg-clip-text text-transparent">
                Malicious Characteristics
              </span>
            </h1>
            <p className="max-w-2xl mx-auto text-sm md:text-base text-[var(--text-secondary)] leading-relaxed">
              Upload standalone <code className="font-mono text-xs px-1.5 py-0.5 rounded bg-[var(--bg-surface-2)] border border-[var(--border-theme)] text-[var(--text-primary)]">.exe</code>, <code className="font-mono text-xs px-1.5 py-0.5 rounded bg-[var(--bg-surface-2)] border border-[var(--border-theme)] text-[var(--text-primary)]">.dll</code> files or compressed <code className="font-mono text-xs px-1.5 py-0.5 rounded bg-[var(--bg-surface-2)] border border-[var(--border-theme)] text-[var(--text-primary)]">.zip</code> archives. Our pipeline safely inspects archives with Zip Slip protection, extracts 24 PE structural dimensions without execution, and evaluates them against the EMBER 2018 Random Forest model.
            </p>
          </div>

          {/* Drag & Drop Zone */}
          <div
            {...getRootProps()}
            className={`relative group rounded-3xl border-2 border-dashed p-8 md:p-14 text-center cursor-pointer transition-all duration-300 backdrop-blur-xl ${
              isDragReject
                ? "border-rose-500 bg-rose-500/10"
                : isDragActive
                ? "border-[var(--accent-primary)] bg-[var(--accent-primary)]/10 scale-[1.01] shadow-2xl shadow-[var(--accent-glow)]"
                : "border-[var(--border-theme-strong)] bg-[var(--bg-surface-1)] hover:border-[var(--accent-primary)] hover:bg-[var(--bg-surface-2)] shadow-xl"
            }`}
          >
            <input {...getInputProps()} />

            <div className="flex flex-col items-center justify-center space-y-4">
              <div className="relative">
                <div className="w-20 h-20 rounded-2xl bg-gradient-to-tr from-[var(--bg-surface-2)] to-[var(--bg-surface-3)] border border-[var(--border-theme)] flex items-center justify-center shadow-lg group-hover:scale-110 transition-transform">
                  <UploadCloud className="w-10 h-10 text-[var(--accent-primary)]" />
                </div>
                <div className="absolute -top-1 -right-1 w-7 h-7 rounded-full bg-[#ee9b00] flex items-center justify-center text-[#001219] font-bold text-[11px] shadow-md font-mono">
                  PE+ZIP
                </div>
              </div>

              <div className="space-y-1.5">
                <h3 className="text-lg md:text-xl font-bold text-[var(--text-primary)]">
                  {isDragActive
                    ? "Release to analyze binary or archive"
                    : "Drag & drop binary or ZIP archive here, or click to browse"}
                </h3>
                <p className="text-xs md:text-sm text-[var(--text-muted)]">
                  Supported formats: Windows Portable Executables (<span className="font-mono text-[var(--text-secondary)]">.exe</span>, <span className="font-mono text-[var(--text-secondary)]">.dll</span>) & Compressed Archives (<span className="font-mono text-[var(--text-secondary)]">.zip</span>) up to 50 MB
                </p>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                <span className="inline-flex items-center gap-1.5 text-xs font-mono text-[var(--text-secondary)] px-2.5 py-1 rounded-lg bg-[var(--bg-surface-2)] border border-[var(--border-theme)]">
                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                  Isolated Volatile Workspace
                </span>
                <span className="inline-flex items-center gap-1.5 text-xs font-mono text-[var(--text-secondary)] px-2.5 py-1 rounded-lg bg-[var(--bg-surface-2)] border border-[var(--border-theme)]">
                  <FolderArchive className="w-3.5 h-3.5 text-[var(--accent-primary)]" />
                  Zip Slip & Bomb Protection
                </span>
                <span className="inline-flex items-center gap-1.5 text-xs font-mono text-[var(--text-secondary)] px-2.5 py-1 rounded-lg bg-[var(--bg-surface-2)] border border-[var(--border-theme)]">
                  <CheckCircle2 className="w-3.5 h-3.5 text-[#ee9b00]" />
                  Zero Code Execution
                </span>
              </div>
            </div>
          </div>

          {/* Bento Feature Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
            <div className="p-5 rounded-2xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] space-y-2">
              <div className="w-9 h-9 rounded-xl bg-[var(--accent-primary)]/15 text-[var(--accent-primary)] flex items-center justify-center">
                <ShieldAlert className="w-5 h-5" />
              </div>
              <h4 className="text-sm font-semibold text-[var(--text-primary)]">Safe Archive Inspection</h4>
              <p className="text-xs text-[var(--text-muted)] leading-relaxed">
                Inspects ZIP archives before extraction. Detects Zip Slip path traversal attacks, compression ratio bombs, recursion limits, and password locks.
              </p>
            </div>

            <div className="p-5 rounded-2xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] space-y-2">
              <div className="w-9 h-9 rounded-xl bg-[#ee9b00]/15 text-[#ee9b00] flex items-center justify-center">
                <Cpu className="w-5 h-5" />
              </div>
              <h4 className="text-sm font-semibold text-[var(--text-primary)]">EMBER Random Forest Model</h4>
              <p className="text-xs text-[var(--text-muted)] leading-relaxed">
                Trained on real-world Windows malware datasets. Every discovered PE target is vectorized across 24 structural dimensions and evaluated.
              </p>
            </div>

            <div className="p-5 rounded-2xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] space-y-2">
              <div className="w-9 h-9 rounded-xl bg-emerald-500/15 text-emerald-400 flex items-center justify-center">
                <FileCode2 className="w-5 h-5" />
              </div>
              <h4 className="text-sm font-semibold text-[var(--text-primary)]">Honest & Secure Reporting</h4>
              <p className="text-xs text-[var(--text-muted)] leading-relaxed">
                Unsupported file types are clearly disclosed rather than labeled clean. Temporary files are wiped immediately even on scan failures.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
