import React, { useEffect, useState } from "react";
import { Cpu, FileSearch, ShieldCheck, Binary, Sparkles, FolderArchive, ShieldAlert } from "lucide-react";

interface StagedScannerProps {
  fileName: string;
  fileSize: number;
  isArchive?: boolean;
}

export const StagedScanner: React.FC<StagedScannerProps> = ({ fileName, fileSize, isArchive = false }) => {
  const [currentStep, setCurrentStep] = useState(0);

  const peSteps = [
    { label: "Verifying MZ header & hashing bytes", icon: Binary, detail: "Validating PE magic signature (4D 5A) and calculating SHA-256..." },
    { label: "Parsing PE structural directories", icon: FileSearch, detail: "Reading sections, export/import address tables, and headers in-memory..." },
    { label: "Extracting 24 static feature dimensions", icon: Cpu, detail: "Calculating section Shannon entropies, raw/virtual sizes, and ASCII strings..." },
    { label: "Querying EMBER Random Forest model", icon: Sparkles, detail: "Evaluating tree ensembles across trained decision paths..." },
    { label: "Synthesizing threat assessment", icon: ShieldCheck, detail: "Determining verdict, uncalibrated score, and heuristic indicators..." },
  ];

  const archiveSteps = [
    { label: "Inspecting archive headers & central directory", icon: FolderArchive, detail: "Validating ZIP magic signatures (50 4B), CRC32, and compression types..." },
    { label: "Enforcing security limits & Zip Slip checks", icon: ShieldAlert, detail: "Checking canonical path boundaries, bomb compression ratios, and file counts..." },
    { label: "Safely unpacking targets in isolated workspace", icon: FileSearch, detail: "Discovering PE binaries (.exe, .dll) across nested archive directories..." },
    { label: "Extracting 24-feature vectors with PE engine", icon: Cpu, detail: "Evaluating section entropies and headers for all discovered executables..." },
    { label: "Synthesizing comprehensive archive report", icon: ShieldCheck, detail: "Compiling file-by-file verdicts, disclosures, and aggregate threat risk..." },
  ];

  const steps = isArchive ? archiveSteps : peSteps;

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentStep((prev) => (prev < steps.length - 1 ? prev + 1 : prev));
    }, 650);
    return () => clearInterval(timer);
  }, [steps.length]);

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="w-full max-w-2xl mx-auto rounded-3xl border border-[var(--border-theme-strong)] bg-[var(--bg-surface-2)] p-6 md:p-8 shadow-2xl relative overflow-hidden backdrop-blur-xl">
      {/* Animated laser scanning line */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden opacity-30">
        <div className="w-full h-1 bg-gradient-to-r from-transparent via-[var(--accent-primary)] to-transparent animate-scanline blur-[1px]" />
      </div>

      {/* Target File Overview */}
      <div className="flex items-center justify-between pb-6 border-b border-[var(--border-theme)] mb-6">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-widest text-[var(--accent-primary)] font-bold">
            {isArchive ? "Archive Inspection In Progress" : "PE Analysis In Progress"}
          </span>
          <h3 className="text-lg font-bold text-[var(--text-primary)] font-mono truncate max-w-sm">
            {fileName}
          </h3>
        </div>
        <div className="text-right">
          <span className="text-xs font-mono text-[var(--text-muted)] block">Size</span>
          <span className="text-sm font-mono text-[var(--text-secondary)] font-medium">
            {formatSize(fileSize)}
          </span>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="w-full h-2 rounded-full bg-[var(--bg-surface-3)] overflow-hidden mb-6 relative">
        <div
          className="h-full bg-gradient-to-r from-[var(--accent-primary)] to-[var(--accent-secondary)] transition-all duration-500 rounded-full"
          style={{ width: `${((currentStep + 1) / steps.length) * 100}%` }}
        />
      </div>

      {/* Steps List */}
      <div className="space-y-4">
        {steps.map((step, idx) => {
          const Icon = step.icon;
          const isDone = idx < currentStep;
          const isCurrent = idx === currentStep;

          return (
            <div
              key={idx}
              className={`flex items-start gap-4 p-3 rounded-2xl transition-all duration-300 ${
                isCurrent
                  ? "bg-[var(--accent-primary)]/10 border border-[var(--border-theme-strong)] translate-x-1"
                  : isDone
                  ? "opacity-80"
                  : "opacity-35"
              }`}
            >
              <div
                className={`p-2 rounded-xl mt-0.5 transition-colors ${
                  isCurrent
                    ? "bg-[var(--accent-primary)] text-white shadow-md shadow-[var(--accent-primary)]/30 animate-pulse"
                    : isDone
                    ? "bg-emerald-500/20 text-emerald-400"
                    : "bg-[var(--bg-surface-3)] text-[var(--text-muted)]"
                }`}
              >
                <Icon className="w-4 h-4" />
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h4
                    className={`text-sm font-medium ${
                      isCurrent
                        ? "text-[var(--text-primary)] font-semibold"
                        : isDone
                        ? "text-[var(--text-secondary)]"
                        : "text-[var(--text-muted)]"
                    }`}
                  >
                    {step.label}
                  </h4>
                  {isCurrent && (
                    <span className="text-[10px] font-mono text-[var(--accent-secondary)] animate-pulse uppercase">
                      Running...
                    </span>
                  )}
                  {isDone && (
                    <span className="text-[10px] font-mono text-emerald-400 uppercase">
                      Completed
                    </span>
                  )}
                </div>
                <p className="text-xs text-[var(--text-muted)] mt-0.5 leading-relaxed">
                  {step.detail}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
