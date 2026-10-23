import React from "react";
import {
  Cpu,
  Layers,
  Database,
  ShieldAlert,
  ArrowRight,
  CheckCircle2,
  FileCode,
  Network,
  Info,
} from "lucide-react";

export const AboutPage: React.FC = () => {
  const pipelineSteps = [
    {
      title: "1. Upload & Client Validation",
      desc: "User selects Windows binary (.exe / .dll). File size is validated (<= 50 MB) in-browser.",
      icon: FileCode,
    },
    {
      title: "2. Gateway Ingestion",
      desc: "Node/Express gateway validates MZ magic bytes (4D 5A) and computes SHA-256. Binary resides purely in memory.",
      icon: Network,
    },
    {
      title: "3. In-Memory PE Extraction",
      desc: "Python microservice parses sections, headers, and strings with pefile.PE(data=...), yielding 24 feature metrics.",
      icon: Layers,
    },
    {
      title: "4. Random Forest Inference",
      desc: "Trained on EMBER 2018. Evaluates decision ensembles to calculate verdict and model confidence score.",
      icon: Cpu,
    },
    {
      title: "5. SQLite Logging & Result",
      desc: "Analysis metadata, SHA-256, score, and feature vector are stored in SQLite. Executable is immediately discarded.",
      icon: Database,
    },
  ];

  return (
    <div className="w-full max-w-5xl mx-auto py-6 md:py-10 px-4 space-y-10">
      {/* Title */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono font-medium border border-[var(--border-theme-strong)] bg-[var(--bg-surface-2)] text-[var(--accent-secondary)]">
          <Info className="w-3.5 h-3.5 text-[#ee9b00]" />
          <span>System Architecture & Engineering Specification</span>
        </div>
        <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-[var(--text-primary)]">
          How ThreatForge Evaluates Binaries
        </h1>
        <p className="max-w-2xl mx-auto text-xs md:text-sm text-[var(--text-muted)] leading-relaxed">
          A high-throughput, zero-execution static analysis architecture designed for fast triage of Windows PE executables.
        </p>
      </div>

      {/* Interactive Pipeline Diagram */}
      <div className="rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] p-6 md:p-8 shadow-xl space-y-6">
        <h3 className="text-base font-bold text-[var(--text-primary)] flex items-center gap-2">
          <Layers className="w-5 h-5 text-[var(--accent-primary)]" />
          End-to-End Processing Pipeline
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3 relative">
          {pipelineSteps.map((step, idx) => {
            const Icon = step.icon;
            return (
              <div
                key={idx}
                className="p-4 rounded-2xl bg-[var(--bg-surface-2)] border border-[var(--border-theme)] space-y-2 relative group hover:border-[var(--accent-primary)] transition-all"
              >
                <div className="flex items-center justify-between">
                  <div className="p-2 rounded-xl bg-[var(--accent-primary)]/15 text-[var(--accent-primary)]">
                    <Icon className="w-4 h-4" />
                  </div>
                  {idx < pipelineSteps.length - 1 && (
                    <ArrowRight className="hidden md:block w-4 h-4 text-[var(--text-muted)] -mr-5 z-10" />
                  )}
                </div>
                <h4 className="text-xs font-bold text-[var(--text-primary)] mt-1">
                  {step.title}
                </h4>
                <p className="text-[11px] text-[var(--text-muted)] leading-relaxed">
                  {step.desc}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Model & Dataset Details */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Model Card */}
        <div className="rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-[var(--border-theme)]">
            <Cpu className="w-5 h-5 text-[#ee9b00]" />
            <h3 className="text-base font-bold text-[var(--text-primary)]">
              Model & Dataset Architecture
            </h3>
          </div>

          <div className="space-y-3 text-xs text-[var(--text-secondary)] leading-relaxed">
            <p>
              The classification core utilizes a <strong>scikit-learn Random Forest Classifier</strong> trained against the benchmark <strong>EMBER 2018 (Elastic Malware Benchmark for Empowering Researchers)</strong> dataset.
            </p>
            <div className="p-3.5 rounded-2xl bg-[var(--bg-surface-2)] border border-[var(--border-theme)] space-y-2 font-mono text-[11px]">
              <div className="flex justify-between">
                <span className="text-[var(--text-muted)]">Model Architecture:</span>
                <span className="font-bold text-[var(--text-primary)]">RandomForestClassifier</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--text-muted)]">Feature Dimensions:</span>
                <span className="font-bold text-[var(--text-primary)]">24 PE Metrics</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--text-muted)]">Reported Accuracy:</span>
                <span className="font-bold text-emerald-400">~97% Test Accuracy</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--text-muted)]">Reported ROC-AUC:</span>
                <span className="font-bold text-emerald-400">0.996</span>
              </div>
            </div>
            <p className="text-[11px] text-[var(--text-muted)]">
              Features evaluate binary volume, memory footprints, API linkage density, header bitmasks, ASCII strings, and section Shannon entropies.
            </p>
          </div>
        </div>

        {/* Limitations & Caveats */}
        <div className="rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] p-6 shadow-xl space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-[var(--border-theme)] text-amber-500">
            <ShieldAlert className="w-5 h-5" />
            <h3 className="text-base font-bold text-[var(--text-primary)]">
              Engineering Limitations
            </h3>
          </div>

          <div className="space-y-3 text-xs text-[var(--text-secondary)] leading-relaxed">
            <div className="flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-[#ee9b00] shrink-0 mt-0.5" />
              <div>
                <strong className="text-[var(--text-primary)]">Static Analysis Only:</strong>
                <p className="text-[11px] text-[var(--text-muted)] mt-0.5">
                  Uploaded files are never executed. Dynamic API hooks, network beacons, and runtime memory injections cannot be observed directly.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-[#ee9b00] shrink-0 mt-0.5" />
              <div>
                <strong className="text-[var(--text-primary)]">Approximated Feature Space:</strong>
                <p className="text-[11px] text-[var(--text-muted)] mt-0.5">
                  Real-file features are extracted using Python’s <code className="font-mono text-[10px]">pefile</code>, which approximates EMBER's Rust/LIEF string and entropy definitions.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-2.5">
              <CheckCircle2 className="w-4 h-4 text-[#ee9b00] shrink-0 mt-0.5" />
              <div>
                <strong className="text-[var(--text-primary)]">Scores are Not Calibrated Probabilities:</strong>
                <p className="text-[11px] text-[var(--text-muted)] mt-0.5">
                  The model score reflects tree ensemble agreement, not a true Bayesian posterior. Treat the output as a strong diagnostic heuristic, not an infallible verdict.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
