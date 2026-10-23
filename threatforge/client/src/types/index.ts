export interface Indicator {
  severity: "low" | "medium" | "high" | "critical";
  title: string;
  detail: string;
}

export interface TopContributor {
  feature: string;
  impact: string;
  direction: string;
}

export type AnalysisVerdict =
  | "BENIGN"
  | "MALICIOUS"
  | "UNKNOWN"
  | "SUSPICIOUS"
  | "INCONCLUSIVE"
  | "NO_MALWARE_DETECTED";

export interface ArchiveFileRecord {
  path: string;
  size: number;
  file_type: string;
  supported: boolean;
  verdict: "BENIGN" | "MALICIOUS" | "SUSPICIOUS" | "INCONCLUSIVE" | "UNSUPPORTED" | "ERROR";
  model_score: number | null;
  threat_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";
  indicators: Indicator[];
  top_contributors: TopContributor[];
  error: string | null;
  sha256: string | null;
}

export interface ArchiveScanReport {
  archive_filename: string;
  analyzed_at: string;
  archive_sha256: string;
  archive_size: number;
  verdict: AnalysisVerdict;
  total_files: number;
  scanned_files_count: number;
  malicious_count: number;
  suspicious_count: number;
  clean_count: number;
  unsupported_count: number;
  error_count: number;
  summary_notes: string;
  error: string | null;
  files: ArchiveFileRecord[];
}

export interface AnalysisRecord {
  id: string;
  filename: string;
  sha256: string;
  file_size: number;
  analyzed_at: string;
  verdict: AnalysisVerdict;
  model_score: number;
  threat_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";
  features: Record<string, number>;
  indicators: Indicator[];
  top_contributors: TopContributor[];
  error?: string | null;
  file_type?: "pe" | "archive";
  archive_data?: ArchiveScanReport | null;
}

export interface AnalysisListResponse {
  items: AnalysisRecord[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export interface StatsResponse {
  total_scans: number;
  malicious_count: number;
  benign_count: number;
  unknown_count: number;
  detection_rate: number;
  scans_per_day: Array<{
    date: string;
    total: number;
    malicious: number;
    benign: number;
  }>;
  recent_scans: AnalysisRecord[];
}

/** @deprecated kept for backward compat — use AppTheme instead */
export type ThemeMode = "dark" | "light" | "system";
/** @deprecated kept for backward compat */
export type AccentPreset = "teal" | "amber" | "rust" | "sand";

export type AppTheme =
  | "ocean"    // Deep teal · dark
  | "crimson"  // Oxidized iron red · dark
  | "violet"   // Arcane purple · dark
  | "amber"    // Forge fire gold · dark
  | "jade"     // Emerald matrix · dark
  | "arctic"   // Ice precision · light
  | "sand";    // Warm parchment · light

export type NavigationTab = "scan" | "dashboard" | "history" | "about";
