import React, { useState } from "react";
import { ChevronDown, ChevronUp, Copy, Check, Search, Table } from "lucide-react";
import { toast } from "sonner";

interface FeatureTableProps {
  features: Record<string, number>;
}

const FEATURE_DESCRIPTIONS: Record<string, string> = {
  size: "Total physical binary byte size on disk.",
  vsize: "SizeOfImage declared in PE Optional Header (memory footprint).",
  imports: "Total count of imported API functions across all linked DLLs.",
  exports: "Total count of exported functions/symbols in the export directory.",
  has_debug: "Indicates presence of debug directory table (1 = Present, 0 = Stripped).",
  has_relocations: "Indicates presence of base relocation table for ASLR.",
  has_resources: "Indicates presence of PE resource directory (.rsrc).",
  has_signature: "Indicates presence of Authenticode security certificate directory.",
  numstrings: "Count of printable ASCII strings of length >= 4.",
  avlength: "Mean character length of extracted ASCII strings.",
  paths: "Count of strings containing local or UNC file system path markers.",
  urls: "Count of strings containing web URL indicators (http/https/www).",
  number_of_sections: "Total number of PE structural section headers.",
  section_entropy_mean: "Average Shannon entropy across all sections (0.0 to 8.0).",
  section_entropy_max: "Highest Shannon entropy observed in any section (>= 7.2 indicates packing).",
  section_raw_size_mean: "Average SizeOfRawData across sections.",
  section_raw_size_max: "Maximum SizeOfRawData among sections.",
  section_virtual_size_mean: "Average Misc_VirtualSize across sections.",
  section_virtual_size_max: "Maximum Misc_VirtualSize among sections.",
  coff_timestamp: "COFF TimeDateStamp representing binary link time in Unix epoch.",
  coff_characteristics_count: "Total bit count of active flags in COFF Characteristics.",
  sizeof_code: "Declared size of the executable code (.text) section.",
  sizeof_headers: "Total size of MS-DOS header, PE header, and section headers.",
  dll_characteristics_count: "Total bit count of active security flags in DllCharacteristics (DEP, ASLR).",
};

export const FeatureTable: React.FC<FeatureTableProps> = ({ features }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [filter, setFilter] = useState("");
  const [copied, setCopied] = useState(false);

  const featureKeys = Object.keys(features);

  const filteredKeys = featureKeys.filter((key) =>
    key.toLowerCase().includes(filter.toLowerCase())
  );

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(features, null, 2));
    setCopied(true);
    toast.success("All 24 feature values copied to clipboard as JSON.");
    setTimeout(() => setCopied(false), 2000);
  };

  const formatValue = (key: string, val: number) => {
    if (key.includes("entropy") || key === "avlength") {
      return val.toFixed(4);
    }
    if (Number.isInteger(val)) {
      return val.toLocaleString();
    }
    return val.toFixed(2);
  };

  return (
    <div className="rounded-3xl border border-[var(--border-theme)] bg-[var(--bg-surface-1)] shadow-xl overflow-hidden transition-all">
      {/* Header bar */}
      <div
        className="flex items-center justify-between p-5 cursor-pointer select-none bg-[var(--bg-surface-2)]/60 hover:bg-[var(--bg-surface-2)] transition-colors"
        onClick={() => setIsOpen(!isOpen)}
      >
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-[var(--accent-primary)]/15 text-[var(--accent-primary)]">
            <Table className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-[var(--text-primary)] flex items-center gap-2">
              Static Feature Vector (24 Dimensions)
              <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded-full bg-[var(--bg-surface-3)] text-[var(--text-secondary)]">
                {featureKeys.length} / 24
              </span>
            </h3>
            <p className="text-xs text-[var(--text-muted)]">
              Structural characteristics extracted via in-memory PE parser
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {isOpen ? (
            <ChevronUp className="w-5 h-5 text-[var(--text-muted)]" />
          ) : (
            <ChevronDown className="w-5 h-5 text-[var(--text-muted)]" />
          )}
        </div>
      </div>

      {/* Collapsible Content */}
      {isOpen && (
        <div className="p-5 border-t border-[var(--border-theme)] space-y-4 animate-in fade-in duration-200">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="relative w-full sm:w-72">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-[var(--text-muted)]" />
              <input
                type="text"
                placeholder="Search features..."
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs rounded-xl border border-[var(--border-theme)] bg-[var(--bg-surface-2)] text-[var(--text-primary)] placeholder-[var(--text-muted)] outline-none focus:border-[var(--accent-primary)]"
              />
            </div>

            <button
              onClick={handleCopyJson}
              className="flex items-center gap-2 px-3 py-1.5 text-xs rounded-xl border border-[var(--border-theme)] bg-[var(--bg-surface-2)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--accent-primary)] transition-colors cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? "Copied" : "Copy Features JSON"}</span>
            </button>
          </div>

          <div className="rounded-2xl border border-[var(--border-theme)] overflow-hidden overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-[var(--border-theme)] bg-[var(--bg-surface-2)] text-[var(--text-muted)] font-mono uppercase text-[10px]">
                  <th className="py-2.5 px-4 font-semibold">Feature Dimension</th>
                  <th className="py-2.5 px-4 font-semibold text-right">Value</th>
                  <th className="py-2.5 px-4 font-semibold hidden md:table-cell">Technical Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-theme)]">
                {filteredKeys.length === 0 ? (
                  <tr>
                    <td colSpan={3} className="py-6 text-center text-[var(--text-muted)]">
                      No matching feature found.
                    </td>
                  </tr>
                ) : (
                  filteredKeys.map((key) => {
                    const val = features[key];
                    const desc = FEATURE_DESCRIPTIONS[key] || "Extracted structural PE metric.";

                    return (
                      <tr
                        key={key}
                        className="hover:bg-[var(--bg-surface-2)]/50 transition-colors group"
                      >
                        <td className="py-2.5 px-4 font-mono font-medium text-[var(--text-primary)] group-hover:text-[var(--accent-primary)]">
                          {key}
                        </td>
                        <td className="py-2.5 px-4 font-mono font-bold text-right text-[var(--text-secondary)]">
                          {formatValue(key, val)}
                        </td>
                        <td className="py-2.5 px-4 text-[var(--text-muted)] hidden md:table-cell">
                          {desc}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
