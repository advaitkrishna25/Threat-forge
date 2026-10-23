# ThreatForge / GuardForge

**Static PE & Secure ZIP Archive Malware Analyzer** — An end-to-end, zero-execution binary intelligence platform powered by an EMBER 2018 Random Forest classifier.

---

## Architecture Overview

```
threatforge/
├── client/          React 19 + Vite + Tailwind v4 frontend
├── server/          Node.js 20 + Express gateway (TypeScript)
└── ml-service/      Python Flask ML microservice (pefile + scikit-learn + archive_scanner)
```

**Flow:** 
- **PE Files (`.exe`, `.dll`):** Upload → Express gateway (MZ magic byte check `4D 5A` + SHA-256) → Flask ML `/analyze` (in-memory PE parsing, 24-feature extraction) → Random Forest prediction → SQLite storage → React UI render.
- **ZIP Archives (`.zip`):** Upload → Express gateway (ZIP magic byte check `50 4B` + SHA-256) → Flask ML `/analyze-archive` → `ArchiveScanner` pre-extraction safety inspection → Zip Slip canonicalization & bomb limit verification → isolated temporary workspace extraction → recursive inspection of nested archives → in-memory PE feature extraction on all `.exe` and `.dll` targets → aggregate verdict calculation → secure temporary workspace cleanup in `finally:` block → SQLite storage → React Archive Report render.

---

## Supported File Formats

| Format | Extension | Detection Engine | Notes |
|---|---|---|---|
| Windows Executables | `.exe` | 24-Feature EMBER Random Forest | Evaluates Shannon entropies, imports, headers, and exports without execution. |
| Dynamic Link Libraries | `.dll` | 24-Feature EMBER Random Forest | Evaluates library imports, export tables, and PE characteristics. |
| Compressed Archives | `.zip` | Safe ZIP Archive Inspector + PE Engine | Safely inspects archive contents, extracts and scans all embedded PE binaries. |
| Unsupported Archive Items | `.txt`, `.pdf`, `.png`, etc. | Disclosed in Report | Non-executable files are marked `UNSUPPORTED` and clearly disclosed rather than labeled clean. |

---

## Security Guarantees & Precautions

1. **Zero File Execution:** Uploaded files and archive members are strictly opened as raw binary data for static analysis and cryptographic hashing. No file is ever executed or loaded as active code.
2. **Zip Slip / Path Traversal Prevention:** Archive member filenames are canonicalized against the isolated temporary directory path. Any traversal sequences (`..`, absolute paths, leading slashes, Windows drive letters) are rejected immediately as security violations.
3. **Zip Bomb & Resource Exhaustion Defense:** Enforces configurable thresholds across the archive and all nested archives:
   - `MAX_TOTAL_EXTRACTED_SIZE`: 100 MB max total uncompressed data
   - `MAX_INDIVIDUAL_FILE_SIZE`: 50 MB max per uncompressed file
   - `MAX_FILE_COUNT`: 250 files maximum
   - `MAX_COMPRESSION_RATIO`: 100:1 maximum compression ratio
   - `PROCESSING_TIMEOUT_SECONDS`: 30 seconds maximum processing time
4. **Volatile Workspace Isolation & Guaranteed Cleanup:** Scans run inside dedicated temporary directories (`tempfile.mkdtemp(prefix="threatforge_scan_")`). All temporary files are guaranteed to be purged in a `finally:` block upon completion or failure.
5. **Password-Protected Archive Handling:** Archives or members requiring a password are recognized without crashing, reported with clear diagnostic messages, and classified as `INCONCLUSIVE`.
6. **Honest Detection Reporting:** The platform does not describe an archive as "guaranteed safe" merely because the model predicts tested binaries as clean. Unsupported files are explicitly disclosed in the scan report.

---

## Archive Verdict Rules

- **Malicious:** At least one supported file is classified as malicious by the Random Forest model.
- **Suspicious:** No malicious file is detected, but one or more files exhibit elevated heuristic indicators or borderline anomaly scores.
- **Inconclusive:** No malicious or suspicious file is detected, but relevant contents could not be analyzed (e.g. password-protected archives, corrupt files, or limits exceeded).
- **No malware detected:** All supported files were successfully scanned and no malware was detected, with unsupported files clearly disclosed.

---

## Prerequisites

| Requirement | Version |
|---|---|
| Node.js | 20+ |
| Python | 3.10+ |
| pip packages | pefile, joblib, scikit-learn, flask, pytest |

---

## Quick Start (3 Terminals)

### Terminal 1 — ML Service (Python)

```bash
cd "AI Malware Analyzer/threatforge/ml-service"
python app.py
```

The model (`malware_model.pkl`) loads at startup — expect ~15-20 seconds for the 909 MB file.

Verify: `GET http://localhost:5000/health`

### Terminal 2 — Express Gateway (Node.js)

```bash
cd "AI Malware Analyzer/threatforge/server"
npm run dev
```

Gateway runs at `http://localhost:3001`

### Terminal 3 — React Frontend (Vite)

```bash
cd "AI Malware Analyzer/threatforge/client"
npm run dev
```

Frontend runs at `http://localhost:5173`

---

## Orchestrated Start (from `threatforge/` root)

```bash
cd "AI Malware Analyzer/threatforge"
npm run dev
```

Uses `concurrently` to run all three processes simultaneously with colored output labels.

---

## Running Automated Tests

### Python Test Suite (Archive Scanner & ML Service)

Includes tests for all 13 required scenarios:
1. ZIP with clean EXE
2. ZIP with malicious EXE
3. ZIP with clean DLL
4. ZIP with clean and malicious files
5. ZIP with unsupported files only
6. Corrupted ZIP handling
7. Password-protected ZIP handling
8. Nested ZIP archives
9. Path traversal (Zip Slip) attempts
10. ZIP bombs and resource limit violations
11. Feature extraction and model prediction failures
12. Temporary workspace cleanup on success and failure
13. Regression tests for standalone EXE and DLL scanning

```bash
cd "AI Malware Analyzer/threatforge/ml-service"
python -m pytest tests/test_archive_scanner.py -v
```

### Gateway Integration Tests

```bash
cd "AI Malware Analyzer/threatforge/server"
npx tsx src/test_gateway.ts
```

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/analyze` | POST | Upload standalone binary (`.exe`, `.dll`) or ZIP archive (`.zip`) |
| `/api/analyses` | GET | List analyses (query: search, verdict, file_type, sort, page, limit) |
| `/api/analyses/:id` | GET | Fetch single analysis record |
| `/api/analyses/:id` | DELETE | Delete one analysis record |
| `/api/analyses` | DELETE | Clear all analysis history |
| `/api/stats` | GET | Dashboard stats, timeline, and recent scans |
| `/health` | GET | Gateway + ML microservice health check |

---

## Frontend Features

- Drag and drop scan interface supporting `.exe`, `.dll`, and `.zip` up to 50 MB
- Staged scanner progress animation reflecting archive inspection, extraction, and PE vector analysis
- High-contrast verdict banners: `MALICIOUS`, `SUSPICIOUS`, `INCONCLUSIVE`, `NO MALWARE DETECTED`
- Dedicated Archive Scan Report with summary metric cards (Total, Scanned, Malicious, Suspicious, Clean, Unsupported)
- Searchable, filterable, and expandable table of all archive members showing individual paths, sizes, types, and verdicts
- Expandable file details displaying SHA-256 and heuristic indicators for individual targets
- Scan History with SQLite persistence, CSV export, and filtering by verdict and file type
- Theme customizer with dark/light themes (Ocean, Crimson, Violet, Amber, Jade, Arctic, Sand)
