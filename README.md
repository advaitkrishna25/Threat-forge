# ThreatForge / GuardForge

**Static PE & Secure ZIP Archive Malware Analyzer** — An end-to-end, zero-execution binary intelligence platform powered by an EMBER Random Forest classifier.

---

## Architecture Overview

```
Threat-forge/
├── package.json         Workspace root scripts (orchestrated dev, setup, test)
├── .gitignore           Comprehensive Git ignore rules for node_modules, DBs, and large models
├── README.md            Documentation & setup instructions
└── threatforge/
    ├── client/          React 19 + Vite + Tailwind CSS frontend (Port 5173)
    ├── server/          Node.js 20 + Express gateway with TypeScript & SQLite (Port 3001)
    └── ml-service/      Python Flask microservice (pefile + scikit-learn + archive_scanner) (Port 5000)
```

**Flow:**
- **PE Binaries (`.exe`, `.dll`):** Upload → Express gateway (MZ magic byte check `4D 5A` + SHA-256 calculation) → Flask ML microservice `/analyze` (in-memory PE parsing, 24-feature extraction) → Random Forest classification → SQLite persistence → React dashboard rendering.
- **ZIP Archives (`.zip`):** Upload → Express gateway (ZIP magic byte check `50 4B` + SHA-256 calculation) → Flask ML `/analyze-archive` → `ArchiveScanner` pre-extraction safety inspection → Zip Slip path traversal & Zip Bomb limit verification → isolated temporary workspace extraction → recursive member inspection → in-memory PE feature extraction across all `.exe` and `.dll` targets → aggregate verdict calculation → guaranteed temporary workspace cleanup in `finally:` block → SQLite persistence → Interactive React Archive Report rendering.

---

## Supported File Formats

| Format | Extension | Detection Engine | Notes |
|---|---|---|---|
| **Windows Executables** | `.exe` | 24-Feature EMBER Random Forest | Evaluates Shannon entropies, imported DLLs/functions, section headers, and characteristics without executing code. |
| **Dynamic Link Libraries** | `.dll` | 24-Feature EMBER Random Forest | Evaluates library imports, export tables, and PE characteristics. |
| **Compressed Archives** | `.zip` | Safe ZIP Archive Inspector + PE Engine | Safely inspects archive contents, defends against traversal & bombs, extracts and scans all embedded PE binaries. |
| **Unsupported Archive Items** | `.txt`, `.pdf`, `.png`, etc. | Disclosed in Report | Non-executable files are safely marked `UNSUPPORTED` and disclosed rather than falsely labeled clean. |

---

## Security Guarantees & Precautions

1. **Zero File Execution:** Uploaded files and archive members are strictly read as raw binary buffers for static feature extraction and cryptographic hashing. No file is ever executed or loaded as active code.
2. **Zip Slip / Path Traversal Prevention:** Archive member filenames are canonicalized against the isolated temporary directory path. Any traversal sequences (`..`, absolute paths, leading slashes, Windows drive letters) are rejected immediately as security violations.
3. **Zip Bomb & Resource Exhaustion Defense:** Enforces strict configurable thresholds across the archive and all nested archives:
   - `MAX_TOTAL_EXTRACTED_SIZE`: 100 MB max total uncompressed data
   - `MAX_INDIVIDUAL_FILE_SIZE`: 50 MB max per uncompressed file
   - `MAX_FILE_COUNT`: 250 files maximum
   - `MAX_COMPRESSION_RATIO`: 100:1 maximum compression ratio
   - `PROCESSING_TIMEOUT_SECONDS`: 30 seconds maximum processing time
4. **Volatile Workspace Isolation & Guaranteed Cleanup:** Scans execute inside isolated temporary directories (`tempfile.mkdtemp(prefix="threatforge_scan_")`). All extracted files are guaranteed to be purged in a `finally:` block upon completion or failure.
5. **Password-Protected Archive Handling:** Encrypted archives or password-protected members are detected without crashing, reported with clear diagnostic messages, and classified as `INCONCLUSIVE`.
6. **Honest Detection Reporting:** The platform does not label an archive as "safe" if unsupported or unanalyzed files are present. All non-executable contents are explicitly disclosed in the scan report.

---

## Archive Verdict Rules

- **Malicious:** At least one supported binary in the archive is classified as malicious by the Random Forest classifier.
- **Suspicious:** No malicious file is detected, but one or more files exhibit elevated heuristic indicators (e.g. section entropy > 7.2 or suspicious injection APIs).
- **Inconclusive:** No malicious or suspicious file is detected, but relevant contents could not be scanned (e.g. password protection, corruption, or resource limit exhaustion).
- **No malware detected:** All supported files were successfully scanned and predicted clean, with any unsupported files disclosed.

---

## Prerequisites

| Requirement | Supported Version | Notes |
|---|---|---|
| **Node.js** | 20+ | Required for Gateway and Frontend |
| **Python** | 3.10+ | Required for ML Microservice |
| **npm** | 10+ | Standard package manager |

---

## Quick Start (Installation & Setup)

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/Threat-forge.git
cd Threat-forge
```

### 2. Install Dependencies

You can install all frontend, server, and ML dependencies at once from the root workspace:

```bash
# Install Node dependencies for root, server, and client
npm run install:all

# Install Python requirements
npm run install:ml
```

*Or install step-by-step manually:*

```bash
# Server dependencies
cd threatforge/server
npm install

# Client dependencies
cd ../client
npm install

# ML Service dependencies (virtual environment recommended)
cd ../ml-service
pip install -r requirements.txt
```

### 3. Environment Variables (Optional)

Default configurations are pre-wired for local development and run out of the box. If you wish to customize ports or URLs, copy the `.env.example` templates:

```bash
# Gateway configuration (default port: 3001)
cp threatforge/server/.env.example threatforge/server/.env

# Frontend configuration (default API: http://localhost:3001)
cp threatforge/client/.env.example threatforge/client/.env

# ML Service configuration (default port: 5000)
cp threatforge/ml-service/.env.example threatforge/ml-service/.env
```

---

## Running the Application

### Option A: One-Command Start (Recommended)

From the project root:

```bash
npm run dev
```

This uses `concurrently` to boot the ML microservice, Express gateway, and Vite React frontend in parallel with color-coded logging.

### Option B: Running in 3 Separate Terminals

#### Terminal 1 — ML Microservice (Python)

```bash
cd threatforge/ml-service
python app.py
```
*Runs on `http://127.0.0.1:5000` (Health Check: `http://127.0.0.1:5000/health`)*

#### Terminal 2 — Express API Gateway (Node.js / TypeScript)

```bash
cd threatforge/server
npm run dev
```
*Runs on `http://localhost:3001` (Health Check: `http://localhost:3001/health`)*

#### Terminal 3 — React Frontend (Vite)

```bash
cd threatforge/client
npm run dev
```
*Open your browser at `http://localhost:5173`*

---

## Machine Learning Model Information

ThreatForge includes a bundled, pre-trained Random Forest classifier (`threatforge/ml-service/model.pkl`, ~3.3 MB) trained on EMBER PE static features:

- **Ready Out-of-the-Box:** Fresh clones work immediately without requiring large external model downloads.
- **Instant Startup:** The bundled model loads in <0.2 seconds at microservice startup.
- **High Accuracy:** Evaluates 24 static PE features (Shannon entropies, DLL import hashes, section counts, COFF timestamps, headers).
- **Graceful Fallback:** If no `.pkl` model file is present, the service smoothly falls back to an intelligent heuristic static PE analyzer rather than crashing.
- **Full Model Support:** If you have trained or downloaded the full 300-estimator model (`malware_model.pkl`), place it in `threatforge/ml-service/` or the repository root — `app.py` will automatically detect and prioritize it.

### Retraining or Generating Models

A dedicated trainer script is included in `threatforge/ml-service/train_model.py`:

```bash
cd threatforge/ml-service

# Train compact bundled model (model.pkl):
python train_model.py --compact

# Train full high-capacity model (malware_model.pkl):
python train_model.py --full --samples 300000
```

---

## Running Automated Tests

Run all test suites across the repository:

```bash
# Run both server integration and ML unit tests
npm test
```

### Python ML & Archive Scanner Test Suite (14 Scenarios)

Includes automated tests covering:
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
14. Health check and microservice endpoints

```bash
cd threatforge/ml-service
python -m pytest tests/test_archive_scanner.py -v
```

### Gateway Integration Tests

Validates SQLite schema creation, analysis insertion, record retrieval, filtering, and deletion:

```bash
cd threatforge/server
npm test
```

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/analyze` | `POST` | Upload standalone binary (`.exe`, `.dll`) or ZIP archive (`.zip`) |
| `/api/analyses` | `GET` | List scan history (query: `search`, `verdict`, `file_type`, `sort`, `page`, `limit`) |
| `/api/analyses/:id` | `GET` | Fetch single analysis record |
| `/api/analyses/:id` | `DELETE` | Delete single analysis record |
| `/api/analyses` | `DELETE` | Clear all analysis history |
| `/api/stats` | `GET` | Dashboard metrics, scan volume timeline, and recent scans |
| `/health` | `GET` | Gateway + ML microservice health check |

---

## Frontend Features

- **Drag & Drop Scanner:** Supports `.exe`, `.dll`, and `.zip` files up to 50 MB.
- **Staged Progress Animation:** Live visualization of archive inspection, extraction, and PE vector analysis.
- **Verdict Badges:** High-contrast verdict indicators: `MALICIOUS`, `SUSPICIOUS`, `INCONCLUSIVE`, `NO MALWARE DETECTED`.
- **Archive Scan Report:** Summary metric cards (Total, Scanned, Malicious, Suspicious, Clean, Unsupported).
- **Archive Members Table:** Searchable, filterable, and expandable table of all archive members showing individual relative paths, sizes, types, and verdicts.
- **Deep Heuristic Insights:** Expandable file drawer displaying SHA-256 hashes, section entropy readings, and detected suspicious API calls.
- **Persistent Scan History:** SQLite persistence with CSV export, search, and verdict filtering.
- **Theme Customizer:** Modern dark/light theme options (Ocean, Crimson, Violet, Amber, Jade, Arctic, Sand).
