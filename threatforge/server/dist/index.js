import express from "express";
import cors from "cors";
import helmet from "helmet";
import multer from "multer";
import crypto from "node:crypto";
import dotenv from "dotenv";
import { z } from "zod";
import { insertAnalysis, getAnalysis, listAnalyses, deleteAnalysisById, deleteAllAnalyses, getStats, } from "./db.js";
dotenv.config();
const PORT = parseInt(process.env.PORT || "3001", 10);
const FLASK_URL = process.env.FLASK_URL || "http://127.0.0.1:5000";
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "http://localhost:5173";
const app = express();
// Security and CORS
app.use(helmet({ crossOriginResourcePolicy: false }));
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps, curl, or same-origin)
        if (!origin || origin === CLIENT_ORIGIN || origin.startsWith("http://localhost:") || origin.startsWith("http://127.0.0.1:")) {
            callback(null, true);
        }
        else {
            callback(null, true); // Dev-friendly fallback
        }
    },
    credentials: true,
}));
app.use(express.json());
// In-memory Multer configuration (Max 50MB, strictly no disk writes)
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 50 * 1024 * 1024, // 50 MB
    },
    fileFilter: (_req, file, cb) => {
        const ext = file.originalname.toLowerCase().split(".").pop();
        if (ext === "exe" || ext === "dll" || ext === "zip") {
            cb(null, true);
        }
        else {
            cb(new Error("Invalid file extension: Only Windows executables (.exe, .dll) and ZIP archives (.zip) are permitted."));
        }
    },
});
// Health check
app.get("/health", async (_req, res) => {
    let mlHealthy = false;
    try {
        const mlResp = await fetch(`${FLASK_URL}/health`, { signal: AbortSignal.timeout(2000) });
        mlHealthy = mlResp.ok;
    }
    catch {
        mlHealthy = false;
    }
    res.json({
        status: "ok",
        gateway: "threatforge-gateway",
        ml_service_url: FLASK_URL,
        ml_service_healthy: mlHealthy,
    });
});
// POST /api/analyze
app.post("/api/analyze", upload.single("file"), async (req, res) => {
    const file = req.file;
    if (!file || !file.buffer || file.buffer.length === 0) {
        res.status(400).json({ error: "Missing file in request" });
        return;
    }
    const ext = file.originalname.toLowerCase().split(".").pop();
    const sha256 = crypto.createHash("sha256").update(file.buffer).digest("hex");
    const id = crypto.randomUUID();
    const analyzedAt = new Date().toISOString();
    // Branch 1: ZIP Archive Analysis
    if (ext === "zip") {
        // 1. Verify ZIP magic bytes (50 4B 03 04, 50 4B 05 06, or 50 4B 07 08)
        const isZipMagic = file.buffer.length >= 4 &&
            file.buffer[0] === 0x50 &&
            file.buffer[1] === 0x4b &&
            ((file.buffer[2] === 0x03 && file.buffer[3] === 0x04) ||
                (file.buffer[2] === 0x05 && file.buffer[3] === 0x06) ||
                (file.buffer[2] === 0x07 && file.buffer[3] === 0x08));
        if (!isZipMagic) {
            res.status(400).json({
                error: "Invalid archive format: File header lacks valid ZIP magic bytes (50 4B).",
                verdict: "INCONCLUSIVE",
            });
            return;
        }
        try {
            const formData = new FormData();
            const uint8Array = new Uint8Array(file.buffer);
            const blob = new Blob([uint8Array]);
            formData.append("file", blob, file.originalname);
            const mlResponse = await fetch(`${FLASK_URL}/analyze-archive`, {
                method: "POST",
                body: formData,
                signal: AbortSignal.timeout(60000), // 60s timeout for archive scanning
            });
            const report = (await mlResponse.json());
            // Extract highest confidence / model score among scanned archive files
            let maxScore = 0.0;
            if (report.files && report.files.length > 0) {
                for (const f of report.files) {
                    if (typeof f.model_score === "number" && f.model_score > maxScore) {
                        maxScore = f.model_score;
                    }
                }
            }
            // Generate summary indicators from archive contents
            const indicators = [];
            if (report.malicious_count > 0) {
                indicators.push({
                    severity: "critical",
                    title: `Malicious Binary Detected (${report.malicious_count})`,
                    detail: `Archive contains ${report.malicious_count} executable(s) identified as malware.`,
                });
            }
            if (report.suspicious_count > 0) {
                indicators.push({
                    severity: "high",
                    title: `Suspicious Files Flagged (${report.suspicious_count})`,
                    detail: `Archive contains ${report.suspicious_count} executable(s) exhibiting anomalous features.`,
                });
            }
            if (report.unsupported_count > 0) {
                indicators.push({
                    severity: "low",
                    title: `Unsupported Files Disclosed (${report.unsupported_count})`,
                    detail: `${report.unsupported_count} file(s) are non-executable formats and could not be evaluated by the PE classifier.`,
                });
            }
            const threatLevel = report.verdict === "MALICIOUS"
                ? "CRITICAL"
                : report.verdict === "SUSPICIOUS"
                    ? "HIGH"
                    : report.verdict === "INCONCLUSIVE"
                        ? "UNKNOWN"
                        : "LOW";
            const record = {
                id,
                filename: file.originalname,
                sha256,
                file_size: file.size,
                analyzed_at: analyzedAt,
                verdict: report.verdict || "INCONCLUSIVE",
                model_score: maxScore,
                threat_level: threatLevel,
                features: {},
                indicators,
                top_contributors: [],
                error: report.error || null,
                file_type: "archive",
                archive_data: report,
            };
            insertAnalysis(record);
            res.status(report.error && report.verdict === "INCONCLUSIVE" ? 422 : 200).json(record);
            return;
        }
        catch (err) {
            const errorMsg = `ML microservice archive connection failed: ${err.message || "Service unreachable"}`;
            const fallbackReport = {
                archive_filename: file.originalname,
                analyzed_at: analyzedAt,
                archive_sha256: sha256,
                archive_size: file.size,
                verdict: "INCONCLUSIVE",
                total_files: 0,
                scanned_files_count: 0,
                malicious_count: 0,
                suspicious_count: 0,
                clean_count: 0,
                unsupported_count: 0,
                error_count: 1,
                summary_notes: errorMsg,
                error: errorMsg,
                files: [],
            };
            const record = {
                id,
                filename: file.originalname,
                sha256,
                file_size: file.size,
                analyzed_at: analyzedAt,
                verdict: "INCONCLUSIVE",
                model_score: 0.0,
                threat_level: "UNKNOWN",
                features: {},
                indicators: [],
                top_contributors: [],
                error: errorMsg,
                file_type: "archive",
                archive_data: fallbackReport,
            };
            insertAnalysis(record);
            res.status(422).json(record);
            return;
        }
    }
    // Branch 2: Standalone Windows PE Executable Analysis (.exe, .dll)
    // 1. Verify MZ magic bytes: 0x4D 0x5A ('MZ')
    if (file.buffer.length < 2 || file.buffer[0] !== 0x4d || file.buffer[1] !== 0x5a) {
        res.status(400).json({
            error: "Invalid executable format: File header lacks valid MZ magic bytes (4D 5A).",
            verdict: "UNKNOWN",
        });
        return;
    }
    let verdict = "UNKNOWN";
    let modelScore = 0.0;
    let threatLevel = "UNKNOWN";
    let features = {};
    let indicators = [];
    let topContributors = [];
    let analysisError = null;
    try {
        // Forward bytes in memory to Python ML service
        const formData = new FormData();
        const uint8Array = new Uint8Array(file.buffer);
        const blob = new Blob([uint8Array]);
        formData.append("file", blob, file.originalname);
        const mlResponse = await fetch(`${FLASK_URL}/analyze`, {
            method: "POST",
            body: formData,
            signal: AbortSignal.timeout(30000), // 30s timeout
        });
        const mlData = (await mlResponse.json());
        if (!mlResponse.ok || mlData.error) {
            verdict = "UNKNOWN";
            analysisError = mlData.error || `ML Service returned status ${mlResponse.status}`;
            threatLevel = "UNKNOWN";
        }
        else {
            verdict = mlData.verdict || "UNKNOWN";
            modelScore = typeof mlData.model_score === "number" ? mlData.model_score : 0.0;
            threatLevel = mlData.threat_level || "UNKNOWN";
            features = mlData.features || {};
            indicators = mlData.indicators || [];
            topContributors = mlData.top_contributors || [];
        }
    }
    catch (err) {
        verdict = "UNKNOWN";
        threatLevel = "UNKNOWN";
        analysisError = `ML microservice connection failed: ${err.message || "Service unreachable"}`;
    }
    const record = {
        id,
        filename: file.originalname,
        sha256,
        file_size: file.size,
        analyzed_at: analyzedAt,
        verdict,
        model_score: modelScore,
        threat_level: threatLevel,
        features,
        indicators,
        top_contributors: topContributors,
        error: analysisError,
        file_type: "pe",
        archive_data: null,
    };
    // Save analysis results only (never the binary) to SQLite
    insertAnalysis(record);
    res.status(analysisError && verdict === "UNKNOWN" ? 422 : 200).json(record);
});
// GET /api/analyses
app.get("/api/analyses", (req, res) => {
    const querySchema = z.object({
        search: z.string().optional(),
        verdict: z.string().optional(),
        file_type: z.string().optional(),
        sort: z.enum(["date_desc", "date_asc", "score_desc", "score_asc"]).optional(),
        page: z.coerce.number().optional(),
        limit: z.coerce.number().optional(),
    });
    const parsed = querySchema.safeParse(req.query);
    if (!parsed.success) {
        res.status(400).json({ error: "Invalid query parameters", details: parsed.error.issues });
        return;
    }
    const result = listAnalyses(parsed.data);
    res.json(result);
});
// GET /api/analyses/:id
app.get("/api/analyses/:id", (req, res) => {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const analysis = getAnalysis(id);
    if (!analysis) {
        res.status(404).json({ error: `Analysis with ID '${id}' not found` });
        return;
    }
    res.json(analysis);
});
// DELETE /api/analyses/:id
app.delete("/api/analyses/:id", (req, res) => {
    const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
    const deleted = deleteAnalysisById(id);
    if (!deleted) {
        res.status(404).json({ error: `Analysis with ID '${id}' not found` });
        return;
    }
    res.json({ success: true, message: "Analysis removed" });
});
// DELETE /api/analyses
app.delete("/api/analyses", (_req, res) => {
    deleteAllAnalyses();
    res.json({ success: true, message: "All analysis history cleared" });
});
// GET /api/stats
app.get("/api/stats", (_req, res) => {
    const stats = getStats();
    res.json(stats);
});
// Global Error Handler
app.use((err, _req, res, _next) => {
    console.error("Unhandled Server Error:", err);
    if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") {
            res.status(413).json({ error: "File exceeds 50MB maximum allowable limit." });
            return;
        }
        res.status(400).json({ error: `Upload error: ${err.message}` });
        return;
    }
    res.status(500).json({ error: err.message || "Internal server error" });
});
app.listen(PORT, () => {
    console.log(`ThreatForge Gateway running on http://localhost:${PORT}`);
    console.log(`Forwarding PE & Archive analysis to ML Service at: ${FLASK_URL}`);
});
