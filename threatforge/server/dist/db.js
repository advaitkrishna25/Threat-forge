import Database from "better-sqlite3";
import path from "node:path";
import fs from "node:fs";
const dbDir = path.resolve(process.cwd(), "data");
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}
const dbPath = path.join(dbDir, "threatforge.db");
const db = new Database(dbPath);
// Enable WAL mode for high performance
db.pragma("journal_mode = WAL");
// Initialize Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    analyzed_at TEXT NOT NULL,
    verdict TEXT NOT NULL,
    model_score REAL NOT NULL,
    threat_level TEXT NOT NULL,
    features TEXT NOT NULL,
    indicators TEXT NOT NULL,
    top_contributors TEXT NOT NULL,
    error TEXT,
    file_type TEXT DEFAULT 'pe',
    archive_data TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_analyses_sha256 ON analyses (sha256);
  CREATE INDEX IF NOT EXISTS idx_analyses_analyzed_at ON analyses (analyzed_at DESC);
  CREATE INDEX IF NOT EXISTS idx_analyses_verdict ON analyses (verdict);
`);
// Safe migrations for existing databases
try {
    db.exec("ALTER TABLE analyses ADD COLUMN file_type TEXT DEFAULT 'pe'");
}
catch { }
try {
    db.exec("ALTER TABLE analyses ADD COLUMN archive_data TEXT");
}
catch { }
export function insertAnalysis(analysis) {
    const stmt = db.prepare(`
    INSERT INTO analyses (
      id, filename, sha256, file_size, analyzed_at, verdict,
      model_score, threat_level, features, indicators, top_contributors, error,
      file_type, archive_data
    ) VALUES (
      @id, @filename, @sha256, @file_size, @analyzed_at, @verdict,
      @model_score, @threat_level, @features, @indicators, @top_contributors, @error,
      @file_type, @archive_data
    )
  `);
    stmt.run({
        id: analysis.id,
        filename: analysis.filename,
        sha256: analysis.sha256,
        file_size: analysis.file_size,
        analyzed_at: analysis.analyzed_at,
        verdict: analysis.verdict,
        model_score: analysis.model_score,
        threat_level: analysis.threat_level,
        features: JSON.stringify(analysis.features || {}),
        indicators: JSON.stringify(analysis.indicators || []),
        top_contributors: JSON.stringify(analysis.top_contributors || []),
        error: analysis.error,
        file_type: analysis.file_type || "pe",
        archive_data: analysis.archive_data ? JSON.stringify(analysis.archive_data) : null,
    });
}
function parseRow(row) {
    return {
        ...row,
        file_type: row.file_type || "pe",
        features: JSON.parse(row.features || "{}"),
        indicators: JSON.parse(row.indicators || "[]"),
        top_contributors: JSON.parse(row.top_contributors || "[]"),
        archive_data: row.archive_data ? JSON.parse(row.archive_data) : null,
    };
}
export function getAnalysis(id) {
    const stmt = db.prepare("SELECT * FROM analyses WHERE id = ?");
    const row = stmt.get(id);
    if (!row)
        return null;
    return parseRow(row);
}
export function deleteAnalysisById(id) {
    const stmt = db.prepare("DELETE FROM analyses WHERE id = ?");
    const result = stmt.run(id);
    return result.changes > 0;
}
export function deleteAllAnalyses() {
    db.exec("DELETE FROM analyses");
}
export function listAnalyses(params = {}) {
    const page = Math.max(1, params.page || 1);
    const limit = Math.max(1, Math.min(100, params.limit || 10));
    const offset = (page - 1) * limit;
    const conditions = [];
    const queryParams = {};
    if (params.search && params.search.trim() !== "") {
        conditions.push("(filename LIKE @search OR sha256 LIKE @search)");
        queryParams.search = `%${params.search.trim()}%`;
    }
    if (params.verdict &&
        [
            "BENIGN",
            "MALICIOUS",
            "UNKNOWN",
            "SUSPICIOUS",
            "INCONCLUSIVE",
            "NO_MALWARE_DETECTED",
        ].includes(params.verdict.toUpperCase())) {
        conditions.push("verdict = @verdict");
        queryParams.verdict = params.verdict.toUpperCase();
    }
    if (params.file_type && ["pe", "archive"].includes(params.file_type.toLowerCase())) {
        conditions.push("file_type = @file_type");
        queryParams.file_type = params.file_type.toLowerCase();
    }
    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    let orderBy = "analyzed_at DESC";
    if (params.sort === "date_asc")
        orderBy = "analyzed_at ASC";
    else if (params.sort === "score_desc")
        orderBy = "model_score DESC";
    else if (params.sort === "score_asc")
        orderBy = "model_score ASC";
    const countStmt = db.prepare(`SELECT COUNT(*) as count FROM analyses ${whereClause}`);
    const totalCount = countStmt.get(queryParams).count;
    const dataStmt = db.prepare(`
    SELECT * FROM analyses
    ${whereClause}
    ORDER BY ${orderBy}
    LIMIT @limit OFFSET @offset
  `);
    const rows = dataStmt.all({ ...queryParams, limit, offset });
    const items = rows.map(parseRow);
    return {
        items,
        total: totalCount,
        page,
        limit,
        totalPages: Math.ceil(totalCount / limit) || 1,
    };
}
export function getStats() {
    const totalStmt = db.prepare("SELECT COUNT(*) as count FROM analyses");
    const totalScans = totalStmt.get().count;
    const verdictStmt = db.prepare(`
    SELECT verdict, COUNT(*) as count
    FROM analyses
    GROUP BY verdict
  `);
    const verdictRows = verdictStmt.all();
    let malicious = 0;
    let benign = 0;
    let unknown = 0;
    for (const row of verdictRows) {
        if (row.verdict === "MALICIOUS")
            malicious += row.count;
        else if (row.verdict === "BENIGN" || row.verdict === "NO_MALWARE_DETECTED")
            benign += row.count;
        else
            unknown += row.count;
    }
    const detectionRate = totalScans > 0 ? (malicious / totalScans) * 100 : 0;
    // Scans grouped by date (YYYY-MM-DD)
    const timelineStmt = db.prepare(`
    SELECT 
      substr(analyzed_at, 1, 10) as date,
      COUNT(*) as total,
      SUM(CASE WHEN verdict = 'MALICIOUS' THEN 1 ELSE 0 END) as malicious,
      SUM(CASE WHEN verdict IN ('BENIGN', 'NO_MALWARE_DETECTED') THEN 1 ELSE 0 END) as benign
    FROM analyses
    GROUP BY substr(analyzed_at, 1, 10)
    ORDER BY date ASC
    LIMIT 30
  `);
    const timelineRows = timelineStmt.all();
    // Most recent 5
    const recentStmt = db.prepare(`
    SELECT * FROM analyses
    ORDER BY analyzed_at DESC
    LIMIT 5
  `);
    const recentRows = recentStmt.all().map(parseRow);
    return {
        total_scans: totalScans,
        malicious_count: malicious,
        benign_count: benign,
        unknown_count: unknown,
        detection_rate: Math.round(detectionRate * 10) / 10,
        scans_per_day: timelineRows,
        recent_scans: recentRows,
    };
}
