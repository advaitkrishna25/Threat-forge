import assert from "node:assert";
import { insertAnalysis, getAnalysis, listAnalyses, deleteAnalysisById, AnalysisRecord } from "./db.js";

async function runGatewayTests() {
  console.log("Running Gateway Database and Analysis Record Tests...");

  const testArchiveId = "test-archive-" + Date.now();
  const testPeId = "test-pe-" + Date.now();

  // Test 1: Insert Archive Record
  const archiveRecord: AnalysisRecord = {
    id: testArchiveId,
    filename: "test_bundle.zip",
    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    file_size: 4096,
    analyzed_at: new Date().toISOString(),
    verdict: "NO_MALWARE_DETECTED",
    model_score: 0.12,
    threat_level: "LOW",
    features: {},
    indicators: [{ severity: "low", title: "Archive Scanned", detail: "1 PE target scanned clean" }],
    top_contributors: [],
    error: null,
    file_type: "archive",
    archive_data: {
      archive_filename: "test_bundle.zip",
      analyzed_at: new Date().toISOString(),
      archive_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      archive_size: 4096,
      verdict: "NO_MALWARE_DETECTED",
      total_files: 2,
      scanned_files_count: 1,
      malicious_count: 0,
      suspicious_count: 0,
      clean_count: 1,
      unsupported_count: 1,
      error_count: 0,
      summary_notes: "Clean scan",
      error: null,
      files: [
        {
          path: "app.exe",
          size: 2048,
          file_type: ".exe",
          supported: true,
          verdict: "BENIGN",
          model_score: 0.12,
          threat_level: "LOW",
          indicators: [],
          top_contributors: [],
          error: null,
          sha256: "abc123456",
        },
        {
          path: "readme.txt",
          size: 100,
          file_type: ".txt",
          supported: false,
          verdict: "UNSUPPORTED",
          model_score: null,
          threat_level: "UNKNOWN",
          indicators: [],
          top_contributors: [],
          error: "Unsupported file",
          sha256: "def456789",
        },
      ],
    },
  };

  insertAnalysis(archiveRecord);
  const fetchedArchive = getAnalysis(testArchiveId);
  assert.ok(fetchedArchive, "Fetched archive record should exist");
  assert.strictEqual(fetchedArchive.file_type, "archive");
  assert.strictEqual(fetchedArchive.verdict, "NO_MALWARE_DETECTED");
  assert.ok(fetchedArchive.archive_data, "Archive data should be parsed");
  assert.strictEqual(fetchedArchive.archive_data.files.length, 2);
  console.log("✓ Archive record insert & retrieval passed");

  // Test 2: Insert Standalone PE Record
  const peRecord: AnalysisRecord = {
    id: testPeId,
    filename: "standalone.exe",
    sha256: "a1b2c3d4e5f60000000000000000000000000000000000000000000000000000",
    file_size: 10240,
    analyzed_at: new Date().toISOString(),
    verdict: "BENIGN",
    model_score: 0.05,
    threat_level: "LOW",
    features: { size: 10240, imports: 45 },
    indicators: [],
    top_contributors: [],
    error: null,
    file_type: "pe",
    archive_data: null,
  };

  insertAnalysis(peRecord);
  const fetchedPe = getAnalysis(testPeId);
  assert.ok(fetchedPe, "Fetched PE record should exist");
  assert.strictEqual(fetchedPe.file_type, "pe");
  assert.strictEqual(fetchedPe.verdict, "BENIGN");
  assert.strictEqual(fetchedPe.features.size, 10240);
  console.log("✓ Standalone PE record insert & retrieval passed");

  // Test 3: List analyses with filters
  const allList = listAnalyses({ limit: 10 });
  assert.ok(allList.items.length >= 2, "List should contain items");

  const archiveFilterList = listAnalyses({ file_type: "archive" });
  assert.ok(archiveFilterList.items.some((i) => i.id === testArchiveId));

  const peFilterList = listAnalyses({ file_type: "pe" });
  assert.ok(peFilterList.items.some((i) => i.id === testPeId));

  const verdictFilterList = listAnalyses({ verdict: "NO_MALWARE_DETECTED" });
  assert.ok(verdictFilterList.items.some((i) => i.id === testArchiveId));
  console.log("✓ List filtering by file_type and verdict passed");

  // Cleanup test records
  deleteAnalysisById(testArchiveId);
  deleteAnalysisById(testPeId);
  assert.strictEqual(getAnalysis(testArchiveId), null);
  assert.strictEqual(getAnalysis(testPeId), null);
  console.log("✓ Cleanup of test records passed");

  console.log("\nALL GATEWAY INTEGRATION TESTS PASSED SUCCESSFULLY!\n");
}

runGatewayTests().catch((err) => {
  console.error("Test failed:", err);
  process.exit(1);
});
