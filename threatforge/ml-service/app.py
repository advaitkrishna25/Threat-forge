import os
import sys
import logging
from pathlib import Path
from flask import Flask, request, jsonify
import joblib

from extractor import extract_pe_features_from_bytes
from archive_scanner import ArchiveScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ml-service")

app = Flask(__name__)

# Search candidate paths for model
candidate_paths = [
    os.getenv("MODEL_PATH"),
    "malware_model.pkl",
    "../malware_model.pkl",
    "../../malware_model.pkl",
    r"a:\Coding\AI Malware Analyzer\malware_model.pkl",
]

model = None
features_list = []
loaded_path = None

for p in candidate_paths:
    if p and os.path.exists(p):
        try:
            logger.info(f"Loading Random Forest model from: {p}...")
            saved = joblib.load(p)
            model = saved["model"]
            features_list = saved["features"]
            loaded_path = os.path.abspath(p)
            logger.info(f"Model successfully loaded! Feature count: {len(features_list)} from {loaded_path}")
            break
        except Exception as e:
            logger.error(f"Failed to load model from {p}: {e}")

if model is None:
    logger.warning("WARNING: malware_model.pkl could not be loaded at startup! Check MODEL_PATH.")


def predict_pe_bytes(raw_bytes: bytes, filename: str = "binary.bin") -> dict:
    """
    Standardized PE feature extraction and ML classification routine.
    Reused across both standalone executable analysis and ZIP archive member scanning.
    """
    if model is None:
        return {
            "verdict": "UNKNOWN",
            "model_score": 0.0,
            "threat_level": "UNKNOWN",
            "features": {},
            "indicators": [],
            "top_contributors": [],
            "error": "ML model is not loaded on server"
        }

    if not raw_bytes:
        return {
            "verdict": "UNKNOWN",
            "model_score": 0.0,
            "threat_level": "UNKNOWN",
            "features": {},
            "indicators": [],
            "top_contributors": [],
            "error": "File buffer is empty (0 bytes)"
        }

    try:
        extraction_result = extract_pe_features_from_bytes(raw_bytes)
        features_dict = extraction_result["features"]
        indicators = extraction_result["indicators"]
        top_contributors = extraction_result["top_contributors"]

        # Vectorize in the exact order the model expects
        X = [[features_dict.get(feat, 0.0) for feat in features_list]]

        prediction = int(model.predict(X)[0])
        probabilities = model.predict_proba(X)[0]
        # malicious score is index 1
        malicious_score = float(probabilities[1])

        verdict = "MALICIOUS" if prediction == 1 else "BENIGN"

        if verdict == "MALICIOUS":
            threat_level = "CRITICAL" if malicious_score >= 0.85 else "HIGH"
        else:
            threat_level = "MEDIUM" if malicious_score >= 0.35 else "LOW"

        return {
            "verdict": verdict,
            "model_score": round(malicious_score, 4),
            "threat_level": threat_level,
            "features": features_dict,
            "indicators": indicators,
            "top_contributors": top_contributors,
            "error": None
        }

    except Exception as e:
        logger.error(f"Error during feature extraction or prediction for {filename}: {e}", exc_info=True)
        return {
            "verdict": "UNKNOWN",
            "model_score": 0.0,
            "threat_level": "UNKNOWN",
            "features": {},
            "indicators": [],
            "top_contributors": [],
            "error": f"Failed to parse PE binary: {str(e)}"
        }


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "threatforge-ml",
        "model_loaded": model is not None,
        "model_path": loaded_path,
        "features_count": len(features_list) if features_list else 0
    }), 200


@app.route("/analyze", methods=["POST"])
def analyze():
    if model is None:
        return jsonify({
            "verdict": "UNKNOWN",
            "model_score": 0.0,
            "threat_level": "UNKNOWN",
            "features": {},
            "indicators": [],
            "top_contributors": [],
            "error": "ML model is not loaded on server"
        }), 503

    if "file" not in request.files:
        return jsonify({
            "verdict": "UNKNOWN",
            "model_score": 0.0,
            "threat_level": "UNKNOWN",
            "features": {},
            "indicators": [],
            "top_contributors": [],
            "error": "No file field in multipart request"
        }), 400

    uploaded_file = request.files["file"]
    filename = uploaded_file.filename or "unknown.bin"
    raw_bytes = uploaded_file.read()

    result = predict_pe_bytes(raw_bytes, filename)
    status_code = 422 if result.get("error") and result.get("verdict") == "UNKNOWN" else 200
    return jsonify(result), status_code


@app.route("/analyze-archive", methods=["POST"])
def analyze_archive():
    if model is None:
        return jsonify({
            "verdict": "INCONCLUSIVE",
            "archive_filename": "unknown.zip",
            "total_files": 0,
            "scanned_files_count": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "clean_count": 0,
            "unsupported_count": 0,
            "error_count": 0,
            "files": [],
            "error": "ML model is not loaded on server"
        }), 503

    if "file" not in request.files:
        return jsonify({
            "verdict": "INCONCLUSIVE",
            "archive_filename": "unknown.zip",
            "total_files": 0,
            "scanned_files_count": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "clean_count": 0,
            "unsupported_count": 0,
            "error_count": 0,
            "files": [],
            "error": "No file field in multipart request"
        }), 400

    uploaded_file = request.files["file"]
    filename = uploaded_file.filename or "archive.zip"
    raw_bytes = uploaded_file.read()

    if not raw_bytes:
        return jsonify({
            "verdict": "INCONCLUSIVE",
            "archive_filename": filename,
            "total_files": 0,
            "scanned_files_count": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "clean_count": 0,
            "unsupported_count": 0,
            "error_count": 0,
            "files": [],
            "error": "Uploaded archive is empty (0 bytes)"
        }), 400

    try:
        scanner = ArchiveScanner(predict_pe_fn=predict_pe_bytes)
        report = scanner.scan_archive_bytes(raw_bytes, filename)
        return jsonify(report), 200
    except Exception as e:
        logger.error(f"Unhandled error analyzing archive {filename}: {e}", exc_info=True)
        return jsonify({
            "verdict": "INCONCLUSIVE",
            "archive_filename": filename,
            "total_files": 0,
            "scanned_files_count": 0,
            "malicious_count": 0,
            "suspicious_count": 0,
            "clean_count": 0,
            "unsupported_count": 0,
            "error_count": 0,
            "files": [],
            "error": f"Failed to inspect archive: {str(e)}"
        }), 422


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    logger.info(f"Starting ThreatForge ML service on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)
