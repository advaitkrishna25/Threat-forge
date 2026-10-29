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

BASE_DIR = Path(__file__).resolve().parent

# Search candidate paths for model (supports both full 909MB model and bundled compact model)
candidate_paths = [
    os.getenv("MODEL_PATH"),
    str(BASE_DIR / "malware_model.pkl"),
    str(BASE_DIR / "model.pkl"),
    str(BASE_DIR.parent / "malware_model.pkl"),
    str(BASE_DIR.parent / "model.pkl"),
    str(BASE_DIR.parent.parent / "malware_model.pkl"),
    str(BASE_DIR.parent.parent / "model.pkl"),
    "malware_model.pkl",
    "model.pkl",
    "../malware_model.pkl",
    "../model.pkl",
    "../../malware_model.pkl",
    "../../model.pkl",
]

model = None
features_list = []
loaded_path = None

for p in candidate_paths:
    if p and os.path.exists(p):
        try:
            logger.info(f"Attempting to load model from: {p}...")
            saved = joblib.load(p)
            model = saved.get("model")
            features_list = saved.get("features", [])
            loaded_path = os.path.abspath(p)
            logger.info(f"Model successfully loaded from {loaded_path} (features: {len(features_list)})")
            break
        except Exception as e:
            logger.error(f"Failed to load model from {p}: {e}")

if model is None:
    logger.warning("WARNING: Neither malware_model.pkl nor model.pkl could be loaded at startup! Fallback heuristic analyzer will be utilized.")


def _heuristic_pe_classification(raw_bytes: bytes, features_dict: dict, indicators: list, top_contributors: list) -> dict:
    """
    Intelligent heuristic PE classifier fallback if no pre-trained ML model artifact is loaded.
    Evaluates Shannon entropy, known evasion patterns, section anomalies, and Authenticode signing.
    """
    score = 0.05
    max_entropy = features_dict.get("section_entropy_max", 0.0)
    has_sig = features_dict.get("has_signature", 0)
    imports_cnt = features_dict.get("imports", 0)
    num_sections = features_dict.get("number_of_sections", 0)

    # Entropy evaluation (packing / encryption indicator)
    if max_entropy >= 7.5:
        score += 0.50
    elif max_entropy >= 7.1:
        score += 0.35
    elif max_entropy >= 6.7:
        score += 0.15

    # Authenticode signature evaluation
    if has_sig == 0:
        score += 0.15

    # Heuristic indicator count impact
    critical_inds = sum(1 for ind in indicators if ind.get("severity") in ("critical", "high"))
    score += min(critical_inds * 0.15, 0.30)

    # Anomaly checks: very low imports with high entropy (stager/dropper)
    if imports_cnt < 5 and max_entropy > 6.8:
        score += 0.20

    score = min(max(round(score, 4), 0.02), 0.98)
    verdict = "MALICIOUS" if score >= 0.50 else "BENIGN"

    if verdict == "MALICIOUS":
        threat_level = "CRITICAL" if score >= 0.85 else "HIGH"
    else:
        threat_level = "MEDIUM" if score >= 0.35 else "LOW"

    return {
        "verdict": verdict,
        "model_score": score,
        "threat_level": threat_level,
        "features": features_dict,
        "indicators": indicators,
        "top_contributors": top_contributors,
        "engine": "heuristic_fallback",
        "error": None
    }


def predict_pe_bytes(raw_bytes: bytes, filename: str = "binary.bin") -> dict:
    """
    Standardized PE feature extraction and classification routine.
    Reused across standalone executable analysis and ZIP archive member scanning.
    """
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

        # If Random Forest model is available, vectorize and predict
        if model is not None and features_list:
            X = [[features_dict.get(feat, 0.0) for feat in features_list]]
            prediction = int(model.predict(X)[0])
            probabilities = model.predict_proba(X)[0]
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
                "engine": "random_forest",
                "error": None
            }

        # Fallback to heuristic PE analysis engine
        return _heuristic_pe_classification(raw_bytes, features_dict, indicators, top_contributors)

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
        "model_engine": "random_forest" if model is not None else "heuristic_fallback",
        "model_path": loaded_path,
        "features_count": len(features_list) if features_list else 24
    }), 200


@app.route("/analyze", methods=["POST"])
def analyze():
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
