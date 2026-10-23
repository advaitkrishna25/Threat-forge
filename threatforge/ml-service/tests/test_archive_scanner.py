import io
import os
import sys
import zipfile
import shutil
import tempfile
import pytest
from unittest.mock import patch, MagicMock

# Ensure ml-service root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from archive_scanner import ArchiveScanner, is_path_traversal, DEFAULT_CONFIG
import app as ml_app


# Helper: Generate a harmless minimal mock Windows PE binary starting with MZ
def make_dummy_pe(is_dll=False) -> bytes:
    # Minimal MZ header (0x4D 0x5A) + stub
    data = bytearray(b"MZ" + b"\x00" * 256)
    return bytes(data)


# Helper: Create in-memory zip bytes
def create_zip_archive(files_dict: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, content in files_dict.items():
            if isinstance(content, str):
                content = content.encode("utf-8")
            zf.writestr(arcname, content)
    return buf.getvalue()


# Mock model predictor for deterministic testing
def mock_predict_fn(raw_bytes: bytes, filename: str) -> dict:
    fname = filename.lower()
    if "malicious" in fname:
        return {
            "verdict": "MALICIOUS",
            "model_score": 0.94,
            "threat_level": "CRITICAL",
            "features": {"size": len(raw_bytes), "section_entropy_max": 7.8},
            "indicators": [{"severity": "critical", "title": "High Entropy", "detail": "Test detail"}],
            "top_contributors": [{"feature": "section_entropy_max", "impact": "7.8", "direction": "Malicious"}],
            "error": None
        }
    elif "suspicious" in fname:
        return {
            "verdict": "BENIGN",
            "model_score": 0.55,
            "threat_level": "HIGH",
            "features": {"size": len(raw_bytes)},
            "indicators": [{"severity": "high", "title": "Suspicious Imports", "detail": "Test detail"}],
            "top_contributors": [],
            "error": None
        }
    elif "fail" in fname:
        raise ValueError("Simulated parsing failure for testing")
    else:
        return {
            "verdict": "BENIGN",
            "model_score": 0.05,
            "threat_level": "LOW",
            "features": {"size": len(raw_bytes)},
            "indicators": [],
            "top_contributors": [],
            "error": None
        }


# =========================================================================
# TEST 1: ZIP containing a clean EXE
# =========================================================================
def test_1_zip_clean_exe():
    zip_bytes = create_zip_archive({
        "calc_clean.exe": make_dummy_pe()
    })
    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn)
    report = scanner.scan_archive_bytes(zip_bytes, "clean.zip")

    assert report["verdict"] == "NO_MALWARE_DETECTED"
    assert report["total_files"] == 1
    assert report["scanned_files_count"] == 1
    assert report["clean_count"] == 1
    assert report["malicious_count"] == 0
    assert report["suspicious_count"] == 0
    assert report["files"][0]["verdict"] == "BENIGN"
    assert report["files"][0]["supported"] is True


# =========================================================================
# TEST 2: ZIP containing a malicious EXE according to controlled test fixture
# =========================================================================
def test_2_zip_malicious_exe():
    zip_bytes = create_zip_archive({
        "payload_malicious.exe": make_dummy_pe()
    })
    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn)
    report = scanner.scan_archive_bytes(zip_bytes, "malware.zip")

    assert report["verdict"] == "MALICIOUS"
    assert report["malicious_count"] == 1
    assert report["clean_count"] == 0
    assert report["files"][0]["verdict"] == "MALICIOUS"
    assert report["files"][0]["threat_level"] == "CRITICAL"
    assert report["files"][0]["model_score"] == 0.94


# =========================================================================
# TEST 3: ZIP containing a DLL
# =========================================================================
def test_3_zip_dll():
    zip_bytes = create_zip_archive({
        "library_clean.dll": make_dummy_pe(is_dll=True)
    })
    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn)
    report = scanner.scan_archive_bytes(zip_bytes, "dll_archive.zip")

    assert report["verdict"] == "NO_MALWARE_DETECTED"
    assert report["scanned_files_count"] == 1
    assert report["files"][0]["file_type"] == ".dll"
    assert report["files"][0]["supported"] is True
    assert report["files"][0]["verdict"] == "BENIGN"


# =========================================================================
# TEST 4: ZIP containing both clean and malicious files
# =========================================================================
def test_4_zip_clean_and_malicious():
    zip_bytes = create_zip_archive({
        "clean_tool.exe": make_dummy_pe(),
        "trojan_malicious.exe": make_dummy_pe(),
        "readme.txt": "Documentation"
    })
    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn)
    report = scanner.scan_archive_bytes(zip_bytes, "mixed.zip")

    assert report["verdict"] == "MALICIOUS"
    assert report["total_files"] == 3
    assert report["scanned_files_count"] == 2
    assert report["clean_count"] == 1
    assert report["malicious_count"] == 1
    assert report["unsupported_count"] == 1


# =========================================================================
# TEST 5: ZIP containing unsupported file types only
# =========================================================================
def test_5_zip_unsupported_files_only():
    zip_bytes = create_zip_archive({
        "notes.txt": "Hello world",
        "diagram.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00",
        "data.csv": "col1,col2\n1,2"
    })
    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn)
    report = scanner.scan_archive_bytes(zip_bytes, "docs.zip")

    # Unsupported files must NOT be labeled as clean or malicious
    assert report["verdict"] == "NO_MALWARE_DETECTED"
    assert report["scanned_files_count"] == 0
    assert report["unsupported_count"] == 3
    for f in report["files"]:
        assert f["supported"] is False
        assert f["verdict"] == "UNSUPPORTED"
    assert "Unsupported file format" in report["files"][0]["error"]


# =========================================================================
# TEST 6: Corrupted ZIP
# =========================================================================
def test_6_corrupted_zip():
    corrupted_bytes = b"PK\x03\x04\xff\xff\x00\x00totally_corrupt_stream_garbage_header_12345"
    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn)
    report = scanner.scan_archive_bytes(corrupted_bytes, "corrupt.zip")

    assert report["verdict"] == "INCONCLUSIVE"
    assert report["error"] is not None
    assert "Invalid or corrupted archive" in report["error"] or "corrupt" in report["error"].lower()


# =========================================================================
# TEST 7: Password-protected ZIP
# =========================================================================
def test_7_password_protected_zip():
    # Build a zip with the encrypted bit flag set in both local and central directory headers
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("secret_tool.exe", b"MZ" + b"\x00" * 100)

    raw = bytearray(buf.getvalue())
    # Set bit 0 of flag_bits (offset 6) in local header
    loc_idx = raw.find(b"PK\x03\x04")
    if loc_idx != -1:
        raw[loc_idx + 6] = 1
    # Set bit 0 of flag_bits (offset 8) in central directory header
    cd_idx = raw.find(b"PK\x01\x02")
    if cd_idx != -1:
        raw[cd_idx + 8] = 1

    encrypted_zip_bytes = bytes(raw)
    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn)
    report = scanner.scan_archive_bytes(encrypted_zip_bytes, "encrypted.zip")

    assert report["verdict"] == "INCONCLUSIVE"
    assert report["files"][0]["verdict"] == "INCONCLUSIVE"
    assert "password" in report["files"][0]["error"].lower()


# =========================================================================
# TEST 8: Nested ZIP archives
# =========================================================================
def test_8_nested_zip_archives():
    # Inner zip contains an executable
    inner_zip_bytes = create_zip_archive({
        "inner_clean.exe": make_dummy_pe()
    })
    # Outer zip contains inner zip and a root file
    outer_zip_bytes = create_zip_archive({
        "inner_archive.zip": inner_zip_bytes,
        "outer_doc.txt": "Top level info"
    })

    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn)
    report = scanner.scan_archive_bytes(outer_zip_bytes, "outer.zip")

    assert report["verdict"] == "NO_MALWARE_DETECTED"
    # Both outer and nested files were discovered
    paths = [f["path"] for f in report["files"]]
    assert any("inner_clean.exe" in p for p in paths)
    assert report["clean_count"] == 1


# =========================================================================
# TEST 9: Path traversal attempts (Zip Slip)
# =========================================================================
def test_9_path_traversal_zip_slip():
    # Build a malicious archive with relative traversal sequences
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", "root:x:0:0")
        zf.writestr("..\\..\\windows\\system32\\cmd.exe", "fake")

    traversal_zip_bytes = buf.getvalue()
    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn)
    report = scanner.scan_archive_bytes(traversal_zip_bytes, "traversal.zip")

    assert report["verdict"] == "INCONCLUSIVE"
    assert report["error"] is not None
    assert "Zip Slip" in report["error"] or "Security violation" in report["error"]


# =========================================================================
# TEST 10: ZIP bombs or archives that exceed configured limits
# =========================================================================
def test_10_zip_bomb_file_count_limit():
    # Test file count limit enforcement
    custom_limits = {"MAX_FILE_COUNT": 5}
    files = {f"file_{i}.txt": f"Content {i}" for i in range(10)}
    zip_bytes = create_zip_archive(files)

    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn, config=custom_limits)
    report = scanner.scan_archive_bytes(zip_bytes, "bomb_files.zip")

    assert report["verdict"] == "INCONCLUSIVE"
    assert report["error"] is not None
    assert "Total file count exceeded limit" in report["error"]


def test_10_zip_bomb_uncompressed_size_limit():
    # Test total extracted size limit enforcement
    custom_limits = {"MAX_TOTAL_EXTRACTED_SIZE": 1000}  # 1 KB limit
    zip_bytes = create_zip_archive({
        "large_file.txt": "A" * 5000
    })

    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn, config=custom_limits)
    report = scanner.scan_archive_bytes(zip_bytes, "bomb_size.zip")

    assert report["verdict"] == "INCONCLUSIVE"
    assert report["error"] is not None
    assert "Total extracted size exceeded limit" in report["error"]


# =========================================================================
# TEST 11: Feature extraction or model prediction failures
# =========================================================================
def test_11_prediction_failure():
    zip_bytes = create_zip_archive({
        "fail_corrupt.exe": make_dummy_pe()
    })
    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn)
    report = scanner.scan_archive_bytes(zip_bytes, "fail_pe.zip")

    # When an executable fails analysis, verdict must be INCONCLUSIVE
    assert report["verdict"] == "INCONCLUSIVE"
    assert report["error_count"] == 1
    assert report["files"][0]["verdict"] == "INCONCLUSIVE"
    assert "Simulated parsing failure" in report["files"][0]["error"]


# =========================================================================
# TEST 12: Temporary file cleanup after successful and failed scans
# =========================================================================
def test_12_temp_file_cleanup_on_success_and_failure():
    created_dirs = []
    original_mkdtemp = tempfile.mkdtemp

    def tracking_mkdtemp(*args, **kwargs):
        d = original_mkdtemp(*args, **kwargs)
        created_dirs.append(d)
        return d

    scanner = ArchiveScanner(predict_pe_fn=mock_predict_fn)

    # 1. Test cleanup on success
    with patch("tempfile.mkdtemp", side_effect=tracking_mkdtemp):
        zip_bytes = create_zip_archive({"test.exe": make_dummy_pe()})
        scanner.scan_archive_bytes(zip_bytes, "success.zip")

    assert len(created_dirs) == 1
    success_dir = created_dirs[0]
    assert not os.path.exists(success_dir), "Temporary directory was not cleaned up after success!"

    # 2. Test cleanup on failure/exception
    with patch("tempfile.mkdtemp", side_effect=tracking_mkdtemp):
        corrupted_bytes = b"not_a_zip_stream"
        scanner.scan_archive_bytes(corrupted_bytes, "fail.zip")

    assert len(created_dirs) == 2
    fail_dir = created_dirs[1]
    assert not os.path.exists(fail_dir), "Temporary directory was not cleaned up after failure!"


# =========================================================================
# TEST 13: Regression tests for existing standalone EXE and DLL scanning
# =========================================================================
def test_13_regression_standalone_scanning():
    # Directly test predict_pe_bytes function in ml-service/app.py
    # Test empty buffer rejection
    empty_result = ml_app.predict_pe_bytes(b"", "empty.exe")
    assert empty_result["verdict"] == "UNKNOWN"
    assert "empty" in empty_result["error"].lower()

    # Test Flask test_client on /analyze with standalone files
    with ml_app.app.test_client() as client:
        # 1. Clean executable check
        data = {"file": (io.BytesIO(b"MZ" + b"\x00" * 200), "sample.exe")}
        response = client.post("/analyze", data=data, content_type="multipart/form-data")
        assert response.status_code in (200, 422)  # Either parsed or PE format caught without crashing

        # 2. Archive endpoint check
        zip_bytes = create_zip_archive({"tool.exe": make_dummy_pe()})
        data_zip = {"file": (io.BytesIO(zip_bytes), "package.zip")}
        resp_zip = client.post("/analyze-archive", data=data_zip, content_type="multipart/form-data")
        assert resp_zip.status_code == 200
        json_data = resp_zip.get_json()
        assert "verdict" in json_data
        assert "total_files" in json_data
        assert "files" in json_data
