import os
import shutil
import tempfile
import zipfile
import time
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("archive-scanner")

# Configurable Safety Limits
DEFAULT_CONFIG = {
    # Max total uncompressed size across all extracted files (100 MB)
    "MAX_TOTAL_EXTRACTED_SIZE": int(os.getenv("MAX_TOTAL_EXTRACTED_SIZE", 100 * 1024 * 1024)),
    # Max size for any individual extracted file (50 MB)
    "MAX_INDIVIDUAL_FILE_SIZE": int(os.getenv("MAX_INDIVIDUAL_FILE_SIZE", 50 * 1024 * 1024)),
    # Max total files across archive and nested archives
    "MAX_FILE_COUNT": int(os.getenv("MAX_FILE_COUNT", 250)),
    # Max compression ratio (uncompressed / compressed) to block zip bombs
    "MAX_COMPRESSION_RATIO": float(os.getenv("MAX_COMPRESSION_RATIO", 100.0)),
    # Max recursion depth for nested zip archives
    "MAX_RECURSION_DEPTH": int(os.getenv("MAX_RECURSION_DEPTH", 3)),
    # Processing timeout in seconds
    "PROCESSING_TIMEOUT_SECONDS": float(os.getenv("PROCESSING_TIMEOUT_SECONDS", 30.0)),
}

SUPPORTED_EXTENSIONS = {".exe", ".dll"}


class ArchiveSecurityException(Exception):
    """Raised when an archive violates safety constraints (Zip Slip, Zip Bomb, etc.)."""
    pass


class ArchiveLimitExceededException(Exception):
    """Raised when resource limits (size, file count, ratio, time) are exceeded."""
    pass


def is_path_traversal(target_dir: str, filename: str) -> bool:
    """
    Prevents Zip Slip / path traversal attacks.
    Ensures the canonical resolved path of the extracted file is strictly
    contained inside the intended target directory.
    """
    # Reject absolute paths, drive letters, or obvious traversal patterns immediately
    if filename.startswith(("/", "\\")):
        return True
    if len(filename) > 1 and filename[1] == ":":
        return True

    # Normalize target directory
    resolved_target_dir = os.path.abspath(target_dir)

    # Normalize destination path
    dest_path = os.path.abspath(os.path.join(resolved_target_dir, filename))

    # Check prefix containment
    prefix = resolved_target_dir + os.sep
    if not (dest_path == resolved_target_dir or dest_path.startswith(prefix)):
        return True

    return False


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).digest().hex()


def compute_file_sha256(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class ArchiveScanner:
    def __init__(self, predict_pe_fn, config: Optional[Dict[str, Any]] = None):
        """
        :param predict_pe_fn: Callable(raw_bytes: bytes, filename: str) -> dict
               Expected to return dict with verdict, model_score, threat_level,
               features, indicators, top_contributors, error.
        :param config: Optional custom configuration dictionary.
        """
        self.predict_pe_fn = predict_pe_fn
        self.config = {**DEFAULT_CONFIG, **(config or {})}

    def scan_archive_bytes(self, zip_bytes: bytes, archive_filename: str = "archive.zip") -> Dict[str, Any]:
        """
        Scans a ZIP archive provided as raw bytes.
        Creates an isolated temporary directory, performs pre-extraction inspection,
        safely unpacks files within strict security limits, scans supported executables,
        and guarantees cleanup of all temporary files via a try/finally block.
        """
        start_time = time.time()
        archive_sha256 = compute_sha256(zip_bytes)
        archive_size = len(zip_bytes)
        analyzed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Validate that the byte sequence is at least a candidate zip
        if len(zip_bytes) < 4:
            return self._build_report(
                archive_filename=archive_filename,
                analyzed_at=analyzed_at,
                archive_sha256=archive_sha256,
                archive_size=archive_size,
                files=[],
                archive_error="Invalid archive: File is too small to be a valid ZIP archive.",
                verdict="INCONCLUSIVE"
            )

        # Create isolated temporary directory
        temp_dir = tempfile.mkdtemp(prefix="threatforge_scan_")
        logger.info(f"Created temporary directory for archive scan: {temp_dir}")

        try:
            zip_path = os.path.join(temp_dir, "input.zip")
            with open(zip_path, "wb") as f:
                f.write(zip_bytes)

            # Pre-flight check: is it a valid zip file?
            if not zipfile.is_zipfile(zip_path):
                return self._build_report(
                    archive_filename=archive_filename,
                    analyzed_at=analyzed_at,
                    archive_sha256=archive_sha256,
                    archive_size=archive_size,
                    files=[],
                    archive_error="Invalid or corrupted archive: Header does not match standard ZIP signature.",
                    verdict="INCONCLUSIVE"
                )

            # State tracking across recursive extraction
            state = {
                "total_uncompressed_size": 0,
                "total_file_count": 0,
                "start_time": start_time,
                "extracted_files": [],  # List of file inspection dictionaries
                "had_encrypted": False,
                "had_inconclusive": False,
                "had_security_violation": False,
                "security_error": None,
            }

            self._process_zip_file(
                zip_path=zip_path,
                current_dir=temp_dir,
                state=state,
                parent_prefix="",
                depth=0
            )

            if state["security_error"]:
                return self._build_report(
                    archive_filename=archive_filename,
                    analyzed_at=analyzed_at,
                    archive_sha256=archive_sha256,
                    archive_size=archive_size,
                    files=state["extracted_files"],
                    archive_error=state["security_error"],
                    verdict="INCONCLUSIVE"
                )

            return self._aggregate_results(
                archive_filename=archive_filename,
                analyzed_at=analyzed_at,
                archive_sha256=archive_sha256,
                archive_size=archive_size,
                files=state["extracted_files"],
                had_encrypted=state["had_encrypted"],
                had_inconclusive=state["had_inconclusive"]
            )

        except ArchiveSecurityException as e:
            logger.warning(f"Archive security violation in {archive_filename}: {e}")
            return self._build_report(
                archive_filename=archive_filename,
                analyzed_at=analyzed_at,
                archive_sha256=archive_sha256,
                archive_size=archive_size,
                files=state.get("extracted_files", []) if "state" in locals() else [],
                archive_error=f"Security violation detected: {str(e)}",
                verdict="INCONCLUSIVE"
            )

        except ArchiveLimitExceededException as e:
            logger.warning(f"Archive resource limit exceeded in {archive_filename}: {e}")
            return self._build_report(
                archive_filename=archive_filename,
                analyzed_at=analyzed_at,
                archive_sha256=archive_sha256,
                archive_size=archive_size,
                files=state.get("extracted_files", []) if "state" in locals() else [],
                archive_error=f"Resource limit exceeded: {str(e)}",
                verdict="INCONCLUSIVE"
            )

        except Exception as e:
            logger.error(f"Unexpected error processing archive {archive_filename}: {e}", exc_info=True)
            return self._build_report(
                archive_filename=archive_filename,
                analyzed_at=analyzed_at,
                archive_sha256=archive_sha256,
                archive_size=archive_size,
                files=state.get("extracted_files", []) if "state" in locals() else [],
                archive_error=f"Archive extraction failed: {str(e)}",
                verdict="INCONCLUSIVE"
            )

        finally:
            # Secure cleanup: Ensure temporary files are ALWAYS wiped from disk
            try:
                if os.path.exists(temp_dir):
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    logger.info(f"Cleaned up temporary directory: {temp_dir}")
            except Exception as clean_err:
                logger.error(f"Failed to clean up temp dir {temp_dir}: {clean_err}")

    def _process_zip_file(
        self,
        zip_path: str,
        current_dir: str,
        state: Dict[str, Any],
        parent_prefix: str = "",
        depth: int = 0
    ) -> None:
        """
        Recursively processes a zip file. Inspects members, enforces limits,
        and triggers PE analysis for supported executables.
        """
        # Enforce processing timeout
        if time.time() - state["start_time"] > self.config["PROCESSING_TIMEOUT_SECONDS"]:
            raise ArchiveLimitExceededException(
                f"Processing time exceeded maximum limit of {self.config['PROCESSING_TIMEOUT_SECONDS']} seconds."
            )

        # Enforce recursion depth limit
        if depth > self.config["MAX_RECURSION_DEPTH"]:
            state["had_inconclusive"] = True
            state["extracted_files"].append({
                "path": f"{parent_prefix}[nested_archive_exceeded_depth]",
                "size": 0,
                "file_type": "archive/zip",
                "supported": False,
                "verdict": "INCONCLUSIVE",
                "model_score": None,
                "threat_level": "UNKNOWN",
                "indicators": [],
                "top_contributors": [],
                "error": f"Recursion depth limit ({self.config['MAX_RECURSION_DEPTH']}) exceeded for nested archive.",
                "sha256": None
            })
            return

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                infolist = zf.infolist()

                # Step 1: Pre-inspection of all archive members before extracting
                for info in infolist:
                    # Enforce timeout
                    if time.time() - state["start_time"] > self.config["PROCESSING_TIMEOUT_SECONDS"]:
                        raise ArchiveLimitExceededException(
                            f"Processing time exceeded maximum limit of {self.config['PROCESSING_TIMEOUT_SECONDS']} seconds."
                        )

                    # Check for Zip Slip / Path Traversal
                    if is_path_traversal(current_dir, info.filename):
                        state["had_security_violation"] = True
                        state["security_error"] = f"Zip Slip path traversal attempt detected in member '{info.filename}'."
                        raise ArchiveSecurityException(state["security_error"])

                    # If directory, skip extraction calculation
                    if info.is_dir() or info.filename.endswith("/"):
                        continue

                    # File count limit check
                    state["total_file_count"] += 1
                    if state["total_file_count"] > self.config["MAX_FILE_COUNT"]:
                        raise ArchiveLimitExceededException(
                            f"Total file count exceeded limit ({self.config['MAX_FILE_COUNT']} files). Potential zip bomb."
                        )

                    # Individual file size limit check
                    if info.file_size > self.config["MAX_INDIVIDUAL_FILE_SIZE"]:
                        raise ArchiveLimitExceededException(
                            f"File '{info.filename}' size ({info.file_size} bytes) exceeds max individual limit ({self.config['MAX_INDIVIDUAL_FILE_SIZE']} bytes)."
                        )

                    # Total uncompressed size limit check
                    state["total_uncompressed_size"] += info.file_size
                    if state["total_uncompressed_size"] > self.config["MAX_TOTAL_EXTRACTED_SIZE"]:
                        raise ArchiveLimitExceededException(
                            f"Total extracted size exceeded limit ({self.config['MAX_TOTAL_EXTRACTED_SIZE']} bytes). Potential zip bomb."
                        )

                    # Compression ratio check (detect zip bombs with high compression ratio)
                    if info.compress_size > 0 and info.file_size > 500_000:
                        ratio = info.file_size / info.compress_size
                        if ratio > self.config["MAX_COMPRESSION_RATIO"]:
                            raise ArchiveLimitExceededException(
                                f"Compression ratio {ratio:.1f}:1 for '{info.filename}' exceeds threshold {self.config['MAX_COMPRESSION_RATIO']}:1. Zip bomb suspected."
                            )

                # Step 2: Extract and inspect members
                for info in infolist:
                    if info.is_dir() or info.filename.endswith("/"):
                        continue

                    rel_path = f"{parent_prefix}{info.filename}"
                    ext = os.path.splitext(info.filename)[1].lower()

                    # Check for password protection / encryption
                    is_encrypted = (info.flag_bits & 0x1) != 0
                    if is_encrypted:
                        state["had_encrypted"] = True
                        state["had_inconclusive"] = True
                        state["extracted_files"].append({
                            "path": rel_path,
                            "size": info.file_size,
                            "file_type": ext or "unknown",
                            "supported": ext in SUPPORTED_EXTENSIONS,
                            "verdict": "INCONCLUSIVE",
                            "model_score": None,
                            "threat_level": "UNKNOWN",
                            "indicators": [{
                                "severity": "medium",
                                "title": "Password Protected Archive Member",
                                "detail": "File is encrypted. Extraction and analysis require a password."
                            }],
                            "top_contributors": [],
                            "error": "Password protected archive member. Content requires a password to inspect.",
                            "sha256": None
                        })
                        continue

                    # Safely extract file bytes into memory/disk within isolated directory
                    try:
                        file_data = zf.read(info.filename)
                    except RuntimeError as re_err:
                        # Zipfile raises RuntimeError for encrypted entries when opening
                        if "password" in str(re_err).lower() or "encrypted" in str(re_err).lower():
                            state["had_encrypted"] = True
                            state["had_inconclusive"] = True
                            state["extracted_files"].append({
                                "path": rel_path,
                                "size": info.file_size,
                                "file_type": ext or "unknown",
                                "supported": ext in SUPPORTED_EXTENSIONS,
                                "verdict": "INCONCLUSIVE",
                                "model_score": None,
                                "threat_level": "UNKNOWN",
                                "indicators": [],
                                "top_contributors": [],
                                "error": "Password protected archive member.",
                                "sha256": None
                            })
                            continue
                        raise

                    file_sha = compute_sha256(file_data)

                    # Handle Nested ZIP Archives
                    if ext == ".zip":
                        nested_subfolder = os.path.join(current_dir, f"nested_{depth}_{hash(rel_path) & 0xfffffff}")
                        os.makedirs(nested_subfolder, exist_ok=True)
                        nested_zip_path = os.path.join(nested_subfolder, "nested.zip")
                        with open(nested_zip_path, "wb") as f_nested:
                            f_nested.write(file_data)

                        if zipfile.is_zipfile(nested_zip_path):
                            # Recursively process the nested zip
                            self._process_zip_file(
                                zip_path=nested_zip_path,
                                current_dir=nested_subfolder,
                                state=state,
                                parent_prefix=f"{rel_path}/",
                                depth=depth + 1
                            )
                        else:
                            state["had_inconclusive"] = True
                            state["extracted_files"].append({
                                "path": rel_path,
                                "size": len(file_data),
                                "file_type": "archive/zip",
                                "supported": False,
                                "verdict": "INCONCLUSIVE",
                                "model_score": None,
                                "threat_level": "UNKNOWN",
                                "indicators": [],
                                "top_contributors": [],
                                "error": "Nested ZIP file is corrupted or not a valid archive.",
                                "sha256": file_sha
                            })
                        continue

                    # Handle Supported Executables (.exe, .dll)
                    if ext in SUPPORTED_EXTENSIONS:
                        # Write temporarily into current isolated folder (never executed)
                        extracted_dest = os.path.join(current_dir, f"file_{state['total_file_count']}{ext}")
                        with open(extracted_dest, "wb") as out_f:
                            out_f.write(file_data)

                        # Validate MZ magic bytes (0x4D 0x5A)
                        if len(file_data) < 2 or file_data[0] != 0x4d or file_data[1] != 0x5a:
                            state["had_inconclusive"] = True
                            state["extracted_files"].append({
                                "path": rel_path,
                                "size": len(file_data),
                                "file_type": ext,
                                "supported": True,
                                "verdict": "INCONCLUSIVE",
                                "model_score": None,
                                "threat_level": "UNKNOWN",
                                "indicators": [{
                                    "severity": "medium",
                                    "title": "Invalid PE Header",
                                    "detail": "File has executable extension but lacks valid MZ magic signature."
                                }],
                                "top_contributors": [],
                                "error": "Invalid executable format: File header lacks valid MZ magic bytes (4D 5A).",
                                "sha256": file_sha
                            })
                            continue

                        # Execute PE Feature Extraction and ML Prediction
                        try:
                            pe_result = self.predict_pe_fn(file_data, os.path.basename(info.filename))
                            pe_error = pe_result.get("error")
                            pe_verdict = pe_result.get("verdict", "UNKNOWN")

                            if pe_error or pe_verdict == "UNKNOWN":
                                state["had_inconclusive"] = True
                                final_file_verdict = "INCONCLUSIVE"
                            else:
                                # Check if suspicious: e.g. medium score or elevated threat
                                score = pe_result.get("model_score", 0.0)
                                if pe_verdict == "MALICIOUS":
                                    final_file_verdict = "MALICIOUS"
                                elif score >= 0.35 or pe_result.get("threat_level") in ("HIGH", "MEDIUM"):
                                    # Flagged as suspicious based on existing probability logic
                                    final_file_verdict = "SUSPICIOUS"
                                else:
                                    final_file_verdict = "BENIGN"

                            state["extracted_files"].append({
                                "path": rel_path,
                                "size": len(file_data),
                                "file_type": ext,
                                "supported": True,
                                "verdict": final_file_verdict,
                                "model_score": pe_result.get("model_score"),
                                "threat_level": pe_result.get("threat_level", "UNKNOWN"),
                                "indicators": pe_result.get("indicators", []),
                                "top_contributors": pe_result.get("top_contributors", []),
                                "error": pe_error,
                                "sha256": file_sha
                            })

                        except Exception as pe_err:
                            logger.error(f"Prediction failed for {rel_path}: {pe_err}", exc_info=True)
                            state["had_inconclusive"] = True
                            state["extracted_files"].append({
                                "path": rel_path,
                                "size": len(file_data),
                                "file_type": ext,
                                "supported": True,
                                "verdict": "INCONCLUSIVE",
                                "model_score": None,
                                "threat_level": "UNKNOWN",
                                "indicators": [],
                                "top_contributors": [],
                                "error": f"Analysis failed: {str(pe_err)}",
                                "sha256": file_sha
                            })

                    else:
                        # Unsupported File Type: Disclose clearly without classifying as clean
                        state["extracted_files"].append({
                            "path": rel_path,
                            "size": len(file_data),
                            "file_type": ext or "non-pe",
                            "supported": False,
                            "verdict": "UNSUPPORTED",
                            "model_score": None,
                            "threat_level": "UNKNOWN",
                            "indicators": [],
                            "top_contributors": [],
                            "error": f"Unsupported file format ({ext or 'unknown'}). The static PE model only evaluates Windows PE binaries (.exe, .dll).",
                            "sha256": file_sha
                        })

        except zipfile.BadZipFile as bz_err:
            state["had_inconclusive"] = True
            raise ArchiveSecurityException(f"Corrupted or invalid ZIP structure: {bz_err}")

    def _aggregate_results(
        self,
        archive_filename: str,
        analyzed_at: str,
        archive_sha256: str,
        archive_size: int,
        files: List[Dict[str, Any]],
        had_encrypted: bool,
        had_inconclusive: bool
    ) -> Dict[str, Any]:
        """
        Determines archive-level verdict and compiles scan report based on Section 4 rules:
        - Malicious: At least one file is classified as malicious.
        - Suspicious: No malicious file is detected, but one or more files are flagged as suspicious.
        - Inconclusive: No malicious or suspicious file is detected, but relevant files could not be analyzed or contents remain uninspected.
        - No malware detected: All supported files were successfully scanned and no malware was detected, with unsupported files clearly disclosed.
        """
        total_discovered = len(files)
        supported_scanned = [f for f in files if f.get("supported")]

        malicious_files = [f for f in supported_scanned if f.get("verdict") == "MALICIOUS"]
        suspicious_files = [f for f in supported_scanned if f.get("verdict") == "SUSPICIOUS"]
        clean_files = [f for f in supported_scanned if f.get("verdict") == "BENIGN"]
        inconclusive_files = [f for f in files if f.get("verdict") in ("INCONCLUSIVE", "ERROR")]
        unsupported_files = [f for f in files if f.get("verdict") == "UNSUPPORTED"]

        malicious_count = len(malicious_files)
        suspicious_count = len(suspicious_files)
        clean_count = len(clean_files)
        error_count = len(inconclusive_files)
        unsupported_count = len(unsupported_files)

        summary_notes = []

        if malicious_count > 0:
            final_verdict = "MALICIOUS"
            summary_notes.append(
                f"Malicious threat detected: {malicious_count} executable(s) inside archive exhibited strong malicious PE characteristics matching known malware models."
            )
        elif suspicious_count > 0:
            final_verdict = "SUSPICIOUS"
            summary_notes.append(
                f"Suspicious executable(s) flagged: {suspicious_count} file(s) exhibited elevated risk indicators or borderline anomaly scores."
            )
        elif had_encrypted or had_inconclusive or error_count > 0:
            final_verdict = "INCONCLUSIVE"
            reasons = []
            if had_encrypted:
                reasons.append("encrypted/password-protected members prevented inspection")
            if error_count > 0:
                reasons.append(f"{error_count} file(s) failed structural PE parsing")
            summary_notes.append(
                f"Analysis inconclusive: Archive contains uninspected or unparseable items ({', '.join(reasons)})."
            )
        else:
            final_verdict = "NO_MALWARE_DETECTED"
            if len(supported_scanned) > 0:
                summary_notes.append(
                    f"No malware detected across {len(supported_scanned)} scanned executable(s). Note: This does not guarantee safety against unmodeled threats."
                )
            else:
                summary_notes.append(
                    "No Windows PE executables (.exe, .dll) found inside archive. Unsupported file types could not be evaluated by the PE classifier."
                )

        if unsupported_count > 0:
            summary_notes.append(
                f"Archive contains {unsupported_count} unsupported file(s) ({', '.join(sorted(list(set(f.get('file_type', '') for f in unsupported_files))))}). These were NOT classified as clean."
            )

        return self._build_report(
            archive_filename=archive_filename,
            analyzed_at=analyzed_at,
            archive_sha256=archive_sha256,
            archive_size=archive_size,
            files=files,
            archive_error=None,
            verdict=final_verdict,
            total_discovered=total_discovered,
            scanned_files_count=len(supported_scanned),
            malicious_count=malicious_count,
            suspicious_count=suspicious_count,
            clean_count=clean_count,
            unsupported_count=unsupported_count,
            error_count=error_count,
            summary_notes=" ".join(summary_notes)
        )

    def _build_report(
        self,
        archive_filename: str,
        analyzed_at: str,
        archive_sha256: str,
        archive_size: int,
        files: List[Dict[str, Any]],
        archive_error: Optional[str] = None,
        verdict: str = "INCONCLUSIVE",
        total_discovered: int = 0,
        scanned_files_count: int = 0,
        malicious_count: int = 0,
        suspicious_count: int = 0,
        clean_count: int = 0,
        unsupported_count: int = 0,
        error_count: int = 0,
        summary_notes: str = ""
    ) -> Dict[str, Any]:
        """Builds a standardized archive scan report JSON structure."""
        if not summary_notes and archive_error:
            summary_notes = archive_error

        # If files were provided and counts were not calculated:
        if files and total_discovered == 0:
            total_discovered = len(files)
            scanned_files_count = len([f for f in files if f.get("supported")])
            malicious_count = len([f for f in files if f.get("verdict") == "MALICIOUS"])
            suspicious_count = len([f for f in files if f.get("verdict") == "SUSPICIOUS"])
            clean_count = len([f for f in files if f.get("verdict") == "BENIGN"])
            error_count = len([f for f in files if f.get("verdict") in ("INCONCLUSIVE", "ERROR")])
            unsupported_count = len([f for f in files if f.get("verdict") == "UNSUPPORTED"])

        return {
            "archive_filename": archive_filename,
            "analyzed_at": analyzed_at,
            "archive_sha256": archive_sha256,
            "archive_size": archive_size,
            "verdict": verdict,
            "total_files": total_discovered,
            "scanned_files_count": scanned_files_count,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "clean_count": clean_count,
            "unsupported_count": unsupported_count,
            "error_count": error_count,
            "summary_notes": summary_notes,
            "error": archive_error,
            "files": files,
        }
