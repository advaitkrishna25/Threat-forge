import math
import re
import pefile
from typing import Dict, Any, List, Tuple

SUSPICIOUS_APIS = {
    "VirtualAlloc": "Allocates executable/writeable memory dynamically, frequently leveraged by shellcode and packers.",
    "VirtualAllocEx": "Allocates memory in remote processes, a key primitive for process injection.",
    "WriteProcessMemory": "Writes arbitrary bytes to the virtual memory of a target process.",
    "CreateRemoteThread": "Executes malicious code inside a remote process context.",
    "SetWindowsHookExA": "Installs global keyboard/mouse hooks, commonly used for keylogging or thread hijacking.",
    "SetWindowsHookExW": "Installs global keyboard/mouse hooks, commonly used for keylogging or thread hijacking.",
    "QueueUserAPC": "Queues asynchronous procedure calls into suspended threads (Early Bird injection).",
    "NtUnmapViewOfSection": "Unmaps legitimate executable memory from a process (Process Hollowing).",
    "ZwUnmapViewOfSection": "Kernel routine to unmap section views in process hollowing attacks.",
    "IsDebuggerPresent": "Detects active debugging environments to evade dynamic analysis.",
    "CheckRemoteDebuggerPresent": "Queries the kernel for remote debugger handles.",
    "HttpSendRequestA": "Transmits HTTP network traffic, common in C2 communications.",
    "HttpSendRequestW": "Transmits HTTP network traffic, common in C2 communications.",
    "URLDownloadToFileA": "Downloads secondary payloads directly from external domains.",
    "URLDownloadToFileW": "Downloads secondary payloads directly from external domains.",
}


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = [0] * 256
    for byte in data:
        counts[byte] += 1

    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


def extract_strings(data: bytes) -> Tuple[int, float, int, int]:
    # Basic printable ASCII strings (matches filetester.py)
    strings = re.findall(rb"[\x20-\x7e]{4,}", data)
    lengths = [len(s) for s in strings]
    numstrings = len(strings)
    avlength = sum(lengths) / len(lengths) if lengths else 0.0

    paths = 0
    urls = 0

    for s in strings:
        text = s.decode("ascii", errors="ignore").lower()
        if "\\" in text or "/" in text or re.search(r"[a-z]:", text):
            paths += 1
        if "http://" in text or "https://" in text or "www." in text:
            urls += 1

    return numstrings, avlength, paths, urls


def extract_pe_features_from_bytes(raw_data: bytes) -> Dict[str, Any]:
    """
    Extracts all 24 PE features from in-memory byte buffer without writing to disk.
    Also extracts indicators and contextual analysis.
    """
    pe = pefile.PE(data=raw_data)

    file_size = len(raw_data)
    size = file_size

    # General PE properties
    vsize = getattr(pe.OPTIONAL_HEADER, "SizeOfImage", 0)

    imports_count = 0
    imported_function_names = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports_count += len(entry.imports)
            for imp in entry.imports:
                if imp.name:
                    name_str = imp.name.decode("ascii", errors="ignore")
                    imported_function_names.append(name_str)

    exports_count = 0
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
        exports_count = len(getattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols", []))

    # Data directories safety checks
    data_dirs = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", [])

    def has_directory_entry(dir_name: str) -> int:
        idx = pefile.DIRECTORY_ENTRY.get(dir_name)
        if idx is not None and idx < len(data_dirs):
            return int(data_dirs[idx].Size > 0)
        return 0

    has_debug = has_directory_entry("IMAGE_DIRECTORY_ENTRY_DEBUG")
    has_relocations = has_directory_entry("IMAGE_DIRECTORY_ENTRY_BASERELOC")
    has_resources = int(hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"))
    has_signature = has_directory_entry("IMAGE_DIRECTORY_ENTRY_SECURITY")

    # Strings
    numstrings, avlength, paths, urls = extract_strings(raw_data)

    # Sections analysis
    sections = getattr(pe, "sections", [])
    entropies = []
    raw_sizes = []
    virtual_sizes = []

    high_entropy_sections = []
    for section in sections:
        sec_name = section.Name.decode("ascii", errors="ignore").strip("\x00")
        try:
            sec_data = section.get_data()
            e = calculate_entropy(sec_data)
        except Exception:
            e = 0.0
        entropies.append(e)
        if e >= 7.2:
            high_entropy_sections.append((sec_name, e))

        raw_sz = getattr(section, "SizeOfRawData", 0)
        virt_sz = getattr(section, "Misc_VirtualSize", 0)
        raw_sizes.append(raw_sz)
        virtual_sizes.append(virt_sz)

    number_of_sections = len(sections)
    section_entropy_mean = sum(entropies) / len(entropies) if entropies else 0.0
    section_entropy_max = max(entropies) if entropies else 0.0
    section_raw_size_mean = sum(raw_sizes) / len(raw_sizes) if raw_sizes else 0.0
    section_raw_size_max = max(raw_sizes) if raw_sizes else 0.0
    section_virtual_size_mean = sum(virtual_sizes) / len(virtual_sizes) if virtual_sizes else 0.0
    section_virtual_size_max = max(virtual_sizes) if virtual_sizes else 0.0

    # Header characteristics
    coff_timestamp = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
    coff_characteristics = getattr(pe.FILE_HEADER, "Characteristics", 0)
    coff_characteristics_count = int(coff_characteristics).bit_count()

    sizeof_code = getattr(pe.OPTIONAL_HEADER, "SizeOfCode", 0)
    sizeof_headers = getattr(pe.OPTIONAL_HEADER, "SizeOfHeaders", 0)
    dll_characteristics = getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0)
    dll_characteristics_count = int(dll_characteristics).bit_count()

    features_dict = {
        "size": size,
        "vsize": vsize,
        "imports": imports_count,
        "exports": exports_count,
        "has_debug": has_debug,
        "has_relocations": has_relocations,
        "has_resources": has_resources,
        "has_signature": has_signature,

        "numstrings": numstrings,
        "avlength": avlength,
        "paths": paths,
        "urls": urls,

        "number_of_sections": number_of_sections,
        "section_entropy_mean": section_entropy_mean,
        "section_entropy_max": section_entropy_max,
        "section_raw_size_mean": section_raw_size_mean,
        "section_raw_size_max": section_raw_size_max,
        "section_virtual_size_mean": section_virtual_size_mean,
        "section_virtual_size_max": section_virtual_size_max,

        "coff_timestamp": coff_timestamp,
        "coff_characteristics_count": coff_characteristics_count,
        "sizeof_code": sizeof_code,
        "sizeof_headers": sizeof_headers,
        "dll_characteristics_count": dll_characteristics_count,
    }

    # Generate heuristic indicators
    indicators: List[Dict[str, str]] = []

    if section_entropy_max >= 7.2:
        sec_str = ", ".join([f"'{s[0]}' ({s[1]:.2f})" for s in high_entropy_sections]) or f"{section_entropy_max:.2f}"
        indicators.append({
            "severity": "critical" if section_entropy_max >= 7.5 else "high",
            "title": "High Section Entropy (Packing/Encryption)",
            "detail": f"Max section entropy is {section_entropy_max:.2f} in {sec_str}. Values above 7.2 strongly indicate encrypted payloads, obfuscated bytecode, or runtime packers (e.g., UPX, Themida)."
        })

    if has_signature == 0:
        indicators.append({
            "severity": "medium",
            "title": "Unsigned Executable",
            "detail": "The binary lacks an Authenticode security certificate in IMAGE_DIRECTORY_ENTRY_SECURITY, a common trait in custom malware and unsigned loaders."
        })
    else:
        indicators.append({
            "severity": "low",
            "title": "Authenticode Directory Present",
            "detail": "The PE contains a security certificate directory entry, typical of signed vendor software."
        })

    if has_debug == 0:
        indicators.append({
            "severity": "medium",
            "title": "Debug Directory Stripped",
            "detail": "The binary lacks a debug directory (IMAGE_DIRECTORY_ENTRY_DEBUG), frequently stripped by malicious authors to complicate reverse engineering."
        })

    # Flag suspicious APIs found in import table
    flagged_apis = []
    for api_name, desc in SUSPICIOUS_APIS.items():
        if api_name in imported_function_names:
            flagged_apis.append((api_name, desc))

    if flagged_apis:
        api_names_str = ", ".join([a[0] for a in flagged_apis[:4]])
        indicators.append({
            "severity": "high",
            "title": f"Suspicious API Imports ({len(flagged_apis)})",
            "detail": f"Detected calls to injection/evasion routines: {api_names_str}. {flagged_apis[0][1]}"
        })

    if urls > 10:
        indicators.append({
            "severity": "medium",
            "title": "Elevated Embedded URL Count",
            "detail": f"Found {urls} web URLs embedded within ASCII strings, characteristic of downloaders, droppers, or C2 beacon endpoints."
        })

    if number_of_sections > 8 or number_of_sections < 2:
        indicators.append({
            "severity": "low",
            "title": f"Atypical Section Count ({number_of_sections})",
            "detail": f"Standard PE binaries typically contain 4-6 sections (.text, .rdata, .data, .rsrc). This binary has {number_of_sections}."
        })

    # Heuristic top contributors based on model weight tendencies
    top_contributors: List[Dict[str, str]] = []
    if section_entropy_max >= 7.0:
        top_contributors.append({
            "feature": "section_entropy_max",
            "impact": f"{section_entropy_max:.2f}",
            "direction": "Malicious"
        })
    if has_signature == 0:
        top_contributors.append({
            "feature": "has_signature",
            "impact": "0 (Unsigned)",
            "direction": "Malicious"
        })
    if has_debug == 0:
        top_contributors.append({
            "feature": "has_debug",
            "impact": "0 (Stripped)",
            "direction": "Malicious"
        })
    if imports_count < 20 and size > 50000:
        top_contributors.append({
            "feature": "imports",
            "impact": f"{imports_count} (Low API footprint)",
            "direction": "Malicious"
        })
    elif imports_count > 150:
        top_contributors.append({
            "feature": "imports",
            "impact": f"{imports_count} APIs",
            "direction": "Benign"
        })
    if has_signature == 1:
        top_contributors.append({
            "feature": "has_signature",
            "impact": "1 (Signed)",
            "direction": "Benign"
        })
    if has_debug == 1:
        top_contributors.append({
            "feature": "has_debug",
            "impact": "1 (Debug table present)",
            "direction": "Benign"
        })

    return {
        "features": features_dict,
        "indicators": indicators,
        "top_contributors": top_contributors[:5]
    }
