import pefile
import joblib
import math
import re
from pathlib import Path


MODEL_FILE = "malware_model.pkl"


def calculate_entropy(data):
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


def extract_strings(data):
    # Basic printable ASCII strings
    strings = re.findall(rb"[\x20-\x7e]{4,}", data)

    lengths = [len(s) for s in strings]

    numstrings = len(strings)

    avlength = (
        sum(lengths) / len(lengths)
        if lengths else 0
    )

    paths = 0
    urls = 0

    for s in strings:
        text = s.decode("ascii", errors="ignore").lower()

        if (
            "\\" in text
            or "/" in text
            or re.search(r"[a-z]:", text)
        ):
            paths += 1

        if (
            "http://" in text
            or "https://" in text
            or "www." in text
        ):
            urls += 1

    return numstrings, avlength, paths, urls


def extract_features(file_path):

    pe = pefile.PE(file_path)

    file_size = Path(file_path).stat().st_size

    # -------------------------
    # GENERAL
    # -------------------------

    size = file_size

    vsize = getattr(
        pe.OPTIONAL_HEADER,
        "SizeOfImage",
        0
    )

    imports = 0

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        imports = sum(
            len(entry.imports)
            for entry in pe.DIRECTORY_ENTRY_IMPORT
        )

    exports = 0

    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exports = len(
            pe.DIRECTORY_ENTRY_EXPORT.symbols
        )

    has_debug = int(
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]
        ].Size > 0
    )

    has_relocations = int(
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]
        ].Size > 0
    )

    has_resources = int(
        hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")
    )

    has_signature = int(
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ].Size > 0
    )

    # -------------------------
    # STRINGS
    # -------------------------

    with open(file_path, "rb") as f:
        raw_data = f.read()

    numstrings, avlength, paths, urls = extract_strings(
        raw_data
    )

    # -------------------------
    # SECTIONS
    # -------------------------

    sections = pe.sections

    entropies = [
        calculate_entropy(section.get_data())
        for section in sections
    ]

    raw_sizes = [
        section.SizeOfRawData
        for section in sections
    ]

    virtual_sizes = [
        section.Misc_VirtualSize
        for section in sections
    ]

    number_of_sections = len(sections)

    section_entropy_mean = (
        sum(entropies) / len(entropies)
        if entropies else 0
    )

    section_entropy_max = (
        max(entropies)
        if entropies else 0
    )

    section_raw_size_mean = (
        sum(raw_sizes) / len(raw_sizes)
        if raw_sizes else 0
    )

    section_raw_size_max = (
        max(raw_sizes)
        if raw_sizes else 0
    )

    section_virtual_size_mean = (
        sum(virtual_sizes) / len(virtual_sizes)
        if virtual_sizes else 0
    )

    section_virtual_size_max = (
        max(virtual_sizes)
        if virtual_sizes else 0
    )

    # -------------------------
    # HEADER
    # -------------------------

    coff_timestamp = (
        pe.FILE_HEADER.TimeDateStamp
    )

    coff_characteristics_count = (
        int(pe.FILE_HEADER.Characteristics).bit_count()
    )

    sizeof_code = (
        pe.OPTIONAL_HEADER.SizeOfCode
    )

    sizeof_headers = (
        pe.OPTIONAL_HEADER.SizeOfHeaders
    )

    dll_characteristics_count = (
        int(pe.OPTIONAL_HEADER.DllCharacteristics).bit_count()
    )

    # -------------------------
    # 24 FEATURES
    # -------------------------

    return {
        "size": size,
        "vsize": vsize,
        "imports": imports,
        "exports": exports,
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


def predict(file_path):

    saved = joblib.load(MODEL_FILE)

    model = saved["model"]
    features = saved["features"]

    extracted = extract_features(file_path)

    X = [[
        extracted[name]
        for name in features
    ]]

    prediction = model.predict(X)[0]
    probability = model.predict_proba(X)[0]

    if prediction == 1:
        result = "MALICIOUS"
    else:
        result = "BENIGN"

    print("\n==============================")
    print("MALWARE ANALYSIS RESULT")
    print("==============================")

    print(f"File        : {file_path}")
    print(f"Prediction  : {result}")

    print(
        f"Benign      : {probability[0] * 100:.2f}%"
    )

    print(
        f"Malicious   : {probability[1] * 100:.2f}%"
    )

    print("\nExtracted Features:")

    for name in features:
        print(
            f"{name:30} : {extracted[name]}"
        )


if __name__ == "__main__":

    file_path = input(
        "Enter EXE/DLL path: "
    ).strip('"')

    try:
        predict(file_path)

    except Exception as e:
        print("\nERROR:")
        print(e)