import os
from pathlib import Path

from modules.file_analyzer import detect_file_type_from_signature


def analyze_signature(file_path: str):
    if not os.path.exists(file_path):
        return {"tool_name": "Signature Analysis", "available": False, "status": "error", "findings": []}

    with open(file_path, "rb") as handle:
        data = handle.read()

    expected_extension = Path(file_path).suffix.lower().lstrip(".")
    actual_type = detect_file_type_from_signature(data)
    findings = []

    if actual_type and expected_extension and actual_type != expected_extension and not (expected_extension == "jpg" and actual_type == "jpeg"):
        findings.append({
            "finding_name": "Extension mismatch",
            "description": f"The file signature indicates {actual_type}, but the extension is {expected_extension}.",
            "severity": "medium",
            "analysis_status": "suspicious_heuristic_indicator",
        })

    if data and data[:8] != b"" and len(data) > 16:
        tail = data[-16:]
        if any(signature in tail for signature in [b"PK\x03\x04", b"MZ", b"\x89PNG", b"%PDF"]):
            findings.append({
                "finding_name": "Unexpected appended content",
                "description": "Trailing bytes match a file signature different from the header, which may indicate appended or layered content.",
                "severity": "medium",
                "analysis_status": "tool_reported_embedded_data",
            })

    if not findings:
        findings.append({
            "finding_name": "No obvious mismatch",
            "description": "No header mismatch or appended signature patterns were detected.",
            "severity": "low",
            "analysis_status": "no_findings_detected",
        })

    return {
        "tool_name": "Signature Analysis",
        "available": True,
        "status": "ok",
        "actual_type": actual_type,
        "expected_extension": expected_extension,
        "findings": findings,
    }
