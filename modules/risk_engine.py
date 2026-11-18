import re
from typing import Any, Dict, Iterable, List, Sequence

RISK_BANDS = [
    ("informational", 0, 20),
    ("low", 21, 40),
    ("medium", 41, 60),
    ("high", 61, 80),
    ("critical", 81, 100),
]

RISK_WEIGHTS = {
    "embedded_executable": 70,
    "embedded_archive": 65,
    "suspicious_appended_data": 32,
    "unexpected_signature": 28,
    "suspicious_metadata": 28,
    "lsb_detection": 26,
    "suspicious_strings": 20,
    "multiple_format_indicators": 18,
    "tool_availability_note": 8,
}

MITRE_BY_HINT = {
    "powershell": ["T1059.001"],
    "cmd": ["T1059.003"],
    "url": ["T1071.001"],
    "embedded_executable": ["T1027", "T1218"],
    "embedded_archive": ["T1027"],
    "appended_data": ["T1027"],
    "unexpected_signature": ["T1036"],
}


def classify_risk_score(score: int) -> str:
    score = max(0, min(100, int(score)))
    for label, minimum, maximum in RISK_BANDS:
        if minimum <= score <= maximum:
            return label
    return "informational"


def _make_finding(finding_id: str, title: str, description: str, detection_method: str, evidence: str, severity: str, contribution: int, recommended_action: str, mitre: Sequence[str] | None = None) -> Dict[str, Any]:
    return {
        "finding_id": finding_id,
        "title": title,
        "description": description,
        "detection_method": detection_method,
        "evidence": evidence or description,
        "severity": severity,
        "risk_contribution": contribution,
        "recommended_action": recommended_action,
        "mitre_attack": list(mitre or []),
    }


def _normalize_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _deduplicate_compound_findings(findings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique = []
    for finding in findings:
        key = finding.get("title", "").lower().strip()
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _collect_signature_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    signature_analysis = (result or {}).get("advanced_analysis", {}).get("signature", {})
    return _normalize_list(signature_analysis.get("findings", []))


def _collect_string_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    strings_analysis = (result or {}).get("advanced_analysis", {}).get("strings", {})
    return _normalize_list(strings_analysis.get("findings", []))


def _collect_tool_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for tool_result in ((result or {}).get("stego_analysis", {}).get("tools", {}) or {}).values():
        for item in _normalize_list(tool_result.get("findings", [])):
            findings.append(item)
    return findings


def build_risk_assessment(result: Dict[str, Any]) -> Dict[str, Any]:
    result = result or {}
    findings: List[Dict[str, Any]] = []
    evidence_items: List[str] = []
    mitre_attack: List[str] = []
    tool_result = (result or {}).get("stego_analysis", {}) or {}
    metadata = (result or {}).get("metadata", {}) or {}
    advanced = (result or {}).get("advanced_analysis", {}) or {}

    def add_finding(finding_id: str, title: str, description: str, detection_method: str, evidence: str, severity: str, contribution: int, recommended_action: str, mitre: Sequence[str] | None = None):
        if not evidence:
            evidence = description
        evidence_items.append(evidence)
        if mitre:
            for entry in mitre:
                if entry:
                    mitre_attack.append(entry)
        findings.append(_make_finding(finding_id, title, description, detection_method, evidence, severity, contribution, recommended_action, mitre))

    if result.get("actual_type") in {"exe", "dll"}:
        add_finding(
            "F-001",
            "Embedded executable",
            "Executable file characteristics were detected in a suspicious context.",
            "signature_check",
            "Executable header or loader markers detected.",
            "critical",
            RISK_WEIGHTS["embedded_executable"],
            "Isolate the file, verify hash integrity, and inspect the artifact in a controlled forensic environment before any remediation.",
            MITRE_BY_HINT["embedded_executable"],
        )

    if metadata.get("warning") and not findings:
        add_finding(
            "F-000",
            "Tool availability note",
            "One or more external forensic tools were unavailable or inconclusive.",
            "tool_status",
            str(metadata.get("warning")),
            "low",
            RISK_WEIGHTS["tool_availability_note"],
            "Validate the forensic toolchain and rerun the review when the required utilities are installed or available on PATH.",
        )

    for finding in _collect_tool_findings(result):
        name = str(finding.get("finding_name", "")).lower()
        description = str(finding.get("description", "") or "")
        evidence = str(finding.get("evidence", "") or description)
        if "archive" in name or "zip" in name or "rar" in name or "cab" in name:
            add_finding(
                "F-002",
                "Embedded archive",
                "An archive container was detected inside the file, which may be used to store additional payloads.",
                str(finding.get("detection_tool", "binwalk")),
                evidence,
                "high",
                RISK_WEIGHTS["embedded_archive"],
                "Review the embedded archive for staged payloads, scripts, or dropped executables and preserve the original evidence chain.",
                MITRE_BY_HINT["embedded_archive"],
            )
        if "appended" in name or "trailing" in name or "overflow" in name or "extra" in name:
            add_finding(
                "F-003",
                "Suspicious appended data",
                "The file contains appended or trailing data beyond the expected format boundary.",
                str(finding.get("detection_tool", "binwalk")),
                evidence,
                "medium",
                RISK_WEIGHTS["suspicious_appended_data"],
                "Parse the trailing content separately and determine whether it is a benign payload, padding, or hidden executable material.",
                MITRE_BY_HINT["appended_data"],
            )
        if "lsb" in name:
            add_finding(
                "F-004",
                "LSB detection",
                "Lower-bit channel anomalies suggest possible steganographic embedding within the image data.",
                str(finding.get("detection_tool", "image_analysis")),
                evidence,
                "high",
                RISK_WEIGHTS["lsb_detection"],
                "Extract the image, compare pixel distributions, and assess whether the suspected LSB pattern represents a concealed payload.",
            )

    for finding in _collect_signature_findings(result):
        name = str(finding.get("finding_name", "")).lower()
        description = str(finding.get("description", "") or "")
        evidence = str(finding.get("evidence", "") or description)
        if "mismatch" in name or "signature" in name or "unexpected" in name or "appended" in name:
            add_finding(
                "F-005",
                "Unexpected signature",
                "The file’s observable structure does not match its expected extension or normal file format.",
                str(finding.get("detection_method", "signature_check")),
                evidence,
                "medium",
                RISK_WEIGHTS["unexpected_signature"],
                "Validate the container format, inspect appended content, and correlate the file’s type against original source metadata.",
                MITRE_BY_HINT["unexpected_signature"],
            )

    if metadata.get("anomalies"):
        metadata_text = " | ".join(str(item) for item in metadata.get("anomalies", []))
        if any("gps" in str(item).lower() for item in metadata.get("anomalies", [])) or any("comment" in str(item).lower() for item in metadata.get("anomalies", [])):
            add_finding(
                "F-006",
                "Suspicious metadata",
                "The analyzed file contains metadata fields that may represent operational or location details not expected for the file type.",
                "metadata_analysis",
                metadata_text,
                "medium",
                RISK_WEIGHTS["suspicious_metadata"],
                "Review the metadata against the file provenance and document any GPS, comments, or embedded authoring details for further triage.",
            )

    image_analysis = advanced.get("image") or {}
    if isinstance(image_analysis, dict) and image_analysis.get("available"):
        lsb_data = image_analysis.get("lsb_summary", {}) or {}
        if isinstance(lsb_data, dict) and lsb_data.get("odd_lsb_count", 0) and lsb_data.get("odd_lsb_count", 0) > 50:
            add_finding(
                "F-007",
                "LSB detection",
                "A meaningful LSB pattern was observed in the image, which is a common steganographic indicator.",
                "image_analysis",
                str(lsb_data),
                "high",
                RISK_WEIGHTS["lsb_detection"],
                "Extract the pixel payload and compare against clean baseline imagery before deciding whether the content is malicious or benign.",
            )

    for finding in _collect_string_findings(result):
        category = str(finding.get("category", "")).lower()
        value = str(finding.get("extracted_string", "") or "")
        if category in {"url", "powershell", "cmd", "shell", "executable_reference", "base64_like"}:
            add_finding(
                "F-008",
                "Suspicious strings",
                "The file contains encoded or operational strings commonly associated with remote command execution or malware staging.",
                "strings_analysis",
                value,
                "medium",
                RISK_WEIGHTS["suspicious_strings"],
                "Inspect the string context and determine whether it is a harmless artifact or a staged command-and-control indicator.",
                MITRE_BY_HINT.get(category, []),
            )

    if result.get("mismatch_detected") or any("mismatch" in str(item.get("finding_name", "")).lower() for item in _collect_signature_findings(result)):
        add_finding(
            "F-009",
            "Unexpected file signature",
            "The file extension and signature are mismatched or otherwise inconsistent with expected file behavior.",
            "signature_check",
            "Extension mismatch or invalid signature markers detected.",
            "medium",
            RISK_WEIGHTS["unexpected_signature"],
            "Verify the originating file, compare evidence against the expected format, and preserve the original artifact for forensic review.",
            MITRE_BY_HINT["unexpected_signature"],
        )

    multiple_indicators = 0
    if metadata.get("anomalies"):
        multiple_indicators += 1
    if any(findings_for_item := True for _ in _collect_tool_findings(result)):
        multiple_indicators += 1
    if any(_collect_signature_findings(result)):
        multiple_indicators += 1
    if any(_collect_string_findings(result)):
        multiple_indicators += 1
    if multiple_indicators >= 3:
        add_finding(
            "F-010",
            "Multiple format indicators",
            "Several independent indicators are present, which raises confidence in the suspicion that the file intentionally conceals or repackages content.",
            "multi_indicator_correlation",
            "; ".join(str(item) for item in evidence_items[:4]),
            "high",
            RISK_WEIGHTS["multiple_format_indicators"],
            "Correlate each indicator, determine whether the behavior is malicious or benign, and escalate to the SOC if more than one payload vector is present.",
            ["T1027"],
        )

    if tool_result.get("overall_status") == "warning" and not any(item["title"] == "Tool availability note" for item in findings):
        add_finding(
            "F-011",
            "Tool availability note",
            "The analyzer was unable to verify some tooling and the result remains inconclusive.",
            "tool_status",
            "One or more external forensic tools were unavailable or inconclusive during review.",
            "low",
            RISK_WEIGHTS["tool_availability_note"],
            "Validate the forensic toolchain and rerun the review when the required utilities are installed or available on PATH.",
        )

    findings = _deduplicate_compound_findings(findings)

    score = min(100, sum(int(item["risk_contribution"]) for item in findings))
    risk_level = classify_risk_score(score)

    if any(item["title"] in {"Embedded executable", "Embedded archive"} for item in findings):
        risk_level = classify_risk_score(max(score, 70))

    if not findings and result.get("actual_type") in {"png", "jpg", "jpeg", "gif", "bmp"}:
        score = 10
        risk_level = "informational"

    recommended_actions = []
    for item in findings[:4]:
        recommended_actions.append(item["recommended_action"])
    if not recommended_actions:
        recommended_actions.append("Monitor the file and retain the artifact for future correlation. No strong indicators were identified.")

    summary = (
        f"The file '{result.get('filename', 'unknown')}' is categorized as {risk_level} risk with {len(findings)} corroborating forensic indicators."
    )
    executive_summary = (
        f"{result.get('filename', 'unknown')} shows {risk_level} risk. "
        + ("Multiple forensic indicators support this assessment." if len(findings) > 1 else "A single indicator was observed during review.")
    )
    evidence_summary = "; ".join(str(item["evidence"])[:180] for item in findings[:3]) if findings else "No decisive forensic evidence detected."

    return {
        "risk_score": int(score),
        "risk_level": risk_level,
        "findings": findings,
        "executive_summary": executive_summary,
        "technical_findings": [item["title"] for item in findings],
        "evidence_summary": evidence_summary,
        "recommended_soc_actions": recommended_actions,
        "summary": summary,
        "mitre_attack": sorted(set(mitre_attack)),
    }
