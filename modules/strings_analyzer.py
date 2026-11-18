import os
import re
import subprocess

from modules.tool_manager import build_finding

URL_RE = re.compile(r"(?:https?:\/\/|www\.)[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]+")
IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
POWERSHELL_RE = re.compile(r"(?i)(powershell|pwsh|Invoke-Expression|IEX|FromBase64String|New-Object)\b")
CMD_RE = re.compile(r"(?i)(cmd\.exe|rundll32|certutil|bitsadmin|net\s+user|sc\.exe|attrib)\b")
SHELL_RE = re.compile(r"(?i)(bash\s+-c|sh\s+-c|curl\s+http|wget\s+http|chmod\s+\+x)\b")
BASE64_LIKE_RE = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
EXECUTABLE_REF_RE = re.compile(r"(?i)(\.exe|\.dll|\.bat|\.cmd|\.ps1|\.com|\.scr)")
SUSPICIOUS_PATH_RE = re.compile(r"(?i)(C:\\|/tmp/|/var/tmp/|AppData|ProgramData|Users\\|\\Windows\\|\\System32\\)")
ENCODED_SCRIPT_RE = re.compile(r"(?i)(base64|FromBase64String|decode\(|eval\(|System\.Text\.Encoding|powershell.*-enc)")


def _iter_strings_in_data(data: bytes, minimum_length: int = 4):
    if not data:
        return []

    matches = []
    current = bytearray()
    for index, byte in enumerate(data):
        if byte in (9, 10, 13):
            if len(current) >= minimum_length:
                matches.append((index - len(current), bytes(current)))
            current = bytearray()
            continue
        if 32 <= byte < 127:
            current.append(byte)
            continue
        if len(current) >= minimum_length:
            matches.append((index - len(current), bytes(current)))
        current = bytearray()
    if len(current) >= minimum_length:
        matches.append((len(data) - len(current), bytes(current)))
    return matches


def _classify_string(value: str):
    classification = "general"
    lowered = value.lower()
    if URL_RE.search(value):
        classification = "url"
    elif IP_RE.search(value):
        classification = "ip_address"
    elif POWERSHELL_RE.search(value):
        classification = "powershell"
    elif CMD_RE.search(value):
        classification = "cmd"
    elif SHELL_RE.search(value):
        classification = "shell"
    elif BASE64_LIKE_RE.fullmatch(value):
        classification = "base64_like"
    elif EXECUTABLE_REF_RE.search(value):
        classification = "executable_reference"
    elif SUSPICIOUS_PATH_RE.search(value):
        classification = "suspicious_path"
    elif ENCODED_SCRIPT_RE.search(value):
        classification = "encoded_script"
    elif re.search(r"(?:[A-Za-z0-9+/]{32,})", value):
        classification = "base64_like"
    if classification == "general" and len(value) >= 20 and all(ch.isalnum() or ch in "_-./\\:" for ch in value):
        classification = "general_string"
    return classification


def _risk_for_category(category: str):
    risk_map = {
        "url": "medium",
        "ip_address": "medium",
        "powershell": "high",
        "cmd": "high",
        "shell": "high",
        "base64_like": "medium",
        "executable_reference": "high",
        "suspicious_path": "high",
        "encoded_script": "high",
        "general_string": "low",
    }
    return risk_map.get(category, "low")


def analyze_strings(file_path: str):
    if not os.path.exists(file_path):
        return {
            "tool_name": "Strings",
            "available": False,
            "status": "error",
            "install_recommendation": "Install the strings utility or supply a file for local ASCII scanning.",
            "findings": [],
        }

    file_bytes = open(file_path, "rb").read()

    tool_result = {
        "tool_name": "Strings",
        "available": True,
        "status": "ok",
        "findings": [],
        "summary": "No suspicious strings detected.",
    }

    strings_output = []
    try:
        proc = subprocess.run(["strings", "-n", "4", file_path], capture_output=True, text=True, timeout=20, check=False)
        if proc.stdout.strip():
            strings_output = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    except Exception:
        strings_output = []

    if not strings_output:
        strings_output = [s.decode("ascii", "ignore") for _, s in _iter_strings_in_data(file_bytes)]

    seen = set()
    for raw_value in strings_output:
        value = raw_value.strip()
        if not value or len(value) < 4:
            continue
        category = _classify_string(value)
        if value in seen:
            continue
        seen.add(value)
        offset = file_bytes.find(value.encode("ascii", "ignore"))
        if offset == -1:
            offset = None
        tool_result["findings"].append(
            {
                "extracted_string": value,
                "offset": offset,
                "category": category,
                "risk": _risk_for_category(category),
                "detection_tool": "strings",
            }
        )

    suspicious = [entry for entry in tool_result["findings"] if entry["risk"] in {"medium", "high"}]
    tool_result["summary"] = f"{len(suspicious)} suspicious string(s) identified." if suspicious else "No suspicious strings detected."
    tool_result["findings"] = suspicious if suspicious else tool_result["findings"][:10]
    return tool_result
