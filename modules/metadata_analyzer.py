import json
import os
import shutil
import subprocess
from datetime import datetime


def _resolve_exiftool_path():
    executable = shutil.which("exiftool")
    if executable:
        return executable
    candidates = [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "ExifTool", "ExifTool.exe"),
        r"C:\Users\Vaibhavi\AppData\Local\Programs\ExifTool\ExifTool.exe",
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def check_exiftool_available():
    return _resolve_exiftool_path() is not None


def analyze_metadata(file_path):
    exiftool_path = _resolve_exiftool_path()
    if not exiftool_path:
        return {
            "available": False,
            "warning": "ExifTool is not installed or not available in PATH. Metadata extraction is unavailable.",
            "entries": [],
            "anomalies": ["ExifTool unavailable"],
            "summary": "ExifTool unavailable; no metadata was extracted.",
            "tags": [],
        }

    try:
        result = subprocess.run(
            [exiftool_path, "-j", str(file_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode not in {0, 1}:
            raise RuntimeError(result.stderr.strip() or "ExifTool execution failed")

        output = result.stdout.strip()
        if not output:
            return {
                "available": True,
                "warning": None,
                "entries": [],
                "anomalies": [],
                "summary": "No readable metadata fields were detected.",
                "tags": [],
            }

        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            payload = []

        if not payload:
            return {
                "available": True,
                "warning": None,
                "entries": [],
                "anomalies": [],
                "summary": "No readable metadata fields were detected.",
                "tags": [],
            }

        record = payload[0]
        if not isinstance(record, dict):
            record = {}

        anomalies = []
        keys = {str(key).lower(): key for key in record.keys()}

        for key in ["comment", "software", "usercomment", "gpslatitude", "gpslongitude", "makemodel", "cameramodel", "createDate", "modifyDate"]:
            if key.lower() in keys:
                value = record.get(keys[key.lower()])
                if value is not None and str(value).strip():
                    if "gps" in key.lower() and value not in {"", "0"}:
                        anomalies.append(f"GPS metadata detected: {value}")
                    if key.lower() in {"comment", "usercomment"}:
                        anomalies.append(f"User comment found: {value}")
                    if key.lower() in {"software"}:
                        anomalies.append(f"Software tag detected: {value}")

        create_dates = [record.get(k) for k in record if "create" in str(k).lower() or "date" in str(k).lower()]
        if len(create_dates) > 0:
            anomalies.append("Creation timestamps were extracted from file metadata.")

        summary = (
            f"Metadata extracted from {len(record)} fields. "
            + (f"Anomalies: {len(anomalies)}." if anomalies else "No obvious metadata inconsistencies detected.")
        )
        return {
            "available": True,
            "warning": None,
            "entries": record,
            "anomalies": anomalies,
            "summary": summary,
            "tags": list(record.keys())[:25],
        }
    except Exception as exc:
        return {
            "available": False,
            "warning": f"Metadata extraction failed: {str(exc)}",
            "entries": [],
            "anomalies": ["Metadata extraction error"],
            "summary": "ExifTool could not parse metadata for this file.",
            "tags": [],
        }
