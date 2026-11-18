import json

from modules.tool_manager import build_finding, run_command, tool_status


def analyze_exiftool(file_path: str):
    status = tool_status("exiftool")
    result = {
        "tool_name": "ExifTool",
        "command_name": "exiftool",
        "status": "unavailable",
        "available": status["available"],
        "version": status.get("version"),
        "supported_formats": status.get("supported_formats", []),
        "install_recommendation": status.get("install_recommendation", ""),
        "findings": [],
    }

    if not status["available"]:
        result["findings"] = [
            build_finding(
                "exiftool",
                "tool availability",
                "Tool unavailable",
                "ExifTool is not installed or not on PATH.",
                status.get("install_recommendation", "Install ExifTool and ensure exiftool is available on PATH."),
                severity="medium",
                analysis_status="unavailable",
            )
        ]
        return result

    exiftool_exec = status.get("path") or "exiftool"
    proc = run_command([exiftool_exec, "-a", "-u", "-g1", file_path], timeout=30)
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    result["status"] = "ok"
    result["analysis_output"] = output.strip()

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        result["findings"].append(
            build_finding(
                "exiftool",
                "metadata inspection",
                "No metadata fields detected",
                "ExifTool did not return readable metadata content for this file.",
                "No command output produced.",
                severity="low",
                analysis_status="no_findings_detected",
            )
        )
        return result

    suspicious_terms = ["gps", "comment", "usercomment", "copyright", "author", "software", "model", "camera", "stego", "payload"]
    relevant_lines = [line for line in lines if any(term in line.lower() for term in suspicious_terms)]

    if relevant_lines:
        evidence = "\n".join(relevant_lines[:3])
        result["findings"].append(
            build_finding(
                "exiftool",
                "metadata inspection",
                "Metadata fields extracted",
                "ExifTool reported metadata tags that should be reviewed for embedded or hidden provenance traces.",
                evidence[:500],
                severity="medium",
                analysis_status="tool_reported_embedded_data",
            )
        )
    else:
        result["findings"].append(
            build_finding(
                "exiftool",
                "metadata inspection",
                "Metadata inspection complete",
                "ExifTool completed successfully and did not surface clear metadata anomalies in the inspected file.",
                lines[0][:500],
                severity="low",
                analysis_status="inconclusive",
            )
        )

    return result
