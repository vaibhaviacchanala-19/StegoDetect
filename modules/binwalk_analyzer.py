import re

from modules.tool_manager import build_finding, run_command, tool_status


def analyze_binwalk(file_path: str):
    status = tool_status("binwalk")
    result = {
        "tool_name": "Binwalk",
        "command_name": "binwalk",
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
                "binwalk",
                "tool availability",
                "Tool unavailable",
                "Binwalk is not installed or not on PATH.",
                status.get("install_recommendation", "Install Binwalk to inspect appended data and embedded archives."),
                severity="medium",
                analysis_status="unavailable",
            )
        ]
        return result

    proc = run_command(["binwalk", file_path], timeout=30)
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    result["status"] = "ok"
    result["analysis_output"] = output.strip()

    matches = re.findall(r"(?m)^\s*(\d+)\s+([0-9A-Fa-f]+)\s+(.+)$", output)
    if not matches:
        result["findings"].append(
            build_finding(
                "binwalk",
                "appended-data scan",
                "No embedded structure detected",
                "Binwalk did not report embedded archives, executables, or suspicious appended content.",
                output.strip()[:500],
                severity="low",
                analysis_status="no_findings_detected",
            )
        )
        return result

    for offset, signature, description in matches[:10]:
        severity = "high" if any(key in description.lower() for key in ["zip", "exe", "pdf", "jpg", "png", "elf"]) else "medium"
        result["findings"].append(
            build_finding(
                "binwalk",
                "embedded-data scan",
                "Embedded structure detected",
                "Binwalk identified a suspicious or embedded file signature.",
                description.strip(),
                offset=int(offset, 10) if str(offset).isdigit() else None,
                severity=severity,
                analysis_status="tool_reported_embedded_data",
            )
        )

    return result
