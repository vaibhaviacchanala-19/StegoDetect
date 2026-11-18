import re

from modules.tool_manager import build_finding, run_command, tool_status


def analyze_zsteg(file_path: str):
    status = tool_status("zsteg")
    result = {
        "tool_name": "Zsteg",
        "command_name": "zsteg",
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
                "zsteg",
                "tool availability",
                "Tool unavailable",
                "Zsteg is not installed or not on PATH.",
                status.get("install_recommendation", "Install zsteg to inspect PNG/BMP LSB data."),
                severity="medium",
                analysis_status="unavailable",
            )
        ]
        return result

    proc = run_command(["zsteg", "-a", file_path], timeout=30)
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    result["status"] = "ok"
    result["analysis_output"] = output.strip()

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        result["findings"].append(
            build_finding(
                "zsteg",
                "LSB analysis",
                "No findings detected",
                "Zsteg did not report hidden-data indicators for this file.",
                "No command output produced.",
                severity="low",
                analysis_status="no_findings_detected",
            )
        )
        return result

    for line in lines:
        if re.search(r"(file|hidden|lsb|bits|channel|png|bmp)", line, flags=re.IGNORECASE):
            result["findings"].append(
                build_finding(
                    "zsteg",
                    "LSB / bit-plane / channel analysis",
                    "Potential hidden data indicator",
                    "Zsteg reported a payload-related signal that warrants review.",
                    line[:500],
                    severity="medium" if "no" not in line.lower() else "low",
                    analysis_status="tool_reported_embedded_data",
                )
            )
            break
    else:
        result["findings"].append(
            build_finding(
                "zsteg",
                "LSB analysis",
                "No suspicious indicators reported",
                "The command output did not show a clear hidden-data signature.",
                output.strip()[:500],
                severity="low",
                analysis_status="inconclusive",
            )
        )

    return result
