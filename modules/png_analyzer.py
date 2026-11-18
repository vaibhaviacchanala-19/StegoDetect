import re

from modules.tool_manager import build_finding, run_command, tool_status


def analyze_pngcheck(file_path: str):
    status = tool_status("pngcheck")
    result = {
        "tool_name": "PNGcheck",
        "command_name": "pngcheck",
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
                "pngcheck",
                "tool availability",
                "Tool unavailable",
                "PNGcheck is not installed or not on PATH.",
                status.get("install_recommendation", "Install PNGcheck to inspect PNG chunk structure and trailing data."),
                severity="medium",
                analysis_status="unavailable",
            )
        ]
        return result

    proc = run_command(["pngcheck", "-v", file_path], timeout=30)
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    result["status"] = "ok"
    result["analysis_output"] = output.strip()

    findings = [
        "CRC error",
        "invalid chunk",
        "unexpected chunk",
        "trailing data",
        "extra data",
        "corrupt",
        "bad CRC",
    ]
    lower_output = output.lower()
    if any(item in lower_output for item in findings):
        result["findings"].append(
            build_finding(
                "pngcheck",
                "PNG chunk validation",
                "PNG integrity concern detected",
                "PNGcheck reported structural or integrity issues in the PNG file.",
                output.strip()[:500],
                severity="high",
                analysis_status="suspicious_heuristic_indicator",
            )
        )
    else:
        result["findings"].append(
            build_finding(
                "pngcheck",
                "PNG chunk validation",
                "No structural anomalies reported",
                "PNGcheck did not report invalid chunks, CRC problems, or trailing data.",
                output.strip()[:500],
                severity="low",
                analysis_status="no_findings_detected",
            )
        )

    return result
