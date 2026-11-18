import os
import tempfile

from modules.tool_manager import build_finding, run_command, tool_status


def analyze_steghide(file_path: str, passphrase: str = None, authorized: bool = False):
    status = tool_status("steghide")
    result = {
        "tool_name": "Steghide",
        "command_name": "steghide",
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
                "steghide",
                "tool availability",
                "Tool unavailable",
                "Steghide is not installed or not on PATH.",
                status.get("install_recommendation", "Install Steghide to continue forensic inspection."),
                severity="medium",
                analysis_status="unavailable",
            )
        ]
        return result

    proc = run_command(["steghide", "--info", file_path], timeout=25)
    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    result["status"] = "ok"
    result["analysis_output"] = output.strip()

    if "No embedded data" in output or "no embedded data" in output.lower():
        result["findings"].append(
            build_finding(
                "steghide",
                "embedded-data check",
                "No embedded data reported",
                "Steghide did not report embedded data in the supplied file.",
                output.strip()[:500],
                severity="low",
                analysis_status="no_findings_detected",
            )
        )
    elif "could not" in output.lower() or "error" in output.lower() or "unsupported" in output.lower():
        result["status"] = "error"
        result["findings"].append(
            build_finding(
                "steghide",
                "embedded-data check",
                "Steghide inspection inconclusive",
                "Steghide returned an error or could not process the file successfully.",
                output.strip()[:500],
                severity="medium",
                analysis_status="inconclusive",
            )
        )
    else:
        result["findings"].append(
            build_finding(
                "steghide",
                "embedded-data check",
                "Embedded-data metadata observed",
                "Steghide reported information that warrants review for hidden content.",
                output.strip()[:500],
                severity="medium",
                analysis_status="tool_reported_embedded_data",
            )
        )

    if authorized and passphrase:
        temp_dir = tempfile.mkdtemp(prefix="stego_steghide_")
        target_path = os.path.join(temp_dir, "steghide_extracted.bin")
        try:
            extract_proc = run_command(["steghide", "--extract", "-sf", file_path, "-p", passphrase, "-xf", target_path], timeout=25)
            extract_output = (extract_proc.stdout or "") + "\n" + (extract_proc.stderr or "")
            if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
                result["findings"].append(
                    build_finding(
                        "steghide",
                        "passphrase extraction",
                        "Confirmed extracted data",
                        "A passphrase-authorized extraction produced an output file.",
                        extract_output.strip()[:500],
                        severity="high",
                        analysis_status="confirmed_extracted_data",
                    )
                )
            elif "extraction" in extract_output.lower() or "success" in extract_output.lower():
                result["findings"].append(
                    build_finding(
                        "steghide",
                        "passphrase extraction",
                        "Extraction completed",
                        "The extraction command reported success, but no output file was retained for review.",
                        extract_output.strip()[:500],
                        severity="medium",
                        analysis_status="confirmed_extracted_data",
                    )
                )
        finally:
            for item in os.listdir(temp_dir):
                target = os.path.join(temp_dir, item)
                if os.path.isfile(target):
                    os.remove(target)
            os.rmdir(temp_dir)

    return result
