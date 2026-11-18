import os
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List

TOOL_REGISTRY = {
    "steghide": {
        "display_name": "Steghide",
        "version_args": ["--version"],
        "supported_formats": ["jpeg", "bmp", "wav", "au"],
        "install_recommendation": "Install Steghide from the official package manager or from steghide.sourceforge.net, then ensure steghide is on PATH.",
    },
    "zsteg": {
        "display_name": "Zsteg",
        "version_args": ["--version"],
        "supported_formats": ["png", "bmp"],
        "install_recommendation": "Install zsteg via RubyGems: gem install zsteg; ensure the zsteg command is available in your PATH.",
    },
    "binwalk": {
        "display_name": "Binwalk",
        "version_args": ["--version"],
        "supported_formats": ["png", "jpeg", "pdf", "zip", "exe", "bin"],
        "install_recommendation": "Install Binwalk via pip or your OS package manager, then verify binwalk --version works.",
    },
    "pngcheck": {
        "display_name": "PNGcheck",
        "version_args": ["-v"],
        "supported_formats": ["png"],
        "install_recommendation": "Install PNGcheck from the official package repository or source distribution and ensure pngcheck is on PATH.",
    },
    "exiftool": {
        "display_name": "ExifTool",
        "version_args": ["-ver"],
        "supported_formats": ["png", "jpeg", "jpg", "gif", "bmp", "tiff", "pdf", "docx", "mp3", "wav"],
        "install_recommendation": "Install ExifTool from the official package repository or from exiftool.org, then ensure exiftool is on PATH.",
    },
}


def resolve_executable(name: str):
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    project_tools_dir = os.path.join(project_root, "tools")

    exact_candidates = {
        "steghide": [
            os.path.join(project_tools_dir, "steghide", "steghide.exe") if os.path.isdir(project_tools_dir) else None,
            os.path.join(project_tools_dir, "steghide.exe") if os.path.isdir(project_tools_dir) else None,
        ],
        "zsteg": [
            r"C:\Users\Vaibhavi\scoop\apps\ruby\current\bin\zsteg.bat",
            r"C:\Users\Vaibhavi\scoop\apps\ruby\current\gems\bin\zsteg.bat",
            os.path.join(project_tools_dir, "zsteg.bat") if os.path.isdir(project_tools_dir) else None,
            r"C:\Users\Vaibhavi\scoop\apps\ruby\current\bin\zsteg",
            r"C:\Users\Vaibhavi\scoop\apps\ruby\current\gems\bin\zsteg",
        ],
        "binwalk": [
            os.path.join(project_tools_dir, "binwalk.cmd") if os.path.isdir(project_tools_dir) else None,
            r"C:\Users\Vaibhavi\AppData\Roaming\Python\Python313\Scripts\binwalk.exe",
            r"C:\Users\Vaibhavi\AppData\Roaming\Python\Python313\Scripts\binwalk",
            os.path.join(project_tools_dir, "binwalk.exe") if os.path.isdir(project_tools_dir) else None,
            os.path.join(project_tools_dir, "binwalk") if os.path.isdir(project_tools_dir) else None,
        ],
        "pngcheck": [
            os.path.join(project_tools_dir, "pngcheck.exe") if os.path.isdir(project_tools_dir) else None,
            r"C:\Users\Vaibhavi\pngcheck-src\pngcheck.exe",
        ],
    }.get(name, [])

    for candidate in exact_candidates:
        if candidate and os.path.exists(candidate):
            return candidate

    executable = shutil.which(name)
    if executable:
        return executable

    if name == "exiftool":
        candidates = [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "ExifTool", "ExifTool.exe"),
            r"C:\Users\Vaibhavi\AppData\Local\Programs\ExifTool\ExifTool.exe",
        ]
        for candidate in candidates:
            if candidate and os.path.exists(candidate):
                return candidate

    if os.path.isdir(project_tools_dir):
        for candidate in [
            os.path.join(project_tools_dir, name),
            os.path.join(project_tools_dir, f"{name}.exe"),
            os.path.join(project_tools_dir, f"{name}.cmd"),
            os.path.join(project_tools_dir, f"{name}.bat"),
        ]:
            if os.path.exists(candidate):
                return candidate
    return None


def run_command(args: List[str], timeout: int = 25) -> subprocess.CompletedProcess:
    if not args:
        return subprocess.CompletedProcess(args, returncode=127, stdout="", stderr="No command provided.")

    command = list(args)
    if command and isinstance(command[0], str):
        resolved = resolve_executable(command[0])
        if resolved:
            command[0] = resolved

    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, returncode=127, stdout="", stderr=str(exc))


def build_finding(tool_name: str, detection_method: str, finding_name: str, description: str, evidence: str, offset: Any = None, severity: str = "medium", analysis_status: str = "inconclusive") -> Dict[str, Any]:
    return {
        "detection_tool": tool_name,
        "detection_method": detection_method,
        "finding_name": finding_name,
        "description": description,
        "evidence": evidence,
        "offset": offset,
        "severity": severity,
        "analysis_status": analysis_status,
    }


def tool_status(name: str) -> Dict[str, Any]:
    config = TOOL_REGISTRY.get(name, {"display_name": name, "supported_formats": [], "install_recommendation": "Install the tool and ensure the command is available on PATH."})
    executable = resolve_executable(name)
    status = {
        "tool_name": config["display_name"],
        "command_name": name,
        "available": bool(executable),
        "status": "available" if executable else "unavailable",
        "version": None,
        "supported_formats": config.get("supported_formats", []),
        "install_recommendation": config.get("install_recommendation", ""),
        "path": executable,
    }
    if not executable:
        return status
    try:
        proc = run_command([executable] + config.get("version_args", ["--version"]))
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        version = output.strip().splitlines()[0] if output.strip() else "unknown"
        status["version"] = version[:200]
    except Exception as exc:  # pragma: no cover - external tool variance
        status["available"] = False
        status["status"] = "error"
        status["error"] = str(exc)
        status["version"] = "unknown"
    return status


def analyze_all_tools(file_path: str) -> Dict[str, Any]:
    from modules.binwalk_analyzer import analyze_binwalk
    from modules.exiftool_analyzer import analyze_exiftool
    from modules.png_analyzer import analyze_pngcheck
    from modules.steghide_analyzer import analyze_steghide
    from modules.zsteg_analyzer import analyze_zsteg

    tool_results = {
        "steghide": analyze_steghide(file_path),
        "zsteg": analyze_zsteg(file_path),
        "binwalk": analyze_binwalk(file_path),
        "pngcheck": analyze_pngcheck(file_path),
        "exiftool": analyze_exiftool(file_path),
    }

    overall_status = "ok"
    if any(result.get("status") == "unavailable" for result in tool_results.values()):
        overall_status = "warning"
    if any(result.get("status") == "error" for result in tool_results.values()):
        overall_status = "warning"

    summary_lines = []
    for tool_name, result in tool_results.items():
        findings = result.get("findings", [])
        if findings:
            summary_lines.append(f"{tool_name}: {len(findings)} finding(s)")
        else:
            summary_lines.append(f"{tool_name}: no notable findings")

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "overall_status": overall_status,
        "tools": tool_results,
        "analysis_summary": "; ".join(summary_lines),
    }
