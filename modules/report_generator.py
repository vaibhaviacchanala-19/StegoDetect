import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from werkzeug.utils import secure_filename


def _safe_text(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)[:2000]
    return str(value)


def _extract_risk_assessment(investigation: Dict[str, Any]) -> Dict[str, Any]:
    report_data = investigation.get("report_data") or {}
    if isinstance(report_data, str):
        try:
            report_data = json.loads(report_data)
        except Exception:
            report_data = {}
    risk_assessment = investigation.get("risk_assessment") or report_data.get("risk_assessment") or {}
    if not risk_assessment:
        risk_assessment = {
            "risk_score": investigation.get("risk_score", 0),
            "risk_level": investigation.get("risk_level", "informational"),
            "executive_summary": investigation.get("detection_summary", "No summary available."),
            "evidence_summary": investigation.get("metadata_summary", "No evidence summary available."),
            "findings": [],
            "recommended_soc_actions": ["Review the investigation in the case workspace."],
        }
    return risk_assessment


def generate_json_report(investigation: Dict[str, Any]) -> Dict[str, Any]:
    risk_assessment = _extract_risk_assessment(investigation)
    findings = risk_assessment.get("findings", []) or []
    metadata_summary = investigation.get("metadata_summary") or "No metadata summary available."
    return {
        "project_name": "StegoDetect",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "investigation_id": investigation.get("id"),
        "filename": investigation.get("filename"),
        "file_size": investigation.get("file_size"),
        "sha256": investigation.get("sha256"),
        "file_type": investigation.get("file_format") or investigation.get("file_type"),
        "analysis_timestamp": investigation.get("analysis_timestamp"),
        "metadata_findings": investigation.get("metadata_summary") or metadata_summary,
        "steganography_findings": investigation.get("detection_summary") or risk_assessment.get("summary", "No steganography findings."),
        "risk_score": investigation.get("risk_score", risk_assessment.get("risk_score", 0)),
        "risk_level": investigation.get("risk_level") or risk_assessment.get("risk_level") or "informational",
        "executive_summary": risk_assessment.get("executive_summary") or risk_assessment.get("summary") or "No executive summary available.",
        "evidence_summary": risk_assessment.get("evidence_summary") or "No decisive evidence recorded.",
        "recommended_actions": risk_assessment.get("recommended_soc_actions") or risk_assessment.get("recommended_actions") or ["Review and document the investigation outcome."],
        "findings": findings,
        "conclusion": risk_assessment.get("summary") or "The file was reviewed using the available forensic checks and stored for analyst review.",
        "advanced_analysis": investigation.get("advanced_analysis") or investigation.get("report_data", {}).get("advanced_analysis") or {},
    }


def generate_html_report(investigation: Dict[str, Any]) -> str:
    report = generate_json_report(investigation)
    findings_html = ""
    for item in report["findings"]:
        findings_html += "<li><strong>{}</strong> — {}<br><small>Evidence: {}</small></li>".format(
            item.get("title", "Finding"),
            item.get("description", "No description available."),
            item.get("evidence", "No evidence recorded."),
        )
    if not findings_html:
        findings_html = "<li>No findings recorded at the risk-assessment layer.</li>"

    recommended = "".join(f"<li>{_safe_text(action)}</li>" for action in report["recommended_actions"])
    html = f"""
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>StegoDetect Investigation Report</title>
      <style>
        body {{ font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 32px; }}
        .box {{ background: #111827; border: 1px solid #374151; border-radius: 10px; padding: 20px; margin-bottom: 20px; }}
        h1, h2, h3 {{ color: #f8fafc; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border-bottom: 1px solid #374151; padding: 8px 0; text-align: left; }}
        .pill {{ display: inline-block; background: #1d4ed8; padding: 6px 10px; border-radius: 999px; }}
      </style>
    </head>
    <body>
      <div class="box">
        <h1>StegoDetect</h1>
        <h3>Digital Forensics Investigation Report</h3>
        <div class="pill">Risk {report['risk_level']} | Score {report['risk_score']}</div>
      </div>

      <div class="box">
        <h2>Case Overview</h2>
        <table>
          <tr><th>Investigation ID</th><td>{report['investigation_id']}</td></tr>
          <tr><th>Filename</th><td>{_safe_text(report['filename'])}</td></tr>
          <tr><th>SHA-256</th><td>{_safe_text(report['sha256'])}</td></tr>
          <tr><th>File Type</th><td>{_safe_text(report['file_type'])}</td></tr>
          <tr><th>Analysis Timestamp</th><td>{_safe_text(report['analysis_timestamp'])}</td></tr>
          <tr><th>File Size</th><td>{_safe_text(report['file_size'])}</td></tr>
        </table>
      </div>

      <div class="box">
        <h2>Executive Summary</h2>
        <p>{_safe_text(report['executive_summary'])}</p>
      </div>

      <div class="box">
        <h2>Evidence Summary</h2>
        <p>{_safe_text(report['evidence_summary'])}</p>
      </div>

      <div class="box">
        <h2>Findings</h2>
        <ul>{findings_html}</ul>
      </div>

      <div class="box">
        <h2>Recommended Actions</h2>
        <ul>{recommended}</ul>
      </div>

      <div class="box">
        <h2>Conclusion</h2>
        <p>{_safe_text(report['conclusion'])}</p>
        <p><a href="#">Download JSON</a> | <a href="#">Download PDF</a></p>
      </div>
    </body>
    </html>
    """
    return html


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _make_pdf_lines(investigation: Dict[str, Any]) -> List[str]:
    report = generate_json_report(investigation)
    risk_assessment = _extract_risk_assessment(investigation)
    findings = risk_assessment.get("findings", []) or []
    findings_lines = []
    for item in findings:
        findings_lines.append(f"- {item.get('title', 'Finding')}: {item.get('description', 'No description available.')} [{item.get('severity', 'unknown')}]")
    if not findings_lines:
        findings_lines.append("- No forensic findings recorded.")

    lines = [
        "StegoDetect Digital Forensics Report",
        "-----------------------------------",
        f"Investigation ID: {report['investigation_id']}",
        f"Filename: {report['filename']}",
        f"File Size: {report['file_size']}",
        f"SHA-256: {report['sha256']}",
        f"File Type: {report['file_type']}",
        f"Analysis Timestamp: {report['analysis_timestamp']}",
        f"Risk Score: {report['risk_score']}",
        f"Risk Classification: {report['risk_level']}",
        "",
        "Executive Summary:", report['executive_summary'],
        "",
        "Evidence Summary:", report['evidence_summary'],
        "",
        "Findings:",
        *findings_lines,
        "",
        "Recommended Actions:",
        *[f"- {_safe_text(action)}" for action in report['recommended_actions']],
        "",
        "Conclusion:", report['conclusion'],
    ]
    return lines


def generate_pdf_report(investigation: Dict[str, Any], output_dir: str = "reports") -> str:
    os.makedirs(output_dir, exist_ok=True)
    lines = _make_pdf_lines(investigation)
    content_lines = []
    y = 760
    for line in lines[:55]:
        content_lines.append(f"BT /F1 12 Tf 72 {y} Td ({_escape_pdf_text(line)}) Tj ET")
        y -= 18
    page_stream = "\n".join(content_lines)
    stream_bytes = page_stream.encode("latin-1", errors="replace")

    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        f"<< /Length {len(stream_bytes)} >>\nstream\n{page_stream}\nendstream".encode("latin-1", errors="replace"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]

    pdf_bytes = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(pdf_bytes))
        pdf_bytes.extend(f"{idx} 0 obj\n".encode("latin-1"))
        pdf_bytes.extend(obj)
        pdf_bytes.extend(b"\nendobj\n")
    xref_offset = len(pdf_bytes)
    pdf_bytes.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    pdf_bytes.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf_bytes.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
    pdf_bytes.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("latin-1"))

    raw_name = investigation.get("filename", "investigation")
    safe_name = secure_filename(Path(raw_name).stem or "investigation") or "investigation"
    filename = f"{safe_name}_{(investigation.get('id') or 'report')}.pdf"
    output_path = os.path.abspath(os.path.join(output_dir, filename))
    report_root = os.path.abspath(output_dir)
    if os.path.commonpath([report_root, output_path]) != report_root:
        output_path = os.path.join(report_root, f"report_{investigation.get('id') or 'report'}.pdf")
    with open(output_path, "wb") as handle:
        handle.write(pdf_bytes)
    return output_path
