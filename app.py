import json
import os
from datetime import datetime, timezone

from flask import Flask, Response, flash, redirect, render_template, request, send_file, url_for

from config import BASE_DIR, DATABASE_PATH, REPORTS_FOLDER, UPLOAD_FOLDER
from database.db import (
    get_dashboard_stats,
    get_investigation_by_id,
    get_recent_investigations,
    init_db,
    save_investigation,
    search_investigations,
    update_investigation_notes,
    update_investigation_status,
)
from modules.base64_analyzer import analyze_base64
from modules.entropy_analyzer import analyze_entropy
from modules.file_analyzer import analyze_file
from modules.hex_viewer import build_hex_preview
from modules.image_analyzer import analyze_image
from modules.metadata_analyzer import analyze_metadata
from modules.report_generator import generate_html_report, generate_json_report, generate_pdf_report
from modules.risk_engine import build_risk_assessment
from modules.signature_analyzer import analyze_signature
from modules.strings_analyzer import analyze_strings
from modules.tool_manager import analyze_all_tools

app = Flask(__name__)
app.config.from_object("config")
app.secret_key = "dev-secret-key-change-me"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

init_db()


@app.errorhandler(413)
def handle_file_too_large(error):
    return render_template("upload.html", result={"status": "error", "message": "File is too large. Maximum allowed size is 25 MB."}), 200


@app.route("/")
def dashboard():
    stats = get_dashboard_stats()
    recent = get_recent_investigations(limit=5)
    return render_template("dashboard.html", stats=stats, recent=recent)


@app.route("/dashboard")
def dashboard_alias():
    return redirect(url_for("dashboard"))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file_obj = request.files.get("file")
        if not file_obj or not file_obj.filename:
            flash("Please select a file to analyze.", "warning")
            return render_template("upload.html", result={"status": "error", "message": "No file selected."})

        result = analyze_file(file_obj)
        if result["status"] in {"error", "duplicate"}:
            return render_template("upload.html", result=result)

        result["metadata"] = analyze_metadata(result["stored_path"])
        result["stego_analysis"] = analyze_all_tools(result["stored_path"])
        result["advanced_analysis"] = {
            "strings": analyze_strings(result["stored_path"]),
            "base64": analyze_base64(result["stored_path"]),
            "entropy": analyze_entropy(result["stored_path"]),
            "hex": build_hex_preview(result["stored_path"]),
            "signature": analyze_signature(result["stored_path"]),
            "image": analyze_image(result["stored_path"]) if result["actual_type"] in {"png", "jpeg", "jpg", "gif", "bmp", "tiff"} else {"tool_name": "Image Analysis", "available": False, "status": "not_applicable", "findings": []},
        }
        risk_assessment = build_risk_assessment(result)
        result["risk_assessment"] = risk_assessment
        result["risk_status"] = risk_assessment["risk_level"]
        result["risk_score"] = risk_assessment["risk_score"]

        legacy_risk = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "high"}.get(risk_assessment["risk_level"], "low")
        report_payload = {
            "filename": result["filename"],
            "sha256": result["sha256"],
            "file_format": result["actual_type"],
            "analysis_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "metadata_summary": result["metadata"].get("summary", "No metadata available."),
            "risk_status": legacy_risk,
            "risk_score": risk_assessment["risk_score"],
            "risk_level": risk_assessment["risk_level"],
            "detection_summary": risk_assessment["summary"],
            "status": "New",
            "investigation_notes": "",
            "mitre_attack": ", ".join(risk_assessment.get("mitre_attack", [])),
            "file_size": result["file_size"],
            "mime_type": result["mime_type"],
            "warning": result["metadata"].get("warning", ""),
            "stored_file": result.get("stored_filename"),
            "risk_assessment": risk_assessment,
            "advanced_analysis": result["advanced_analysis"],
            "metadata": result["metadata"],
            "stego_analysis": result["stego_analysis"],
        }
        investigation = {
            "filename": result["filename"],
            "sha256": result["sha256"],
            "file_format": result["actual_type"],
            "analysis_timestamp": report_payload["analysis_timestamp"],
            "metadata_summary": result["metadata"].get("summary", "No metadata available."),
            "risk_status": legacy_risk,
            "risk_score": risk_assessment["risk_score"],
            "risk_level": risk_assessment["risk_level"],
            "status": "New",
            "investigation_notes": "",
            "mitre_attack": ", ".join(risk_assessment.get("mitre_attack", [])),
            "detection_summary": risk_assessment["summary"],
            "report_data": report_payload,
            "file_size": result["file_size"],
            "mime_type": result["mime_type"],
            "warning": result["metadata"].get("warning", ""),
            "stored_file": result.get("stored_filename"),
        }
        investigation_id = save_investigation(investigation)
        result["investigation_id"] = investigation_id
        result["status"] = "success"
        if result.get("mismatch_detected"):
            result["message"] = "Extension mismatch detected. Review the file carefully."
        try:
            os.remove(result["stored_path"])
        except Exception:
            pass
        result["stored_path"] = None
        return render_template("analysis.html", result=result)

    return render_template("upload.html")


@app.route("/history")
def history():
    search_term = request.args.get("search", "").strip()
    date_filter = request.args.get("date", "").strip()
    severity_filter = request.args.get("severity", "").strip()
    status_filter = request.args.get("status", "").strip()
    investigations = search_investigations(
        search=search_term,
        start_date=date_filter,
        end_date=date_filter,
        severity=severity_filter,
        status=status_filter,
        limit=50,
    )
    return render_template("history.html", investigations=investigations, stats=get_dashboard_stats(), search=search_term, date_filter=date_filter, severity_filter=severity_filter, status_filter=status_filter)


@app.route("/reports")
def reports():
    recent = get_recent_investigations(limit=10)
    return render_template("reports.html", recent=recent, stats=get_dashboard_stats(), reports=True)


@app.route("/about")
def about():
    return render_template("about.html", stats=get_dashboard_stats(), recent=get_recent_investigations(limit=5), about=True)


@app.route("/settings")
def settings():
    return render_template("settings.html", stats=get_dashboard_stats(), recent=get_recent_investigations(limit=5), settings=True)


@app.route("/analysis/<int:investigation_id>", methods=["GET", "POST"])
def analysis(investigation_id):
    item = get_investigation_by_id(investigation_id)
    if not item:
        return render_template("upload.html", result={"status": "error", "message": "Investigation not found."})
    if request.method == "POST":
        new_status = request.form.get("status")
        notes = request.form.get("notes")
        if new_status:
            update_investigation_status(investigation_id, new_status)
        if notes:
            update_investigation_notes(investigation_id, notes)
        item = get_investigation_by_id(investigation_id)

    report_data = item.get("report_data") or {}
    if isinstance(report_data, str):
        try:
            report_data = json.loads(report_data)
        except Exception:
            report_data = {}
    if report_data:
        item["risk_assessment"] = report_data.get("risk_assessment", item.get("risk_assessment") or {"risk_score": item.get("risk_score", 0), "risk_level": item.get("risk_level", "informational"), "summary": item.get("detection_summary", "No summary available.")})
        item["metadata"] = report_data.get("metadata", {"summary": item.get("metadata_summary", "No metadata summary available."), "anomalies": []})
        item["stego_analysis"] = report_data.get("stego_analysis", {})
        item["advanced_analysis"] = report_data.get("advanced_analysis", {})
    item["status"] = item.get("status") or "New"
    item["risk_score"] = item.get("risk_score", item.get("risk_assessment", {}).get("risk_score", 0))
    item["risk_level"] = item.get("risk_level") or item.get("risk_assessment", {}).get("risk_level") or "informational"
    item["risk_status"] = item.get("risk_status") or item.get("risk_level") or "low"
    return render_template("analysis.html", result=item)


@app.route("/reports/<int:investigation_id>/download/<string:report_type>")
def download_report(investigation_id, report_type):
    item = get_investigation_by_id(investigation_id)
    if not item:
        return render_template("upload.html", result={"status": "error", "message": "Investigation not found."})

    report_type = report_type.lower()
    if report_type == "pdf":
        pdf_path = generate_pdf_report(item, output_dir=REPORTS_FOLDER)
        return send_file(pdf_path, as_attachment=True, download_name=f"report_{investigation_id}.pdf", mimetype="application/pdf")
    if report_type == "json":
        payload = generate_json_report(item)
        response = Response(json.dumps(payload, indent=2), mimetype="application/json")
        response.headers["Content-Disposition"] = f"attachment; filename=report_{investigation_id}.json"
        return response
    if report_type == "html":
        html = generate_html_report(item)
        response = Response(html, mimetype="text/html")
        response.headers["Content-Disposition"] = f"attachment; filename=report_{investigation_id}.html"
        return response
    return render_template("upload.html", result={"status": "error", "message": "Unsupported report type."})


@app.route("/health")
def health():
    return {"status": "ok", "database": DATABASE_PATH}


def classify_risk(result):
    metadata = result.get("metadata", {})
    anomalies = metadata.get("anomalies", [])
    risk = "low"
    if result.get("mismatch_detected"):
        risk = "medium"
    if result.get("status") == "duplicate":
        risk = "suspicious"
    if anomalies:
        risk = "suspicious" if risk in {"low", "medium"} else "high"
    if metadata.get("warning"):
        risk = "medium"
    if result.get("actual_type") in {"exe", "bin"}:
        risk = "high"
    return risk


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
