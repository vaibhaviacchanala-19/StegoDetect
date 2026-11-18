import json
import os

from database.db import clear_investigations, save_investigation, search_investigations
from modules.report_generator import generate_html_report, generate_json_report, generate_pdf_report


def _sample_investigation():
    return {
        "id": 1,
        "filename": "suspicious.png",
        "sha256": "abc123",
        "file_format": "png",
        "analysis_timestamp": "2026-11-17 12:00:00",
        "risk_score": 82,
        "risk_status": "high",
        "risk_level": "critical",
        "detection_summary": "Archive plus suspicious strings detected.",
        "status": "Escalated",
        "metadata_summary": "GPS metadata detected.",
        "risk_assessment": {
            "risk_score": 82,
            "risk_level": "critical",
            "executive_summary": "Critical hidden payload identified.",
            "evidence_summary": "Embedded archive and suspicious strings found.",
            "findings": [
                {
                    "title": "Embedded archive",
                    "description": "ZIP archive detected in container.",
                    "evidence": "PK\\x03\\x04",
                    "severity": "high",
                    "recommended_action": "Isolate and review embedded archive.",
                },
                {
                    "title": "Suspicious strings",
                    "description": "Command and control URL found.",
                    "evidence": "http://evil.example/C2",
                    "severity": "medium",
                    "recommended_action": "Inspect URL and yields.",
                },
            ],
        },
        "advanced_analysis": {
            "strings": {"findings": [{"extracted_string": "http://evil.example/C2", "category": "url", "risk": "medium"}]},
            "signature": {"findings": [{"finding_name": "Unexpected file signature", "description": "Mismatch seen.", "evidence": "MZ"}]},
            "entropy": {"overall_entropy": 7.9},
        },
        "file_size": 12345,
    }


def test_pdf_generation_creates_report_file(tmp_path):
    path = generate_pdf_report(_sample_investigation(), output_dir=str(tmp_path))
    assert os.path.exists(path)
    assert path.lower().endswith(".pdf")


def test_json_generation_contains_analysis_findings():
    payload = generate_json_report(_sample_investigation())
    assert payload["risk_level"] == "critical"
    assert payload["findings"]
    assert payload["findings"][0]["title"] == "Embedded archive"


def test_html_generation_contains_summary_and_download_links():
    html = generate_html_report(_sample_investigation())
    assert "StegoDetect" in html
    assert "Critical hidden payload identified." in html
    assert "Download JSON" in html


def test_history_storage_and_search():
    clear_investigations()
    save_investigation({
        "filename": "first.png",
        "sha256": "111111",
        "file_format": "png",
        "analysis_timestamp": "2026-11-17 10:00:00",
        "risk_score": 20,
        "risk_status": "low",
        "risk_level": "low",
        "detection_summary": "No suspicious indicators.",
        "status": "Closed",
        "metadata_summary": "No metadata anomalies.",
    })
    save_investigation({
        "filename": "second.zip",
        "sha256": "222222",
        "file_format": "zip",
        "analysis_timestamp": "2026-11-17 11:00:00",
        "risk_score": 85,
        "risk_status": "high",
        "risk_level": "critical",
        "detection_summary": "Embedded archive detected.",
        "status": "Escalated",
        "metadata_summary": "GPS metadata detected.",
    })
    results = search_investigations(search="second", status="Escalated")
    assert len(results) == 1
    assert results[0]["filename"] == "second.zip"

    filtered = search_investigations(severity="critical")
    assert any(item["risk_level"] == "critical" for item in filtered)


def test_report_downloads_are_not_empty(tmp_path):
    payload = _sample_investigation()
    pdf_path = generate_pdf_report(payload, output_dir=str(tmp_path))
    json_doc = json.loads(json.dumps(generate_json_report(payload)))
    html_doc = generate_html_report(payload)
    assert os.path.getsize(pdf_path) > 200
    assert "risk_score" in json_doc and "findings" in json_doc
    assert "Download JSON" in html_doc
