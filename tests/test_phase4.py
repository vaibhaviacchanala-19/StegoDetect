from modules.risk_engine import build_risk_assessment, classify_risk_score


def test_clean_file_stays_informational_or_low():
    assessment = build_risk_assessment({
        "filename": "clean.png",
        "actual_type": "png",
        "metadata": {"available": True, "warning": None, "anomalies": [], "summary": "No obvious metadata inconsistencies detected."},
        "stego_analysis": {"overall_status": "ok", "tools": {}},
        "advanced_analysis": {"strings": {"findings": []}, "signature": {"findings": []}},
    })
    assert assessment["risk_score"] <= 40
    assert assessment["risk_level"] in {"informational", "low"}


def test_suspicious_metadata_increases_risk():
    assessment = build_risk_assessment({
        "filename": "gps.jpg",
        "metadata": {"anomalies": ["GPS metadata detected: 12.00, 34.00"], "summary": "Metadata extracted from 20 fields. Anomalies: 1."},
        "stego_analysis": {"overall_status": "ok", "tools": {}},
        "advanced_analysis": {"strings": {"findings": []}, "signature": {"findings": []}},
    })
    assert assessment["risk_score"] >= 25
    assert any(item["title"] == "Suspicious metadata" for item in assessment["findings"])


def test_embedded_archive_detects_high_risk():
    assessment = build_risk_assessment({
        "filename": "hidden.zip.png",
        "actual_type": "png",
        "metadata": {"anomalies": [], "summary": "No metadata anomalies"},
        "stego_analysis": {
            "overall_status": "warning",
            "tools": {
                "binwalk": {"findings": [{"finding_name": "Embedded archive", "description": "ZIP archive detected", "evidence": "PK\x03\x04", "severity": "high"}]}
            },
        },
        "advanced_analysis": {"strings": {"findings": []}, "signature": {"findings": []}},
    })
    assert assessment["risk_score"] >= 60
    assert any(item["title"] == "Embedded archive" for item in assessment["findings"])


def test_executable_signature_is_ranked_high():
    assessment = build_risk_assessment({
        "filename": "payload.exe",
        "actual_type": "exe",
        "metadata": {"anomalies": [], "summary": "No metadata"},
        "stego_analysis": {"overall_status": "ok", "tools": {}},
        "advanced_analysis": {"strings": {"findings": []}, "signature": {"findings": [{"finding_name": "Executable header", "description": "PE header discovered in a non-executable file.", "evidence": "MZ header", "severity": "critical"}] }},
    })
    assert assessment["risk_score"] >= 70
    assert assessment["risk_level"] in {"high", "critical"}


def test_multiple_indicators_raise_severity():
    assessment = build_risk_assessment({
        "filename": "multi.png",
        "actual_type": "png",
        "metadata": {"anomalies": ["GPS metadata detected: 12.00, 34.00"], "summary": "Metadata extracted from 20 fields. Anomalies: 1."},
        "stego_analysis": {"overall_status": "warning", "tools": {"binwalk": {"findings": [{"finding_name": "Embedded archive", "description": "ZIP archive found", "evidence": "PK\x03\x04", "severity": "high"}]}}},
        "advanced_analysis": {"strings": {"findings": [{"extracted_string": "http://evil.example/C2", "category": "url", "risk": "medium"}]}, "signature": {"findings": [{"finding_name": "Unexpected file signature", "description": "Mismatch between PNG signature and extension.", "evidence": "\x89PNG", "severity": "medium"}] }, "image": {"available": True, "lsb_summary": {"odd_lsb_count": 123}}},
    })
    assert assessment["risk_score"] >= 60
    assert len(assessment["findings"]) >= 3


def test_inconclusive_analysis_stays_low():
    assessment = build_risk_assessment({
        "filename": "unclear.bin",
        "actual_type": "bin",
        "metadata": {"available": False, "warning": "ExifTool unavailable", "anomalies": ["ExifTool unavailable"], "summary": "ExifTool unavailable; no metadata was extracted."},
        "stego_analysis": {"overall_status": "warning", "tools": {"steghide": {"status": "unavailable"}, "zsteg": {"status": "unavailable"}}},
        "advanced_analysis": {"strings": {"findings": []}, "signature": {"findings": []}},
    })
    assert assessment["risk_score"] <= 50
    assert assessment["risk_level"] in {"informational", "low", "medium"}


def test_tool_unavailable_does_not_drive_critical_risk():
    assessment = build_risk_assessment({
        "filename": "sample.jpg",
        "metadata": {"available": False, "warning": "ExifTool unavailable", "anomalies": ["ExifTool unavailable"]},
        "stego_analysis": {"overall_status": "warning", "tools": {"steghide": {"status": "unavailable"}, "zsteg": {"status": "unavailable"}}},
        "advanced_analysis": {"strings": {"findings": []}, "signature": {"findings": []}},
    })
    assert assessment["risk_score"] < 80
    assert assessment["risk_level"] != "critical"
    assert any(item["title"] == "Tool availability note" for item in assessment["findings"])


def test_classify_risk_score_ranges():
    assert classify_risk_score(10) == "informational"
    assert classify_risk_score(30) == "low"
    assert classify_risk_score(50) == "medium"
    assert classify_risk_score(70) == "high"
    assert classify_risk_score(90) == "critical"
