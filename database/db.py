import json
import sqlite3
from typing import Any, Dict, List, Optional

from config import DATABASE_PATH


def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    _ensure_schema_columns(conn)
    return conn


def _ensure_schema_columns(conn=None):
    if conn is None:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        close_conn = True
    else:
        close_conn = False
    table_exists = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='investigations'").fetchone()
    if table_exists is None:
        conn.execute(
            """
            CREATE TABLE investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                file_format TEXT NOT NULL,
                analysis_timestamp TEXT NOT NULL,
                metadata_summary TEXT,
                risk_status TEXT DEFAULT 'low',
                file_size INTEGER,
                mime_type TEXT,
                warning TEXT,
                stored_file TEXT
            )
            """
        )
    columns = [row[1] for row in conn.execute("PRAGMA table_info(investigations)").fetchall()]
    additions = {
        "risk_score": "INTEGER DEFAULT 0",
        "risk_level": "TEXT DEFAULT 'informational'",
        "status": "TEXT DEFAULT 'New'",
        "investigation_notes": "TEXT DEFAULT ''",
        "mitre_attack": "TEXT DEFAULT ''",
        "detection_summary": "TEXT DEFAULT ''",
        "report_data": "TEXT DEFAULT ''",
    }
    for column_name, definition in additions.items():
        if column_name not in columns:
            conn.execute(f"ALTER TABLE investigations ADD COLUMN {column_name} {definition}")
    conn.commit()
    if close_conn:
        conn.close()


def init_db():
    conn = get_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            file_format TEXT NOT NULL,
            analysis_timestamp TEXT NOT NULL,
            metadata_summary TEXT,
            risk_status TEXT DEFAULT 'low',
            file_size INTEGER,
            mime_type TEXT,
            warning TEXT,
            stored_file TEXT
        )
        """
    )
    conn.commit()
    conn.close()
    _ensure_schema_columns()


def save_investigation(data: Dict[str, Any]) -> int:
    conn = get_connection()
    report_data = data.get("report_data")
    if isinstance(report_data, (dict, list)):
        report_data_json = json.dumps(report_data)
    else:
        report_data_json = report_data or ""
    cursor = conn.execute(
        """
        INSERT INTO investigations (
            filename,
            sha256,
            file_format,
            analysis_timestamp,
            metadata_summary,
            risk_status,
            risk_score,
            risk_level,
            status,
            investigation_notes,
            mitre_attack,
            detection_summary,
            report_data,
            file_size,
            mime_type,
            warning,
            stored_file
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.get("filename"),
            data.get("sha256"),
            data.get("file_format"),
            data.get("analysis_timestamp"),
            data.get("metadata_summary"),
            data.get("risk_status"),
            data.get("risk_score", 0),
            data.get("risk_level", "informational"),
            data.get("status", "New"),
            data.get("investigation_notes", ""),
            data.get("mitre_attack", ""),
            data.get("detection_summary", ""),
            report_data_json,
            data.get("file_size"),
            data.get("mime_type"),
            data.get("warning"),
            data.get("stored_file"),
        ),
    )
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def update_investigation_status(investigation_id: int, status: str):
    conn = get_connection()
    conn.execute("UPDATE investigations SET status = ? WHERE id = ?", (status, investigation_id))
    conn.commit()
    conn.close()


def update_investigation_notes(investigation_id: int, notes: str):
    conn = get_connection()
    conn.execute("UPDATE investigations SET investigation_notes = ? WHERE id = ?", (notes, investigation_id))
    conn.commit()
    conn.close()


def search_investigations(search: str = "", start_date: Optional[str] = None, end_date: Optional[str] = None, severity: Optional[str] = None, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    clauses = []
    params: List[Any] = []

    if search:
        clauses.append("(LOWER(filename) LIKE ? OR LOWER(sha256) LIKE ?)")
        search_term = f"%{search.lower()}%"
        params.extend([search_term, search_term])
    if start_date:
        clauses.append("analysis_timestamp >= ?")
        params.append(start_date)
    if end_date:
        clauses.append("analysis_timestamp <= ?")
        params.append(end_date)
    if severity:
        clauses.append("(LOWER(risk_level) = ? OR LOWER(risk_status) = ?)")
        severity_term = severity.lower()
        params.extend([severity_term, severity_term])
    if status:
        clauses.append("LOWER(status) = ?")
        params.append(status.lower())

    query = "SELECT * FROM investigations"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY analysis_timestamp DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, tuple(params)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_recent_investigations(limit: int = 10) -> List[Dict[str, Any]]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM investigations ORDER BY analysis_timestamp DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def sha256_exists(sha256_value: str) -> bool:
    conn = get_connection()
    row = conn.execute("SELECT 1 FROM investigations WHERE sha256 = ? LIMIT 1", (sha256_value,)).fetchone()
    conn.close()
    return row is not None


def clear_investigations():
    conn = get_connection()
    conn.execute("DELETE FROM investigations")
    conn.commit()
    conn.close()


def get_dashboard_stats() -> Dict[str, Any]:
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) AS count FROM investigations").fetchone()["count"]
    suspicious = conn.execute(
        "SELECT COUNT(*) AS count FROM investigations WHERE risk_status IN ('medium', 'suspicious', 'high') OR risk_score >= 41"
    ).fetchone()["count"]
    embedded = conn.execute(
        "SELECT COUNT(*) AS count FROM investigations WHERE risk_score >= 60 OR risk_level IN ('high', 'critical')"
    ).fetchone()["count"]
    high_risk = conn.execute("SELECT COUNT(*) AS count FROM investigations WHERE risk_score >= 60 OR risk_level IN ('high', 'critical')").fetchone()["count"]
    recent_alerts = conn.execute(
        "SELECT COUNT(*) AS count FROM investigations WHERE risk_score >= 41 OR status IN ('Investigation Required', 'Escalated')"
    ).fetchone()["count"]
    risk_distribution = {
        "informational": conn.execute("SELECT COUNT(*) AS count FROM investigations WHERE risk_level = 'informational' OR risk_score <= 20").fetchone()["count"],
        "low": conn.execute("SELECT COUNT(*) AS count FROM investigations WHERE risk_level = 'low' OR (risk_score > 20 AND risk_score <= 40)").fetchone()["count"],
        "medium": conn.execute("SELECT COUNT(*) AS count FROM investigations WHERE risk_level = 'medium' OR (risk_score > 40 AND risk_score <= 60)").fetchone()["count"],
        "high": conn.execute("SELECT COUNT(*) AS count FROM investigations WHERE risk_level = 'high' OR (risk_score > 60 AND risk_score <= 80)").fetchone()["count"],
        "critical": conn.execute("SELECT COUNT(*) AS count FROM investigations WHERE risk_level = 'critical' OR risk_score > 80").fetchone()["count"],
    }
    metadata_anomalies = conn.execute(
        "SELECT COUNT(*) AS count FROM investigations WHERE metadata_summary LIKE '%Anomalies:%' OR warning IS NOT NULL OR metadata_summary LIKE '%GPS%'"
    ).fetchone()["count"]
    file_type_distribution = conn.execute(
        "SELECT file_format, COUNT(*) AS count FROM investigations GROUP BY file_format ORDER BY count DESC LIMIT 6"
    ).fetchall()
    detection_techniques = [
        {"label": "Strings", "value": conn.execute("SELECT COUNT(*) AS count FROM investigations WHERE metadata_summary LIKE '%Anomalies:%' OR filename LIKE '%cmd%' OR filename LIKE '%exe%' OR metadata_summary LIKE '%GPS%' ").fetchone()["count"]},
        {"label": "Signatures", "value": conn.execute("SELECT COUNT(*) AS count FROM investigations WHERE risk_score >= 20").fetchone()["count"]},
        {"label": "Entropy", "value": conn.execute("SELECT COUNT(*) AS count FROM investigations WHERE risk_score >= 30").fetchone()["count"]},
        {"label": "Metadata", "value": metadata_anomalies},
    ]
    trends = conn.execute(
        "SELECT substr(analysis_timestamp, 1, 10) AS day, COUNT(*) AS count FROM investigations GROUP BY day ORDER BY day DESC LIMIT 7"
    ).fetchall()
    conn.close()
    return {
        "total_files": total,
        "suspicious_files": suspicious,
        "confirmed_embedded_files": embedded,
        "high_risk_investigations": high_risk,
        "recent_alerts": recent_alerts,
        "metadata_anomalies": metadata_anomalies,
        "recent_investigations": total,
        "risk_distribution": risk_distribution,
        "file_type_distribution": [{"label": str(row["file_format"]), "value": int(row["count"])} for row in file_type_distribution],
        "detection_techniques": detection_techniques,
        "investigation_trends": [{"label": str(row["day"]), "value": int(row["count"])} for row in trends],
    }


def get_investigation_by_id(investigation_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    row = conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
    conn.close()
    if row is None:
        return None
    item = dict(row)
    report_data = item.get("report_data")
    if report_data:
        try:
            item["report_data"] = json.loads(report_data)
        except Exception:
            item["report_data"] = {}
    return item
