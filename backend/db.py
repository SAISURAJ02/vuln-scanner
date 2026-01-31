"""SQLite storage layer for scan results."""

import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            hostname TEXT,
            scanned_at TEXT NOT NULL,
            risk_score INTEGER,
            risk_grade TEXT,
            findings_json TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_scan(result: dict) -> int:
    conn = get_conn()
    cur = conn.execute(
        """INSERT INTO scans (target, hostname, scanned_at, risk_score, risk_grade, findings_json)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            result["target"],
            result["hostname"],
            result["scanned_at"],
            result["risk"]["score"],
            result["risk"]["grade"],
            json.dumps(result["findings"]),
        ),
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def get_all_scans() -> list[dict]:
    conn = get_conn()
    rows = conn.execute("SELECT * FROM scans ORDER BY scanned_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    if not row:
        return None
    result = dict(row)
    result["findings"] = json.loads(result.pop("findings_json"))
    return result


def delete_scan(scan_id: int) -> bool:
    conn = get_conn()
    cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    deleted = cur.rowcount > 0
    conn.close()
    return deleted
