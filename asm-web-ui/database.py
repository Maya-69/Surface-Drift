"""
Database manager for AttackSurfaceMapper Web UI.
Handles user authentication records and scan history using SQLite.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path(__file__).resolve().parent / "data" / "asm_history.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                picture TEXT,
                google_id TEXT,
                created_at TEXT NOT NULL,
                last_login_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                target TEXT NOT NULL,
                mode TEXT NOT NULL DEFAULT 'passive',
                status TEXT NOT NULL DEFAULT 'running',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                duration_seconds REAL DEFAULT 0,
                subdomains_count INTEGER DEFAULT 0,
                ips_count INTEGER DEFAULT 0,
                ports_count INTEGER DEFAULT 0,
                emails_count INTEGER DEFAULT 0,
                buckets_count INTEGER DEFAULT 0,
                summary_json TEXT,
                zip_name TEXT,
                zip_size_bytes INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC)")

        # Migration: SurfaceDrift columns
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN surfacedrift_json TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN risk_score INTEGER")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN grade TEXT")
        except sqlite3.OperationalError:
            pass


# User operations
def get_or_create_user(email: str, name: str, picture: str = "", google_id: str = "") -> dict[str, Any]:
    email = email.strip().lower()
    name = name.strip() or email.split("@")[0]
    now = utc_now()

    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cur.fetchone()
        if row:
            user_id = row["id"]
            cur.execute("""
                UPDATE users SET name = ?, picture = ?, google_id = COALESCE(NULLIF(?, ''), google_id), last_login_at = ?
                WHERE id = ?
            """, (name, picture, google_id, now, user_id))
            conn.commit()
            return get_user_by_id(user_id) or dict(row)
        else:
            import uuid
            user_id = f"usr_{uuid.uuid4().hex[:12]}"
            cur.execute("""
                INSERT INTO users (id, email, name, picture, google_id, created_at, last_login_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, email, name, picture, google_id, now, now))
            conn.commit()
            return get_user_by_id(user_id) or {
                "id": user_id, "email": email, "name": name, "picture": picture, "created_at": now
            }


def get_user_by_id(user_id: str) -> Optional[dict[str, Any]]:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, email, name, picture, created_at, last_login_at FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None


# Scan operations
def record_scan_start(scan_id: str, target: str, mode: str, user_id: Optional[str] = None) -> None:
    now = utc_now()
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO scans (id, user_id, target, mode, status, started_at)
            VALUES (?, ?, ?, ?, 'running', ?)
        """, (scan_id, user_id, target, mode, now))
        conn.commit()


def record_scan_completion(
    scan_id: str,
    status: str,
    duration_seconds: float,
    summary: Optional[dict[str, Any]] = None,
    zip_name: str = "",
    zip_size_bytes: int = 0
) -> None:
    now = utc_now()
    counts = (summary or {}).get("counts", {}) if summary else {}
    summary_json_str = json.dumps(summary) if summary else None

    subdomains_count = counts.get("subdomains", 0)
    ips_count = counts.get("ips", 0)
    ports_count = counts.get("ports", 0)
    emails_count = counts.get("emails", 0)
    buckets_count = counts.get("buckets", 0)

    with get_connection() as conn:
        conn.execute("""
            UPDATE scans
            SET status = ?, completed_at = ?, duration_seconds = ?,
                subdomains_count = ?, ips_count = ?, ports_count = ?,
                emails_count = ?, buckets_count = ?,
                summary_json = ?, zip_name = ?, zip_size_bytes = ?
            WHERE id = ?
        """, (
            status, now, duration_seconds,
            subdomains_count, ips_count, ports_count,
            emails_count, buckets_count,
            summary_json_str, zip_name, zip_size_bytes,
            scan_id
        ))
        conn.commit()


def record_surfacedrift_advanced(scan_id: str, advanced: dict[str, Any]) -> None:
    score = advanced.get("posture", {}).get("score")
    grade = advanced.get("posture", {}).get("grade")
    adv_json = json.dumps(advanced)
    with get_connection() as conn:
        conn.execute("""
            UPDATE scans
            SET surfacedrift_json = ?, risk_score = ?, grade = ?
            WHERE id = ?
        """, (adv_json, score, grade, scan_id))
        conn.commit()


def get_user_scans(user_id: Optional[str] = None, limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as conn:
        cur = conn.cursor()
        if user_id:
            cur.execute("""
                SELECT id, user_id, target, mode, status, started_at, completed_at,
                       duration_seconds, subdomains_count, ips_count, ports_count,
                       emails_count, buckets_count, zip_name, zip_size_bytes,
                       risk_score, grade
                FROM scans
                WHERE user_id = ?
                ORDER BY started_at DESC
                LIMIT ?
            """, (user_id, limit))
        else:
            cur.execute("""
                SELECT id, user_id, target, mode, status, started_at, completed_at,
                       duration_seconds, subdomains_count, ips_count, ports_count,
                       emails_count, buckets_count, zip_name, zip_size_bytes,
                       risk_score, grade
                FROM scans
                ORDER BY started_at DESC
                LIMIT ?
            """, (limit,))
        rows = cur.fetchall()
        return [dict(row) for row in rows]


def get_scan_by_id(scan_id: str) -> Optional[dict[str, Any]]:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cur.fetchone()
        if not row:
            return None
        res = dict(row)
        if res.get("summary_json"):
            try:
                res["summary"] = json.loads(res["summary_json"])
            except Exception:
                res["summary"] = None
        if res.get("surfacedrift_json"):
            try:
                res["surfacedrift_advanced"] = json.loads(res["surfacedrift_json"])
            except Exception:
                res["surfacedrift_advanced"] = None
        return res


def delete_scan(scan_id: str, user_id: Optional[str] = None) -> bool:
    with get_connection() as conn:
        cur = conn.cursor()
        if user_id:
            cur.execute("DELETE FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id))
        else:
            cur.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        return cur.rowcount > 0


init_db()
