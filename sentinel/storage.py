"""
storage.py
Handles SQLite persistence and SHA-256 hash-chained evidence logging.
Every event written here becomes part of the tamper-evident chain.
"""

import os
import sqlite3
import hashlib
import json
import time
import threading

# Anchor the database to this file's directory so the system works
# no matter which working directory the process was launched from.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "chimeramesh.db")

_lock = threading.Lock()


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            session_id TEXT,
            ip TEXT,
            service TEXT,
            persona TEXT,
            event_type TEXT,
            detail TEXT,
            intent_score REAL,
            severity TEXT,
            containment_stage INTEGER,
            prev_hash TEXT,
            record_hash TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            ip TEXT,
            persona TEXT,
            service TEXT,
            start_time REAL,
            last_seen REAL,
            intent_score REAL DEFAULT 0,
            containment_stage INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def _hash_record(prev_hash: str, payload: dict) -> str:
    """Compute SHA-256 of previous hash + this event's canonical JSON."""
    canonical = json.dumps(payload, sort_keys=True, default=str)
    h = hashlib.sha256()
    h.update((prev_hash + canonical).encode("utf-8"))
    return h.hexdigest()


def _get_last_hash(cur) -> str:
    cur.execute("SELECT record_hash FROM events ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    return row["record_hash"] if row else "GENESIS"


def log_event(session_id, ip, service, persona, event_type, detail,
              intent_score=0.0, severity="LOW", containment_stage=0):
    """
    Append a tamper-evident event. Thread-safe.
    Returns the inserted row's id and hash.
    """
    with _lock:
        conn = get_conn()
        cur = conn.cursor()
        prev_hash = _get_last_hash(cur)
        ts = time.time()
        # Coerce numerics to the exact types SQLite will store (REAL / INTEGER
        # affinity) BEFORE hashing. Otherwise an int intent_score=0 would be
        # hashed as "0" but stored (and re-verified) as 0.0 -> "0.0", silently
        # breaking the chain on INFO-level events.
        payload = {
            "timestamp": float(ts),
            "session_id": str(session_id),
            "ip": str(ip),
            "service": str(service),
            "persona": str(persona),
            "event_type": str(event_type),
            "detail": detail,
            "intent_score": float(intent_score),
            "severity": str(severity),
            "containment_stage": int(containment_stage),
        }
        record_hash = _hash_record(prev_hash, payload)
        cur.execute("""
            INSERT INTO events
            (timestamp, session_id, ip, service, persona, event_type, detail,
             intent_score, severity, containment_stage, prev_hash, record_hash)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (ts, session_id, ip, service, persona, event_type,
              json.dumps(detail, default=str), intent_score, severity,
              containment_stage, prev_hash, record_hash))
        conn.commit()
        row_id = cur.lastrowid
        conn.close()
        return row_id, record_hash


def upsert_session(session_id, ip, persona, service, intent_score, containment_stage):
    with _lock:
        conn = get_conn()
        cur = conn.cursor()
        now = time.time()
        cur.execute("SELECT session_id FROM sessions WHERE session_id=?", (session_id,))
        if cur.fetchone():
            cur.execute("""
                UPDATE sessions SET last_seen=?, intent_score=?, containment_stage=?
                WHERE session_id=?
            """, (now, intent_score, containment_stage, session_id))
        else:
            cur.execute("""
                INSERT INTO sessions
                (session_id, ip, persona, service, start_time, last_seen,
                 intent_score, containment_stage)
                VALUES (?,?,?,?,?,?,?,?)
            """, (session_id, ip, persona, service, now, now,
                  intent_score, containment_stage))
        conn.commit()
        conn.close()


def get_recent_events(limit=50):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_sessions():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM sessions ORDER BY last_seen DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_summary():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) c FROM sessions")
    total = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) c FROM sessions WHERE intent_score >= 45")
    critical = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) c FROM sessions WHERE containment_stage >= 3")
    contained = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) c FROM sessions WHERE last_seen > ?", (time.time() - 60,))
    active = cur.fetchone()["c"]
    conn.close()
    return {"total_sessions": total, "critical": critical,
            "contained": contained, "active": active}
