"""
rule_engine.py
THE CORE INNOVATION OF CHIMERAMESH SENTINEL: the Deception-Fed Detection Loop.

Confirmed-malicious events observed at the honeypot (where, by construction,
every visitor is unauthorized - there is no legitimate traffic to a decoy)
are automatically converted into lightweight detection rules. Those rules
then protect the REAL protected service (protected_service.py), closing the
gap where a honeypot's threat intelligence normally never becomes a live
detection rule anywhere else.

Every rule is:
  - traceable to the exact evidence-log event that generated it
    ("learned from event #N"), never invented from a static external feed
  - human-readable (a regex pattern + metadata), never a black-box weight
  - confidence-scored, decayed over time, and demotable by an operator
    marking a false positive - a fully auditable weight, not silent
    retraining

Reuses storage.py's connection helpers (same chimeramesh.db) rather than
keeping a second, parallel data store.
"""

import re
import time
import threading
import sqlite3

import storage

_lock = threading.Lock()

# A rule's confidence decays by this fraction per day of not matching,
# and is retired once it drops below RETIRE_THRESHOLD.
DAILY_DECAY = 0.05
RETIRE_THRESHOLD = 0.1
FALSE_POSITIVE_PENALTY = 0.3

# Points a matched rule contributes to a session's score on the protected
# service, scaled by the rule's current confidence (0..1).
BASE_RULE_POINTS = 12


def init_sentinel_db():
    conn = storage.get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sentinel_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT,
            category TEXT,
            source_event_id INTEGER,
            confidence REAL,
            created_at REAL,
            last_matched_at REAL,
            match_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active'
        )
    """)
    conn.commit()
    conn.close()


def generate_rule_from_event(event_id, pattern, category, initial_confidence=0.8):
    """
    Called by the honeypot decoys when they observe a confirmed-malicious
    pattern (e.g. a payload signature, a credential string). Creates a new
    rule citing the exact event that produced it.
    """
    with _lock:
        conn = storage.get_conn()
        cur = conn.cursor()
        # Don't create an exact duplicate of an already-active rule
        cur.execute("SELECT id FROM sentinel_rules WHERE pattern=? AND status='active'",
                    (pattern,))
        if cur.fetchone():
            conn.close()
            return None
        cur.execute("""
            INSERT INTO sentinel_rules
            (pattern, category, source_event_id, confidence, created_at,
             last_matched_at, match_count, status)
            VALUES (?,?,?,?,?,?,0,'active')
        """, (pattern, category, event_id, initial_confidence, time.time(), time.time()))
        conn.commit()
        rule_id = cur.lastrowid
        conn.close()
        storage.log_event(
            "sentinel", "internal", "SENTINEL", "rule-engine", "rule_generated",
            {"rule_id": rule_id, "pattern": pattern, "category": category,
             "learned_from_event": event_id, "confidence": initial_confidence},
            intent_score=0, severity="INFO", containment_stage=0,
        )
        return rule_id


def _active_rules():
    conn = storage.get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM sentinel_rules WHERE status='active'")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def match(text):
    """
    Check text (a request payload, a command, a credential string) against
    every active rule. Returns a list of (rule_id, category, points, reason)
    for every match, so the caller can award points through the SAME
    transparent scoring model (scoring.SessionState.record_rule_match).
    """
    if not text:
        return []
    hits = []
    for rule in _active_rules():
        try:
            if re.search(rule["pattern"], text, re.IGNORECASE):
                points = round(BASE_RULE_POINTS * rule["confidence"], 1)
                reason = (f"matched rule R-{rule['id']:03d} "
                          f"[learned from evidence #{rule['source_event_id']}], "
                          f"confidence {rule['confidence']:.2f}")
                hits.append((rule["id"], rule["category"], points, reason))
                _record_match(rule["id"])
        except re.error:
            continue
    return hits


def _record_match(rule_id):
    conn = storage.get_conn()
    cur = conn.cursor()
    cur.execute("""
        UPDATE sentinel_rules SET last_matched_at=?, match_count=match_count+1
        WHERE id=?
    """, (time.time(), rule_id))
    conn.commit()
    conn.close()


def demote_rule(rule_id, reason="operator marked false positive"):
    """
    Operator feedback: visibly and transparently reduce a rule's
    confidence. No hidden retraining - just an auditable number change,
    logged to the same evidence chain as everything else.
    """
    conn = storage.get_conn()
    cur = conn.cursor()
    cur.execute("SELECT confidence FROM sentinel_rules WHERE id=?", (rule_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    new_conf = max(0.0, row["confidence"] - FALSE_POSITIVE_PENALTY)
    status = "retired" if new_conf < RETIRE_THRESHOLD else "active"
    cur.execute("UPDATE sentinel_rules SET confidence=?, status=? WHERE id=?",
                (new_conf, status, rule_id))
    conn.commit()
    conn.close()
    storage.log_event(
        "sentinel", "internal", "SENTINEL", "rule-engine", "rule_demoted",
        {"rule_id": rule_id, "new_confidence": new_conf, "status": status,
         "reason": reason},
        intent_score=0, severity="INFO", containment_stage=0,
    )
    return new_conf


def decay_rules():
    """Age out rules that haven't proven themselves - call periodically."""
    conn = storage.get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, confidence, last_matched_at FROM sentinel_rules WHERE status='active'")
    rows = cur.fetchall()
    now = time.time()
    for row in rows:
        days_idle = (now - row["last_matched_at"]) / 86400.0
        if days_idle < 1:
            continue
        new_conf = row["confidence"] * (1 - DAILY_DECAY) ** days_idle
        status = "retired" if new_conf < RETIRE_THRESHOLD else "active"
        cur.execute("UPDATE sentinel_rules SET confidence=?, status=? WHERE id=?",
                    (new_conf, status, row["id"]))
    conn.commit()
    conn.close()


def list_rules():
    conn = storage.get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM sentinel_rules ORDER BY id DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
