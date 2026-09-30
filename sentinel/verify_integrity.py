"""
verify_integrity.py
Walks the evidence hash chain in chimeramesh.db and verifies that
each record's stored hash matches a fresh recomputation from its
declared previous hash + payload. Reports the exact first broken link.

Usage:
    python verify_integrity.py
"""

import os
import sqlite3
import hashlib
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "chimeramesh.db")


def recompute_hash(prev_hash, row):
    """
    Recompute a record's hash exactly the way storage.log_event built it:
    canonical JSON of the payload with numerics in their SQLite-stored
    types (REAL for timestamp/intent_score, INTEGER for containment_stage).
    """
    payload = {
        "timestamp": float(row["timestamp"]),
        "session_id": str(row["session_id"]),
        "ip": str(row["ip"]),
        "service": str(row["service"]),
        "persona": str(row["persona"]),
        "event_type": str(row["event_type"]),
        "detail": json.loads(row["detail"]) if isinstance(row["detail"], str) else row["detail"],
        "intent_score": float(row["intent_score"]),
        "severity": str(row["severity"]),
        "containment_stage": int(row["containment_stage"]),
    }
    canonical = json.dumps(payload, sort_keys=True, default=str)
    h = hashlib.sha256()
    h.update((prev_hash + canonical).encode("utf-8"))
    return h.hexdigest()


def verify(verbose=True):
    """Walk the whole chain. Returns True if intact, False otherwise."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM events ORDER BY id ASC")
    rows = cur.fetchall()
    conn.close()

    if not rows:
        if verbose:
            print("No events found. Nothing to verify.")
        return True

    prev_hash = "GENESIS"
    for row in rows:
        expected = recompute_hash(prev_hash, row)
        if expected != row["record_hash"]:
            if verbose:
                print("=" * 60)
                print("INTEGRITY VIOLATION DETECTED")
                print(f"  Event id:        {row['id']}")
                print(f"  Timestamp:       {row['timestamp']}")
                print(f"  Event type:      {row['event_type']}")
                print(f"  Stored hash:     {row['record_hash']}")
                print(f"  Recomputed hash: {expected}")
                print("  -> This record (or an earlier one) has been altered.")
                print("=" * 60)
            return False
        prev_hash = row["record_hash"]

    if verbose:
        print(f"OK - all {len(rows)} events verified. Chain is intact.")
    return True


if __name__ == "__main__":
    verify()
