"""
attack_chain.py
Causal attack-chain correlation: detects known multi-stage attack SHAPES
across an actor's event history (scan -> brute-force -> payload injection,
within a time window) and raises ONE higher-confidence incident instead of
several disconnected low-confidence alerts. This is what directly reduces
alert fatigue - the single biggest complaint about real-world IDS/IPS
deployments.

Reuses the existing evidence log (storage.py) as its only data source -
no second parallel event store.
"""

import time
import threading

import scoring
import storage

CHAIN_WINDOW_SECONDS = 600  # 10 minutes
_already_flagged = {}  # ip -> timestamp of last chain incident raised
_lock = threading.Lock()

# The chain "shapes" this engine recognizes, in order of stage.
# Each stage matches if ANY of these substrings appears in the event_type
# (substring match, not exact equality - event types like
# "bad_payload_confirmed" or "brute_force_confirmed" should still count).
CHAIN_STAGES = [
    ("reconnaissance", {"connection_open", "trap_hit", "network_scan", "port_scan"}),
    ("credential_attack", {"auth_attempt", "brute_force"}),
    ("exploitation", {"bad_payload", "command", "hard_block"}),
]


def _events_for_ip(ip, since_ts):
    """Pull this IP's events from the shared evidence log within the window."""
    conn = storage.get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM events WHERE ip=? AND timestamp >= ? ORDER BY timestamp ASC
    """, (ip, since_ts))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def evaluate_chain(ip):
    """
    Call this after any event is logged for an IP. Cheap: only looks at
    that IP's own recent history. If the recognized scan -> credential ->
    exploitation shape is present, raises ONE combined incident.
    """
    now = time.time()
    with _lock:
        last_flagged = _already_flagged.get(ip, 0)
        if now - last_flagged < CHAIN_WINDOW_SECONDS:
            return None  # already raised a chain incident recently for this actor

        events = _events_for_ip(ip, now - CHAIN_WINDOW_SECONDS)
        if not events:
            return None

        stage_hits = {}
        for stage_name, substrings in CHAIN_STAGES:
            matching = [e for e in events
                        if any(s in e["event_type"] for s in substrings)]
            if matching:
                stage_hits[stage_name] = matching

        if len(stage_hits) < len(CHAIN_STAGES):
            return None  # not all stages present yet

        _already_flagged[ip] = now
        contributing_ids = sorted({e["id"] for matches in stage_hits.values() for e in matches})

        # Award the combined incident through the SAME transparent scoring
        # model used everywhere else - no separate black-box escalation.
        session_id = events[-1]["session_id"]
        state = scoring.get_or_create_session(session_id, ip)
        pts = state.record_rule_match(
            "attack_chain_confirmed", 25,
            f"multi-stage chain confirmed: {' -> '.join(stage_hits.keys())} "
            f"(events {contributing_ids}) within {CHAIN_WINDOW_SECONDS}s"
        )
        storage.log_event(
            session_id, ip, "SENTINEL", "attack-chain", "attack_chain_incident",
            {"stages": list(stage_hits.keys()), "contributing_event_ids": contributing_ids,
             "points_awarded": pts},
            intent_score=state.score, severity=state.severity_band(),
            containment_stage=state.containment_stage(),
        )
        storage.upsert_session(session_id, ip, "attack-chain", "SENTINEL",
                                state.score, state.containment_stage())
        return contributing_ids


def list_incidents(limit=25):
    conn = storage.get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM events WHERE event_type='attack_chain_incident'
        ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows
