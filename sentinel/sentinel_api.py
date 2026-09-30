"""
sentinel_api.py
FastAPI router extending the EXISTING dashboard (dashboard.py mounts this
at /api/sentinel) rather than standing up a second dashboard, per the
Sentinel design constraint of extending, not duplicating.
"""

from fastapi import APIRouter
from pydantic import BaseModel

import rule_engine
import attack_chain
import storage

router = APIRouter()


@router.get("/rules")
def rules():
    return rule_engine.list_rules()


class DemoteRequest(BaseModel):
    reason: str = "operator marked false positive"


@router.post("/rules/{rule_id}/demote")
def demote_rule(rule_id: int, body: DemoteRequest):
    new_conf = rule_engine.demote_rule(rule_id, body.reason)
    if new_conf is None:
        return {"ok": False, "error": "rule not found"}
    return {"ok": True, "rule_id": rule_id, "new_confidence": new_conf}


@router.get("/incidents")
def incidents(limit: int = 25):
    return attack_chain.list_incidents(limit)


@router.get("/network-events")
def network_events(limit: int = 25):
    conn = storage.get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM events WHERE service='NETWORK' ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


@router.get("/status")
def status():
    rules_list = rule_engine.list_rules()
    active_rules = [r for r in rules_list if r["status"] == "active"]
    return {
        "active_rules": len(active_rules),
        "retired_rules": len(rules_list) - len(active_rules),
        "incidents": len(attack_chain.list_incidents(1000)),
    }
