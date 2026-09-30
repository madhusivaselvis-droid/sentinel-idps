"""
protected_service.py
Represents a REAL protected asset on the network (not a decoy - a single,
consistent fingerprint, exactly what a real internal application looks
like). This is what the Deception-Fed Detection Loop actually protects:
rules learned from confirmed-malicious behavior at the honeypot
(rule_engine.py) are checked against every request here, so honeypot
threat intelligence becomes live protection for something real - the gap
named in the Sentinel design document.

Prevention reuses the SAME graduated containment model as the honeypot
(containment.py) - soft response first, hard block only as an audited
last resort - so a real user mistyping their password never gets treated
the same as a confirmed attacker replaying a honeypot-learned credential.
"""

import time
import uuid
from flask import Flask, request, Response

import scoring
import containment
import storage
import rule_engine
import attack_chain

app = Flask(__name__)

_ip_session = {}

SERVICE_NAME = "protected-internal-portal"


def _get_session(ip):
    if ip not in _ip_session:
        _ip_session[ip] = str(uuid.uuid4())
    return _ip_session[ip]


@app.before_request
def gatekeep():
    ip = request.remote_addr
    if containment.is_blocked(ip):
        return Response("Connection refused.", status=403)


def _check_sentinel_rules(session_id, ip, text):
    """Award points for anything matching a honeypot-learned rule."""
    state = scoring.get_or_create_session(session_id, ip)
    hits = rule_engine.match(text)
    for rule_id, category, points, reason in hits:
        state.record_rule_match(f"sentinel_rule_{rule_id}", points, reason)
        storage.log_event(session_id, ip, "PROTECTED", SERVICE_NAME,
                           "sentinel_rule_match",
                           {"rule_id": rule_id, "category": category, "reason": reason},
                           intent_score=state.score, severity=state.severity_band(),
                           containment_stage=state.containment_stage())
    return state


@app.route("/")
def home():
    ip = request.remote_addr
    session_id = _get_session(ip)
    state = _check_sentinel_rules(session_id, ip, "")
    stage = state.containment_stage()
    _apply_containment(ip, stage)
    storage.upsert_session(session_id, ip, SERVICE_NAME, "PROTECTED",
                            state.score, stage)
    return "<html><body><h1>Internal Staff Portal</h1><p>Please log in.</p></body></html>"


@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr
    session_id = _get_session(ip)
    payload = str(request.form.to_dict()) + " " + str(request.args.to_dict())
    state = _check_sentinel_rules(session_id, ip, payload)
    stage = state.containment_stage()
    _apply_containment(ip, stage)

    storage.log_event(session_id, ip, "PROTECTED", SERVICE_NAME, "login_attempt",
                       {"method": request.method}, intent_score=state.score,
                       severity=state.severity_band(), containment_stage=stage)
    storage.upsert_session(session_id, ip, SERVICE_NAME, "PROTECTED",
                            state.score, stage)

    attack_chain.evaluate_chain(ip)

    if stage >= 4:
        result = containment.apply_hard_block(ip)
        storage.log_event(session_id, ip, "PROTECTED", SERVICE_NAME, "hard_block",
                           result, intent_score=state.score, severity="EXTREME",
                           containment_stage=stage)
        return Response("Access temporarily suspended for this address.", status=403)

    return """<html><body><h1>Internal Staff Portal - Login</h1>
    <form method="POST">
    Username: <input name="username"><br>
    Password: <input name="password" type="password"><br>
    <input type="submit" value="Login">
    </form></body></html>"""


def _apply_containment(ip, stage):
    """Same graduated model as the honeypot - soft response before hard."""
    if stage >= 2 and not containment.allow_request(ip):
        time.sleep(0.5)
    delay_ms = {0: 0, 1: 150, 2: 700, 3: 1500, 4: 1500}.get(stage, 0)
    if delay_ms:
        time.sleep(delay_ms / 1000.0)


def run_protected_service(host="0.0.0.0", port=8000):
    app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":
    storage.init_db()
    rule_engine.init_sentinel_db()
    run_protected_service()
