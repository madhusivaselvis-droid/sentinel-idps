"""
http_decoy.py
Fake HTTP service (Flask) with decoy admin/login endpoints.
Every route funnels through one standardized pipeline (process_request)
so containment, scoring, and logging can never be applied inconsistently
between routes (the original /files endpoint skipped soft containment -
fixed by centralizing the flow here).
"""

import time
import uuid
import hashlib
from flask import Flask, request, Response

import personas
import scoring
import containment
import storage
import rule_engine
import attack_chain

app = Flask(__name__)

_ip_persona = {}
_ip_session = {}


def _get_session_and_persona(ip):
    if ip not in _ip_session:
        _ip_session[ip] = str(uuid.uuid4())
        _ip_persona[ip] = personas.assign_persona()
    return _ip_session[ip], _ip_persona[ip]


def process_request(path, method, form_dict=None, args_dict=None):
    ip = request.remote_addr
    session_id, persona = _get_session_and_persona(ip)
    state = scoring.get_or_create_session(session_id, ip)

    payload = str(form_dict or {}) + " " + str(args_dict or {})
    state.record_http_request(path, payload)
    stage = state.containment_stage()

    _apply_soft_containment(ip, stage)

    active_persona = _maybe_redirect(persona, stage)

    detail = {"path": path, "method": method}
    if form_dict:
        safe_form = dict(form_dict)
        if "password" in safe_form:
            pwd = safe_form.pop("password")
            safe_form["password_hash"] = hashlib.sha256(pwd.encode("utf-8", "ignore")).hexdigest()
            safe_form["password_length"] = len(pwd)
        detail["form"] = safe_form
    if args_dict:
        detail["params"] = args_dict

    storage.log_event(session_id, ip, "HTTP", active_persona["name"], "request",
                       detail, intent_score=state.score,
                       severity=state.severity_band(), containment_stage=stage)
    storage.upsert_session(session_id, ip, active_persona["name"], "HTTP",
                            state.score, stage)

    # Deception-Fed Detection Loop: a confirmed-malicious payload pattern
    # observed here (the honeypot - where every visitor is by definition
    # unauthorized) becomes a live rule protecting the REAL protected
    # service, citing this exact event as its origin.
    if state.last_bad_pattern:
        last_event_id, _ = storage.log_event(
            session_id, ip, "HTTP", active_persona["name"], "bad_payload_confirmed",
            {"pattern": state.last_bad_pattern}, intent_score=state.score,
            severity=state.severity_band(), containment_stage=stage)
        rule_engine.generate_rule_from_event(last_event_id, state.last_bad_pattern,
                                              category="payload_injection")
        state.last_bad_pattern = None

    attack_chain.evaluate_chain(ip)

    if stage >= 4:
        result = containment.apply_hard_block(ip)
        storage.log_event(session_id, ip, "HTTP", active_persona["name"],
                           "hard_block", result, intent_score=state.score,
                           severity="EXTREME", containment_stage=stage)

    return active_persona, state, stage


@app.before_request
def gatekeep():
    ip = request.remote_addr
    if containment.is_blocked(ip):
        return Response("Connection refused.", status=403)


@app.route("/", methods=["GET"])
def home():
    active_persona, state, stage = process_request("/", "GET")
    return f"""<html><head><title>{active_persona['page_title']}</title></head>
    <body><h1>{active_persona['page_title']}</h1>
    <p>Welcome. Please <a href="/login">login</a>.</p></body></html>"""


@app.route("/admin", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
@app.route("/management", methods=["GET", "POST"])
def admin_panel():
    form = request.form.to_dict() if request.method == "POST" else None
    args = request.args.to_dict()
    active_persona, state, stage = process_request(request.path, request.method,
                                                     form_dict=form, args_dict=args)
    return f"""<html><head><title>{active_persona['page_title']} - Login</title></head>
    <body><h1>{active_persona['page_title']} - Admin Login</h1>
    <form method="POST">
    Username: <input name="username"><br>
    Password: <input name="password" type="password"><br>
    <input type="submit" value="Login">
    </form>
    <p>Access denied.</p></body></html>"""


@app.route("/files")
def files():
    active_persona, state, stage = process_request("/files", "GET")
    listing = "<br>".join(active_persona["fake_files"])
    return f"<html><body><h2>Index of /files</h2>{listing}</body></html>"


def _apply_soft_containment(ip, stage):
    if stage >= 2:
        if not containment.allow_request(ip):
            time.sleep(0.5)
    delay_ms = {0: 0, 1: 150, 2: 700, 3: 2000, 4: 2000}.get(stage, 0)
    if delay_ms:
        time.sleep(delay_ms / 1000.0)


def _maybe_redirect(persona, stage):
    if containment.should_redirect_to_rabbit_hole(stage):
        return personas.get_rabbit_hole()
    return persona


def run_http_decoy(host="0.0.0.0", port=8080):
    app.run(host=host, port=port, threaded=True)


if __name__ == "__main__":
    storage.init_db()
    run_http_decoy()
