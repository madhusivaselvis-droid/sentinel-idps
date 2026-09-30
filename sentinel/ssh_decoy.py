"""
ssh_decoy.py
Fake SSH service using Paramiko in server mode.
Never grants a real shell - a small set of "lure" credentials are allowed
to appear to succeed so the fake shell can capture attacker commands
(standard medium-interaction honeypot practice, e.g. Cowrie). All other
credentials are rejected. Soft containment (delay) is applied to auth
responses themselves, not just to a post-auth session that would
otherwise (as in the original version of this file) never be reached,
since AUTH_FAILED on every attempt meant no channel could ever open.
"""

import socket
import threading
import uuid
import time
import hashlib
import re
import paramiko

import personas
import scoring
import containment
import storage
import rule_engine
import attack_chain

HOST_KEY = paramiko.RSAKey.generate(2048)

_ip_session_id = {}
_ip_persona = {}

# Credentials allowed to "succeed" purely to open the fake shell and
# capture commands. Never grants anything real.
LURE_CREDENTIALS = {("admin", "admin"), ("root", "toor"), ("root", "123456"),
                     ("admin", "password"), ("test", "test123")}


def _get_session_and_persona(ip):
    if ip not in _ip_session_id:
        _ip_session_id[ip] = str(uuid.uuid4())
        _ip_persona[ip] = personas.assign_persona()
    return _ip_session_id[ip], _ip_persona[ip]


class DecoySSHServer(paramiko.ServerInterface):
    def __init__(self, ip, persona, session_id):
        self.ip = ip
        self.persona = persona
        self.session_id = session_id
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        state = scoring.get_or_create_session(self.session_id, self.ip)
        stage_before = state.containment_stage()

        # Soft containment applied to the auth response itself.
        delay = {0: 0, 1: 0.2, 2: 0.8, 3: 1.5, 4: 1.5}.get(stage_before, 0)
        if delay:
            time.sleep(delay)

        state.record_auth_attempt(username, password, success=False)
        pwd_hash = hashlib.sha256(password.encode("utf-8", "ignore")).hexdigest()
        storage.log_event(
            self.session_id, self.ip, "SSH", self.persona["name"],
            "auth_attempt",
            {"username": username, "password_hash": pwd_hash,
             "password_length": len(password)},
            intent_score=state.score, severity=state.severity_band(),
            containment_stage=state.containment_stage(),
        )
        storage.upsert_session(self.session_id, self.ip, self.persona["name"],
                                "SSH", state.score, state.containment_stage())

        if state.last_brute_force_username:
            last_event_id, _ = storage.log_event(
                self.session_id, self.ip, "SSH", self.persona["name"],
                "brute_force_confirmed",
                {"username": state.last_brute_force_username},
                intent_score=state.score, severity=state.severity_band(),
                containment_stage=state.containment_stage())
            rule_engine.generate_rule_from_event(
                last_event_id, re.escape(state.last_brute_force_username),
                category="credential_stuffing")
            state.last_brute_force_username = None

        attack_chain.evaluate_chain(self.ip)

        if (username, password) in LURE_CREDENTIALS:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True

    def get_allowed_auths(self, username):
        return "password"


def handle_connection(client_sock, addr):
    ip = addr[0]
    session_id, persona = _get_session_and_persona(ip)

    state = scoring.get_or_create_session(session_id, ip)
    state.record_port_scan()
    storage.log_event(session_id, ip, "SSH", persona["name"], "connection_open",
                       {"port": 2222}, intent_score=state.score,
                       severity=state.severity_band(),
                       containment_stage=state.containment_stage())

    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = persona["ssh_banner"]
        transport.add_server_key(HOST_KEY)
        server = DecoySSHServer(ip, persona, session_id)
        transport.start_server(server=server)

        chan = transport.accept(20)
        if chan is not None:
            server.event.wait(10)
            stage = state.containment_stage()
            storage.log_event(session_id, ip, "SSH", persona["name"],
                               "lure_login_granted",
                               {"note": "fake shell access granted to capture commands"},
                               intent_score=state.score, severity=state.severity_band(),
                               containment_stage=stage)
            chan.send(f"Welcome to {persona['page_title']}\r\n$ ")
            buf = b""
            while True:
                data = chan.recv(1024)
                if not data:
                    break
                buf += data
                if b"\r" in buf or b"\n" in buf:
                    command = buf.decode(errors="ignore").strip()
                    buf = b""
                    if command:
                        state.record_command(command)
                        stage = state.containment_stage()
                        active_persona = persona
                        if containment.should_redirect_to_rabbit_hole(stage):
                            active_persona = personas.get_rabbit_hole()
                        storage.log_event(
                            session_id, ip, "SSH", active_persona["name"],
                            "command", {"command": command},
                            intent_score=state.score, severity=state.severity_band(),
                            containment_stage=stage,
                        )
                        storage.upsert_session(session_id, ip, active_persona["name"],
                                                "SSH", state.score, stage)
                        if stage >= 4:
                            result = containment.apply_hard_block(ip)
                            storage.log_event(session_id, ip, "SSH", active_persona["name"],
                                               "hard_block", result,
                                               intent_score=state.score,
                                               severity="EXTREME", containment_stage=stage)
                            chan.send("\r\nConnection terminated.\r\n")
                            break
                        time.sleep(min(3.0, stage * 0.5))
                        chan.send(f"bash: {command.split()[0]}: command not found\r\n$ ")
        transport.close()
    except Exception:
        pass
    finally:
        try:
            client_sock.close()
        except Exception:
            pass


def run_ssh_decoy(bind_host="0.0.0.0", bind_port=2222):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host, bind_port))
    sock.listen(20)
    print(f"[SSH decoy] listening on {bind_host}:{bind_port}")
    while True:
        client_sock, addr = sock.accept()
        t = threading.Thread(target=handle_connection, args=(client_sock, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    storage.init_db()
    run_ssh_decoy()
