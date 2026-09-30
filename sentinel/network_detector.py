"""
network_detector.py
Network-layer reconnaissance detection via trap ports - no raw sockets,
no root privileges required, so this cannot be derailed by permission
issues on demo day (same risk philosophy as containment.py's soft-first
design).

Approach: bind bare TCP listeners on several ports that no real ChimeraMesh
service uses (21, 23, 3306, 445, 6379 by default). Exactly like the honeypot
decoys, ANY connection to one of these is unambiguous reconnaissance - there
is no legitimate reason for traffic to arrive here. This gives the same
"zero false positive by construction" ground truth the honeypot uses,
extended to the network layer.

Correlation: rather than treating each port hit as an isolated low-value
signal (the classic alert-fatigue problem), connections from the same
source IP across MULTIPLE distinct trap ports within a short time window
are correlated into a single higher-confidence "network_scan_detected"
event.

Stretch / explicitly out of scope here: full packet-level detection (SYN
flood shape, TCP flag anomalies, ARP spoofing, DNS exfiltration patterns)
would need raw sockets or scapy with elevated privileges and behaves
differently across OSes - flagged as a stretch goal with this trap-port
approach as the safe fallback that ships in the core system.
"""

import socket
import threading
import time
import uuid

import scoring
import storage
import attack_chain

TRAP_PORTS = [21, 23, 3306, 445, 6379]
CORRELATION_WINDOW_SECONDS = 20
CORRELATION_THRESHOLD_PORTS = 3

# ip -> list of (timestamp, port)
_hits = {}
_correlated_recently = {}  # ip -> last correlation timestamp
_lock = threading.Lock()


# ip -> persistent session id, so recon traffic from one actor fuses into
# the same behavioral session as their later honeypot / protected-service
# activity (matches how ssh_decoy and http_decoy key sessions).
_actor_sessions = {}


def _session_for_ip(ip):
    if ip not in _actor_sessions:
        _actor_sessions[ip] = f"netscan-{ip}"
    return _actor_sessions[ip]


def _record_hit(ip, port):
    with _lock:
        now = time.time()
        _hits.setdefault(ip, []).append((now, port))
        # prune old hits outside the window
        _hits[ip] = [(t, p) for (t, p) in _hits[ip] if now - t <= CORRELATION_WINDOW_SECONDS]
        distinct_ports = {p for (_, p) in _hits[ip]}

        session_id = _session_for_ip(ip)
        state = scoring.get_or_create_session(session_id, ip)

        storage.log_event(session_id, ip, "NETWORK", "trap-port", "trap_hit",
                           {"port": port}, intent_score=state.score,
                           severity=state.severity_band(),
                           containment_stage=state.containment_stage())

        if len(distinct_ports) >= CORRELATION_THRESHOLD_PORTS:
            last_corr = _correlated_recently.get(ip, 0)
            if now - last_corr > CORRELATION_WINDOW_SECONDS:
                _correlated_recently[ip] = now
                pts = state.record_rule_match(
                    "network_scan_correlated", 15,
                    f"{len(distinct_ports)} distinct trap ports hit in "
                    f"{CORRELATION_WINDOW_SECONDS}s: {sorted(distinct_ports)}"
                )
                storage.log_event(
                    session_id, ip, "NETWORK", "trap-port", "network_scan_detected",
                    {"distinct_ports": sorted(distinct_ports), "points": pts},
                    intent_score=state.score, severity=state.severity_band(),
                    containment_stage=state.containment_stage(),
                )
                storage.upsert_session(session_id, ip, "trap-port", "NETWORK",
                                        state.score, state.containment_stage())
                # Feed the causal attack-chain correlator - a network scan
                # is often stage one of a multi-stage attack.
                attack_chain.evaluate_chain(ip)


def _trap_listener(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except PermissionError:
        print(f"[Sentinel network_detector] port {port} needs elevated "
              f"privileges on this OS - skipping (non-fatal, core system "
              f"still runs on the remaining trap ports)")
        return
    except OSError as e:
        print(f"[Sentinel network_detector] could not bind port {port}: {e}")
        return
    sock.listen(20)
    print(f"[Sentinel network_detector] trap listening on 0.0.0.0:{port}")
    while True:
        try:
            client_sock, addr = sock.accept()
            ip = addr[0]
            client_sock.close()
            _record_hit(ip, port)
        except Exception:
            continue


def run_network_detector(ports=None):
    """Start one trap listener thread per configured port."""
    ports = ports or TRAP_PORTS
    for port in ports:
        t = threading.Thread(target=_trap_listener, args=(port,), daemon=True)
        t.start()
