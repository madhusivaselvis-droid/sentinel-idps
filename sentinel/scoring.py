"""
scoring.py
Transparent, explainable behavioral intent scoring.
No black-box ML - every point is traceable to a specific rule.
"""

import time
import re
import math

# Known-bad payload patterns (kept as ONE input feature among several)
BAD_PATTERNS = [
    r";\s*rm\s+-rf",
    r"UNION\s+SELECT",
    r"\.\./\.\./",
    r"<script.*?>",
    r"\bDROP\s+TABLE\b",
    r"\bexec\s*\(",
    r"\bwget\s+http",
]
BAD_PATTERN_RE = re.compile("|".join(BAD_PATTERNS), re.IGNORECASE)

# Points per triggering feature
POINTS = {
    "port_scan": 2,
    "failed_auth": 3,
    "bad_payload": 5,
    "brute_force_threshold": 10,
    "admin_endpoint": 8,
    "rapid_burst": 4,
    "deep_exploration": 3,
}

DECAY_HALF_LIFE_SECONDS = 300  # score halves every 5 minutes of inactivity


class SessionState:
    """Tracks running behavioral state for one attacker session."""

    def __init__(self, session_id, ip):
        self.session_id = session_id
        self.ip = ip
        self.score = 0.0
        self.last_update = time.time()
        self.auth_attempts = []
        self.commands_seen = set()
        self.paths_seen = set()
        self.event_log = []  # (feature_name, points, reason)
        # Set whenever a bad-payload/credential match fires, so callers
        # (the Sentinel rule engine) can turn the exact confirmed pattern
        # into a live detection rule. Cleared by the caller after reading.
        self.last_bad_pattern = None
        self.last_brute_force_username = None

    def _apply_decay(self):
        now = time.time()
        elapsed = now - self.last_update
        if elapsed > 0:
            decay_factor = 0.5 ** (elapsed / DECAY_HALF_LIFE_SECONDS)
            self.score *= decay_factor
        self.last_update = now

    def _add(self, feature, reason=""):
        pts = POINTS[feature]
        self.score += pts
        self.event_log.append((feature, pts, reason))
        return pts

    def record_port_scan(self):
        self._apply_decay()
        return self._add("port_scan", "connection probed without full handshake")

    def record_auth_attempt(self, username, password, success=False):
        self._apply_decay()
        self.auth_attempts.append((time.time(), username, password))
        pts_total = 0
        if not success:
            pts_total += self._add("failed_auth", f"failed login as '{username}'")
        # brute-force: 5+ attempts within 30 seconds
        recent = [a for a in self.auth_attempts if time.time() - a[0] < 30]
        if len(recent) >= 5:
            pts_total += self._add("brute_force_threshold",
                                    f"{len(recent)} attempts in 30s")
            # Surface the exact credential pattern so it can be promoted
            # into a Sentinel rule protecting the real protected service.
            self.last_brute_force_username = username
        return pts_total

    def record_http_request(self, path, payload=""):
        self._apply_decay()
        pts_total = 0
        self.paths_seen.add(path)
        matched_pattern = None
        for pat in BAD_PATTERNS:
            if re.search(pat, payload or "", re.IGNORECASE) or re.search(pat, path or "", re.IGNORECASE):
                matched_pattern = pat
                break
        if matched_pattern:
            pts_total += self._add("bad_payload", f"pattern match in '{path}'")
            self.last_bad_pattern = matched_pattern
        if any(admin in path.lower() for admin in ("/admin", "/login", "/management")):
            pts_total += self._add("admin_endpoint", f"accessed {path}")
        if len(self.paths_seen) >= 6:
            pts_total += self._add("deep_exploration",
                                    f"{len(self.paths_seen)} distinct paths explored")
        return pts_total

    def record_command(self, command):
        self._apply_decay()
        pts_total = 0
        self.commands_seen.add(command)
        if BAD_PATTERN_RE.search(command):
            pts_total += self._add("bad_payload", f"suspicious command: {command[:60]}")
        if len(self.commands_seen) >= 5:
            pts_total += self._add("deep_exploration",
                                    f"{len(self.commands_seen)} distinct commands")
        return pts_total

    def record_rapid_burst(self, requests_last_second):
        if requests_last_second >= 10:
            self._apply_decay()
            return self._add("rapid_burst", f"{requests_last_second} req/s")
        return 0

    def record_rule_match(self, rule_id, points, reason):
        """
        Generic hook used by the Sentinel signature engine (idps/) so that
        rules learned from honeypot evidence can contribute points through
        the SAME transparent scoring model - no second, parallel score.
        """
        self._apply_decay()
        self.score += points
        self.event_log.append((rule_id, points, reason))
        return points

    def severity_band(self):
        if self.score >= 70:
            return "EXTREME"
        elif self.score >= 45:
            return "CRITICAL"
        elif self.score >= 25:
            return "HIGH"
        elif self.score >= 10:
            return "MEDIUM"
        return "LOW"

    def containment_stage(self):
        band = self.severity_band()
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3, "EXTREME": 4}[band]

    def last_contributing_features(self, n=3):
        return self.event_log[-n:]


# In-memory registry of active sessions (keyed by session_id)
_sessions = {}


def get_or_create_session(session_id, ip) -> SessionState:
    if session_id not in _sessions:
        _sessions[session_id] = SessionState(session_id, ip)
    return _sessions[session_id]


def all_sessions():
    return _sessions
