"""
recon_scan_sim.py
Opens raw TCP connections to the Sentinel trap ports (21, 23, 3306, 445,
6379) from the ATTACKER MACHINE/VM. Three or more distinct ports inside
the 20-second window are fused into ONE correlated network_scan_detected
event - this is the reconnaissance stage of the demo attack chain.

Usage:
    python recon_scan_sim.py <target_ip>

Example:
    python recon_scan_sim.py 127.0.0.1
"""

import socket
import sys
import time

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"

TRAP_PORTS = [21, 23, 3306, 445, 6379]

print(f"[recon_scan_sim] probing trap ports on {TARGET}: {TRAP_PORTS}")
for port in TRAP_PORTS:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        # connect_ex returns 0 on success instead of raising; the trap
        # listener accepts then closes immediately, which is all we need.
        result = sock.connect_ex((TARGET, port))
        if result == 0:
            print(f"  port {port:5d} -> connection accepted (trap hit)")
        else:
            print(f"  port {port:5d} -> no answer (oserror {result})")
    except Exception as e:
        print(f"  port {port:5d} -> error: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass
    time.sleep(0.4)

print("\nDone. 3+ distinct ports inside the 20s window should have fused into")
print("ONE 'network_scan_detected' event on the dashboard - not five alerts.")
