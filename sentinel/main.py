"""
main.py
Orchestrator: starts the honeypot decoys (SSH + HTTP), the Sentinel
network-layer trap detectors, the real protected service, and the
unified dashboard together. Run this single file to bring up the
whole system - core honeynet + Sentinel IDPS layer.
"""

import threading
import time

import storage
import rule_engine
import ssh_decoy
import http_decoy
import protected_service
import network_detector


def start_dashboard():
    import uvicorn
    import dashboard as dash_module
    uvicorn.run(dash_module.app, host="0.0.0.0", port=9000, log_level="warning")


def rule_decay_loop():
    while True:
        time.sleep(3600)
        rule_engine.decay_rules()


def main():
    storage.init_db()
    rule_engine.init_sentinel_db()

    threading.Thread(target=ssh_decoy.run_ssh_decoy, args=("0.0.0.0", 2222), daemon=True).start()
    threading.Thread(target=http_decoy.run_http_decoy, args=("0.0.0.0", 8080), daemon=True).start()
    threading.Thread(target=protected_service.run_protected_service, args=("0.0.0.0", 8000), daemon=True).start()
    threading.Thread(target=network_detector.run_network_detector, daemon=True).start()
    threading.Thread(target=rule_decay_loop, daemon=True).start()
    threading.Thread(target=start_dashboard, daemon=True).start()

    print("=" * 68)
    print(" ChimeraMesh + Sentinel IDPS is running")
    print("  SSH decoy (honeypot)      : localhost:2222")
    print("  HTTP decoy (honeypot)     : http://localhost:8080")
    print("  Protected service (real)  : http://localhost:8000")
    print("  Network trap ports        :", network_detector.TRAP_PORTS)
    print("  Dashboard                 : http://localhost:9000")
    print("=" * 68)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()
