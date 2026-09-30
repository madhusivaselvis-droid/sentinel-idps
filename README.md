# ChimeraMesh Sentinel

An adaptive, explainable, **deception-calibrated** Intrusion Detection & Prevention
System. A working honeynet (SSH + HTTP decoys) feeds confirmed attacker behavior —
where every visitor is unauthorized by construction — into a live rule engine that
protects a genuinely separate, real service. Detection is fused across three
transparent layers and resolved through a five-stage graduated response, with every
decision recorded in a SHA-256 hash-chained, tamper-evident evidence vault.

> Full academic design document: [ChimeraMesh_Sentinel_Academic_Design_Document.md](ChimeraMesh_Sentinel_Academic_Design_Document.md)

## What closes the gap

| Gap in typical IDPS | Sentinel's answer |
|---|---|
| Signature-only detection misses novel attacks | Signature matching is one of three fused inputs |
| Black-box ML is unauditable | Zero black-box components — every point is a named feature with a fixed weight |
| Honeypot intel never leaves the honeypot | **Deception-Fed Detection Loop**: honeypot evidence auto-generates rules that defend the real asset |
| Binary allow/drop response | Five stages: Observe → Delay → Throttle → Rabbit-Hole → Temporary Block |
| Alert fatigue | Causal attack-chain correlator fuses recon → credential → exploitation into ONE incident |

## Quick start

```bash
cd sentinel
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Then open the dashboard: **http://localhost:9000**

| Service | Location |
|---|---|
| Unified dashboard | http://localhost:9000 |
| SSH honeypot decoy | `localhost:2222` |
| HTTP honeypot decoy | http://localhost:8080 |
| Protected (real) service | http://localhost:8000 |
| Network trap ports | 21 · 23 · 3306 · 445 · 6379 |

## Demo script (the 60-second tour)

From another terminal (with the venv active):

```bash
cd sentinel

# 1. Reconnaissance — 3+ trap ports inside 20s fuse into ONE correlated event
python attack_scripts/recon_scan_sim.py 127.0.0.1

# 2. Credential attack — score climbs live, containment delays SSH responses
python attack_scripts/ssh_bruteforce_sim.py 127.0.0.1

# 3. Exploitation — honeypot observes SQLi and AUTO-GENERATES a rule
python attack_scripts/http_sqli_sim.py 127.0.0.1 8080 /admin

# 4. The centerpiece — same payload hits the REAL protected service;
#    the honeypot-learned rule catches it there (sentinel_rule_match)
python attack_scripts/http_sqli_sim.py 127.0.0.1 8000 /login
```

Watch the dashboard: rule `R-001` appears citing its exact evidence event, the
attack-chain incident fires citing every contributing event ID, and the
containment ladder escalates to Stage 4 as the score crosses 70.

## Integrity verification

Every event — honeypot, network, protected-service, and Sentinel-internal — joins
one SHA-256 hash chain. Tamper with a row and the verifier pinpoints the record:

```bash
cd sentinel
python verify_integrity.py     # "OK - all N events verified."
# (optionally edit any row in chimeramesh.db, then re-run to see the violation report)
```

## Architecture

```
attacker traffic ─┬─ SSH/HTTP decoys (zero-legit-traffic ground truth)
                  └─ network trap ports (zero-false-positive recon signal)
                         ↓
        transparent behavioral scoring (additive, exp decay)
                         ↓  confirmed-malicious pattern
        Sentinel rule engine (rule R-NNN citing evidence #N)
                         ↓
        protected service (real asset, checks every request)
                         ↓
        causal attack-chain correlator (one incident, full trail)
                         ↓
        graduated containment (stage 0–4, one explainable score)
                         ↓
        SHA-256 hash-chained evidence vault → unified dashboard
```

### Component map

| Component | Role | File |
|---|---|---|
| Persona Engine | Decoy fingerprint pool | [personas.py](sentinel/personas.py) |
| Behavioral Scoring | Explainable additive intent score | [scoring.py](sentinel/scoring.py) |
| Graduated Containment | Five-stage soft-to-hard response | [containment.py](sentinel/containment.py) |
| Evidence Vault | SQLite + SHA-256 hash chain | [storage.py](sentinel/storage.py) |
| SSH Honeypot | Lure credentials + fake shell capture | [ssh_decoy.py](sentinel/ssh_decoy.py) |
| HTTP Honeypot | Decoy admin/login endpoints | [http_decoy.py](sentinel/http_decoy.py) |
| **Sentinel Rule Engine** | Deception-fed rule generation/matching/decay | [rule_engine.py](sentinel/rule_engine.py) |
| **Network Detector** | Trap ports + scan correlation | [network_detector.py](sentinel/network_detector.py) |
| **Attack-Chain Correlator** | Multi-stage shape recognition | [attack_chain.py](sentinel/attack_chain.py) |
| **Protected Service** | The real asset the rules defend | [protected_service.py](sentinel/protected_service.py) |
| Sentinel API | Dashboard extension at `/api/sentinel/*` | [sentinel_api.py](sentinel/sentinel_api.py) |
| Dashboard Backend | FastAPI + static frontend | [dashboard.py](sentinel/dashboard.py) |
| Integrity Verifier | Standalone tamper detection | [verify_integrity.py](sentinel/verify_integrity.py) |
| Orchestrator | Starts everything | [main.py](sentinel/main.py) |

### Scoring model (fully transparent)

```
score = Σ (feature_points × 0.5^(seconds_since_update / 300))

port_scan +2 · failed_auth +3 · bad_payload +5 · brute_force_threshold +10
admin_endpoint +8 · rapid_burst +4 · deep_exploration +3
network_scan_correlated +15 · sentinel_rule_match ≤ +12 (× rule confidence)
attack_chain_confirmed +25
```

Severity bands: LOW <10 · MEDIUM ≥10 · HIGH ≥25 · CRITICAL ≥45 · EXTREME ≥70
(map 1:1 onto containment stages 0–4).

## Honest limitations

- Rules from short credential strings can be overly broad (minimum-length
  specificity screening is a stated follow-on improvement).
- Actor identity is IP+service based; two attackers behind one NAT appear as one.
- No raw packet-level detection (deliberate scope choice — trap ports give the
  same zero-false-positive signal without root privileges).
- Lab-only by design; hard blocks are simulate-mode by default.

## Deploy it live

**One-click (Render):** push/Fork this repo, then go to
[dashboard.render.com](https://dashboard.render.com) → **New → Web Service** →
connect your GitHub → pick this repo. Render reads [`render.yaml`](render.yaml):
Python 3.13, installs deps, runs `python main.py`, health-checks `/api/summary`,
and publishes the dashboard on its assigned `PORT`. You get a public URL like
`https://chimeramesh-sentinel.onrender.com`.

- Free instances **sleep after 15 min idle**; the first request wakes them (~30s).
- On Render's shared host the **privileged trap ports (21/23) may not bind** —
  the detector skips them gracefully and stays on 3306/445/6379 (still 3 ports,
  scan correlation still fires). The dashboard, decoys, and protected service
  are unaffected.
- Only the dashboard port is public; decoy ports stay internal to the box —
  point the simulators at `127.0.0.1` from the Render **Shell** tab, or expose
  more ports on a paid plan.

Also works as-is on **Railway** (`railway up`) and **Fly.io** (`fly launch`).

## Deployment notes

### GitHub

```bash
git init
git add -A
git commit -m "ChimeraMesh Sentinel: deception-fed IDPS with unified SOC dashboard"
git remote add origin https://github.com/<your-username>/sentinel-idps.git
git push -u origin main
```

### Backend (the real system)

This app needs **long-running Python processes and raw TCP listeners** (trap ports
21/23/6379, SSH :2222, HTTP decoy :8080, protected service :8000, dashboard :9000).
Deploy it to one of:

| Target | Notes |
|---|---|
| **Railway / Render** | Simplest: `pip install -r sentinel/requirements.txt` + `python sentinel/main.py`; bind all ports on 0.0.0.0. Free tiers sleep, which breaks the always-on decoys — use a paid instance for realistic honeypot behavior. |
| **Fly.io** | Good fit (TCP services exposed per-port via `fly.toml`), one VM running `main.py`. |
| **VPS (Ubuntu)** | The reference environment: run under `systemd`, keep it on an isolated/host-only network as designed. |

> **Netlify cannot host this backend** — it serves static sites and serverless
> JavaScript only; there are no long-running Python processes or TCP listeners.
> It could host only a static showcase page or the data-less dashboard shell.

### Scope reminder

This is a **lab/teaching system**. If you deploy the decoys anywhere, keep them
on an isolated network — a honeypot's job is to be attacked.

## Scope & safety

This is a **lab/teaching system** for isolated, host-only networks. The decoys
never execute attacker commands, captured passwords are hashed on arrival, and
the hard block is simulated unless you deliberately wire in real enforcement.
