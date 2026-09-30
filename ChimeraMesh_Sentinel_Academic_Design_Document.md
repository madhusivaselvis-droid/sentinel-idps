# ChimeraMesh Sentinel
## An Adaptive, Explainable, Deception-Calibrated Intrusion Detection & Prevention System

### Academic Project Report — Complete System Design, Architecture, and Evaluation

---

## Abstract

Intrusion Detection and Prevention Systems (IDPS) in both academic and
commercial deployments typically fall into one of two camps: signature-based
systems (e.g., Snort, Suricata) that are precise but blind to novel attacks,
or anomaly/ML-based systems that generalize better but are opaque and
difficult to audit. Independently, honeypots have long been used to observe
attacker behavior, but the threat intelligence they generate almost never
becomes a live, automated detection capability protecting a real asset —
honeypot and IDS are typically deployed as two disconnected tools.

**ChimeraMesh Sentinel** closes this gap. It extends a working honeynet
(ChimeraMesh) with a **Deception-Fed Detection Loop**: confirmed-malicious
behavior observed at the honeypot — where, by construction, every visitor is
unauthorized — is automatically converted into human-readable, traceable
detection rules that then protect a genuinely separate, real network asset.
Detection is fused across three layers (signature rules, transparent
behavioral scoring, and network-layer reconnaissance correlation) into a
single explainable score, which drives a five-stage graduated response
(Observe → Delay → Throttle → Rabbit-Hole Redirect → Temporary Block) rather
than a binary allow/drop decision. Every decision — a rule's creation, a
score change, a containment action — is traceable to an exact cause and
stored in a SHA-256 hash-chained, tamper-evident evidence log.

The complete system, including the deception-fed rule generation loop, the
network-layer scan correlator, the causal attack-chain correlator, and the
graduated response engine, was implemented and verified end-to-end: a SQL
injection payload sent to the honeypot generated a live rule that
subsequently caught the same attack pattern against an entirely separate
protected service; three isolated port probes were correctly fused into one
correlated scan event; and a full reconnaissance → credential-attack →
exploitation sequence was correctly recognized as a single high-confidence
incident rather than three disconnected alerts.

---

## 1. Introduction & Problem Statement

Modern networks are defended by point solutions that do not talk to each
other. A honeypot generates rich forensic detail about what a real attacker
actually does — but that intelligence typically stays inside the honeypot's
own logs. A signature-based IDS blocks known-bad patterns — but its rule set
is either hand-maintained or drawn from generic external threat-intel feeds
that know nothing about *this specific network's* actual attackers. An
anomaly-based system might catch something novel — but cannot explain why,
which makes it unauditable and difficult to trust in a security-operations
context.

This project asks: **what if the honeypot's ground truth was used to
automatically, transparently, and continuously calibrate the detection rules
protecting the rest of the network?**

---

## 2. Gap Analysis — What Existing Systems Get Wrong

This project is designed against five specific, named failure modes of
real-world IDS/IPS tooling, each mapped directly to a feature below.

| # | Gap in Existing Systems | How ChimeraMesh Sentinel Closes It |
|---|---|---|
| 1 | **Signature-only detection** (classic Snort/Suricata) misses novel or slow, low-and-slow attacks that don't match a known pattern. | Signature matching is only ONE of three fused inputs; transparent behavioral scoring (timing, diversity, exploration depth) catches what pattern-matching alone would miss. |
| 2 | **Black-box ML detection** is unexplainable, hard to audit, and vulnerable to adversarial evasion — operators can't say *why* something was flagged. | Zero black-box components anywhere. Every point in the score, every rule match, every containment decision is a plain-language, human-readable computation traceable to an exact rule or event ID. |
| 3 | **Detection, deception, and response are siloed products.** A honeypot observes real attacker TTPs, but that intelligence almost never automatically becomes a live detection rule protecting the actual network. | **This is the primary gap this project closes.** The Deception-Fed Detection Loop (Section 4.1) automatically promotes confirmed honeypot evidence into rules that protect a real, separate service — proven working end-to-end in Section 8. |
| 4 | **IPS response is binary** (allow/drop), easily triggering self-inflicted denial of service on false positives, with no graduated middle ground. | Five-stage graduated response (Section 4.4): Observe → Delay → Throttle → Rabbit-Hole Redirect → Temporary Block. A hard block is a last resort, simulate-mode by default, never the first reaction to a signal. |
| 5 | **Alert fatigue** — single-signal alerts with no cross-event correlation, so operators drown in low-context noise instead of seeing attack chains. | The Causal Attack-Chain Correlator (Section 4.3) fuses a recognized multi-stage shape (reconnaissance → credential attack → exploitation) from the same actor into ONE incident, citing every contributing event, instead of N disconnected alerts. |

**Honest scope note on novelty:** no individual technique here is invented
from scratch — signature matching, behavioral scoring, port-scan
correlation, and graduated response all exist in various forms in the
literature and in commercial tools. What is genuinely novel in this project
is the **specific, tightly integrated combination**: using a honeypot's
zero-false-positive ground truth as a *live, automatic, continuously
updating calibration source* for detection rules protecting a separate real
asset, with full traceability and an explicit operator feedback loop — a
combination not found packaged together in standard student-accessible
projects, and one that most production deployments still handle as
disconnected manual processes.

---

## 3. System Architecture

### 3.1 Component Inventory

| Component | Role | File |
|---|---|---|
| Persona Engine | Deceptive fingerprint pool for honeypot decoys | `personas.py` |
| Behavioral Scoring Engine | Transparent, explainable, additive intent scoring with decay | `scoring.py` |
| Graduated Containment Engine | Five-stage soft-to-hard response model | `containment.py` |
| Evidence Vault | SQLite + SHA-256 hash-chained tamper-evident log | `storage.py` |
| SSH Honeypot | Fake SSH service; lure credentials capture attacker commands | `ssh_decoy.py` |
| HTTP Honeypot | Fake HTTP service with decoy admin/login endpoints | `http_decoy.py` |
| **Sentinel Rule Engine** | **Deception-Fed rule generation, matching, decay, operator feedback** | `rule_engine.py` |
| **Sentinel Network Detector** | **Trap-port reconnaissance detection + scan correlation** | `network_detector.py` |
| **Sentinel Attack-Chain Correlator** | **Multi-stage attack shape recognition** | `attack_chain.py` |
| **Protected Service** | **The real asset that Sentinel-learned rules actually defend** | `protected_service.py` |
| Sentinel API | Dashboard extension: rules, incidents, network events | `sentinel_api.py` |
| Dashboard | Unified live operations view (one dashboard, not two) | `dashboard.py` + `static/index.html` |
| Integrity Verifier | Standalone tamper-detection tool | `verify_integrity.py` |
| Orchestrator | Starts every subsystem together | `main.py` |

Bold rows are the new Sentinel IDPS layer built on top of the existing
ChimeraMesh honeynet; all other components are the honeynet this system
extends, reused rather than duplicated.

### 3.2 Data Flow — the Deception-Fed Detection Loop

```
                    ┌────────────────────┐
                    │   ATTACKER TRAFFIC │
                    └──────────┬─────────┘
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
       ┌───────────────────┐       ┌───────────────────┐
       │  HONEYPOT DECOYS   │       │  NETWORK TRAP      │
       │  (SSH / HTTP)      │       │  PORTS             │
       │  every visitor is  │       │  (21/23/3306/445/  │
       │  unauthorized by   │       │  6379 - zero false │
       │  construction      │       │  positives)        │
       └──────────┬─────────┘       └──────────┬─────────┘
                  │                             │
                  ▼                             ▼
       ┌────────────────────────────────────────────────┐
       │      TRANSPARENT BEHAVIORAL SCORING ENGINE      │
       │   (additive, explainable, exponential decay)    │
       └──────────────────────┬───────────────────────────┘
                               │
                 confirmed-malicious pattern observed
                               │
                               ▼
                  ┌─────────────────────────┐
                  │   SENTINEL RULE ENGINE   │
                  │  generates rule R-NNN,   │
                  │  citing "learned from    │
                  │  evidence #N"            │
                  └────────────┬─────────────┘
                               │
                               ▼
                  ┌─────────────────────────┐
                  │   PROTECTED SERVICE      │◄──── legitimate user traffic
                  │   (the REAL asset)       │       (never touches honeypot)
                  │   checks every request   │
                  │   against the rule       │
                  │   library                │
                  └────────────┬─────────────┘
                               │
                 rule match OR behavioral score rise
                               │
                               ▼
                  ┌─────────────────────────┐
                  │  CAUSAL ATTACK-CHAIN     │
                  │  CORRELATOR              │
                  │  (fuses multi-stage      │
                  │  shapes into ONE         │
                  │  incident)               │
                  └────────────┬─────────────┘
                               │
                               ▼
                  ┌─────────────────────────┐
                  │  GRADUATED CONTAINMENT   │
                  │  Stage 0 Observe         │
                  │  Stage 1 Delay           │
                  │  Stage 2 Throttle        │
                  │  Stage 3 Rabbit-Hole     │
                  │  Stage 4 Temporary Block │
                  └────────────┬─────────────┘
                               │
                               ▼
                  ┌─────────────────────────┐
                  │  SHA-256 HASH-CHAINED    │
                  │  EVIDENCE VAULT          │
                  └────────────┬─────────────┘
                               │
                               ▼
                  ┌─────────────────────────┐
                  │  UNIFIED LIVE DASHBOARD  │
                  │  (rules, incidents,      │
                  │  sessions, integrity)    │
                  └─────────────────────────┘
```

---

## 4. Detailed Module Design

### 4.1 The Deception-Fed Detection Loop (Core Innovation)

**Mechanism.** When a honeypot decoy observes a payload matching a known-bad
pattern, or a credential-stuffing sequence crossing the brute-force
threshold, the exact matched pattern is surfaced (`scoring.py`'s
`last_bad_pattern` / `last_brute_force_username`) and passed to
`rule_engine.generate_rule_from_event()`. This creates a new rule record:

```
Rule R-NNN
  pattern:            <the exact regex or escaped credential string>
  category:           payload_injection | credential_stuffing
  source_event_id:    <the exact evidence-log row that generated it>
  confidence:         0.8 (initial)
  status:             active
```

Every subsequent request to `protected_service.py` — the real asset — is
checked against every active rule via `rule_engine.match()`. A match awards
points through the exact same `scoring.SessionState.record_rule_match()`
method the honeypot itself uses; there is no second, parallel scoring
system.

**Why this is defensible as the primary gap-closer:** a honeypot's value is
usually limited to forensic hindsight — "here's what an attacker did."
This loop turns that hindsight into live, automatic foresight for a
different, real target, with full traceability back to the originating
incident.

**Operator feedback loop.** If a rule proves to be a false positive, an
operator calls `POST /api/sentinel/rules/{id}/demote`, which reduces the
rule's confidence by a fixed, auditable amount (`rule_engine.demote_rule`,
confirmed to move confidence 0.8 → 0.5 in testing) rather than silently
retraining anything. A rule whose confidence drops below 0.1 is
automatically retired. Rules also decay passively at 5%/day if unused
(`rule_engine.decay_rules()`), so a rule from months ago cannot silently
outlive its relevance.

**Known limitation, stated honestly:** rules generated from very short or
common credential strings (e.g., a username of `"user"` or `"test"`) produce
broad regex patterns that risk false-positive matches against unrelated
traffic. This was observed directly during testing. A production version
should apply a minimum pattern length/specificity check before promoting a
credential string to a rule — this is flagged as a concrete follow-on
improvement, not hidden.

### 4.2 Network-Layer Reconnaissance Detection

Rather than raw packet capture (which needs elevated privileges and behaves
inconsistently across operating systems — see Section 7 for why this is
scoped out), `network_detector.py` binds plain TCP listeners on five ports
no legitimate ChimeraMesh service uses (21, 23, 3306, 445, 6379). This
reuses the honeypot's own core insight at the network layer: **any
connection to one of these ports is unambiguous reconnaissance** — there is
no legitimate reason for traffic to arrive there, giving the same
zero-false-positive ground truth the application-layer honeypot relies on.

**Correlation, not flooding:** rather than raising N separate low-value
alerts for N port hits, connections from the same source IP across three or
more distinct trap ports within a 20-second window are fused into a single
`network_scan_detected` event (verified in testing: three isolated hits on
ports 21/23/3306 correctly produced exactly one correlated event, not
three).

### 4.3 Causal Attack-Chain Correlation

`attack_chain.py` recognizes a specific, named multi-stage shape:

```
reconnaissance  →  credential_attack  →  exploitation
(scan/trap hit)    (auth attempts)       (bad payload / command / block)
```

within a 10-minute rolling window per source IP, reading directly from the
shared evidence log (no second event store). When all three stages are
present for one actor, ONE incident is raised, citing every contributing
event ID, and a combined confidence bonus (25 points) is awarded through the
same transparent scoring model. This directly targets alert fatigue (Gap
#5): an operator sees one incident with a full causal trail instead of
piecing together a dozen disconnected log lines.

**Verified in testing:** a simulated reconnaissance (3 trap ports) →
credential attack (6-attempt SSH brute force) → exploitation (SQL injection
payload) sequence was correctly fused into one incident citing 19
contributing event IDs, with the actor's score correctly elevated to HIGH
severity as a result of the correlation bonus alone.

### 4.4 Graduated, Explainable Prevention

Extending the original four-stage containment model, Sentinel completes it
into five explicit, reachable stages (the original design had an
unreachable "Stage 4" — this was found and fixed during development, see
Section 9):

| Stage | Score Band | Action |
|---|---|---|
| 0 — Observe | 0–9 (LOW) | Full logging, no interference |
| 1 — Delay | 10–24 (MEDIUM) | Artificial response latency |
| 2 — Throttle | 25–44 (HIGH) | Stronger delay + token-bucket rate limiting |
| 3 — Rabbit-Hole Redirect | 45–69 (CRITICAL) | Switch to a deeper, more heavily-instrumented decoy persona |
| 4 — Temporary Block | 70+ (EXTREME) | Simulate-mode hard block with TTL (verified reachable and firing correctly in testing) |

Every stage transition is driven by the exact same transparent score used
everywhere else in the system — there is no separate, opaque decision layer
for prevention versus detection.

### 4.5 Unified Dashboard

Rather than a second dashboard for the Sentinel layer, `sentinel_api.py`
extends the existing FastAPI app (`dashboard.py`) at `/api/sentinel/*`,
and the existing frontend (`static/index.html`) was extended — not
replaced — with: the live rule library (with an inline "Mark FP" button
driving the demote endpoint), correlated attack-chain incidents, and
network reconnaissance events, alongside the original session table,
score chart, and integrity indicator.

---

## 5. Core Algorithms

### 5.1 Transparent Behavioral Scoring (unchanged core principle, extended)

```
score = Σ (feature_points × exp_decay(time_since_last_update))

Features (all explainable, no learned weights):
  port_scan               +2
  failed_auth              +3
  bad_payload              +5
  brute_force_threshold   +10
  admin_endpoint           +8
  rapid_burst              +4
  deep_exploration         +3
  network_scan_correlated +15   (Sentinel)
  sentinel_rule_match     up to +12, scaled by rule confidence  (Sentinel)
  attack_chain_confirmed  +25   (Sentinel)

decay_factor = 0.5 ^ (elapsed_seconds / 300)   # half-life 5 minutes
```

### 5.2 Deception-Fed Rule Generation (pseudocode)

```
on honeypot_event(payload_or_credential):
    if matches_bad_pattern(payload_or_credential):
        matched_pattern = extract_exact_pattern(payload_or_credential)
        event_id = evidence_log.append(event)
        if not rule_library.has_active_rule(matched_pattern):
            rule = Rule(
                pattern = matched_pattern,
                source_event_id = event_id,
                confidence = 0.8,
                status = "active"
            )
            rule_library.add(rule)
            evidence_log.append("rule_generated", cites=event_id)

on protected_service_request(payload):
    for rule in rule_library.active_rules():
        if rule.pattern matches payload:
            points = 12 * rule.confidence
            score += points   # via the SAME scoring engine
            evidence_log.append("sentinel_rule_match", cites=rule.id)
```

### 5.3 Attack-Chain Correlation (pseudocode)

```
on any_event(ip):
    if time_since(last_chain_incident[ip]) < 600s:
        return  # don't re-raise for the same actor too often

    events = evidence_log.query(ip=ip, since=now - 600s)
    stages_present = {
        "reconnaissance":     any(e.type in {scan-like types} for e in events),
        "credential_attack":  any(e.type in {auth-like types} for e in events),
        "exploitation":       any(e.type in {payload/command/block types} for e in events),
    }
    if all(stages_present.values()):
        incident = combine(events matching any stage)
        score += 25   # via the SAME scoring engine
        evidence_log.append("attack_chain_incident", cites=incident.event_ids)
        last_chain_incident[ip] = now
```

---

## 6. Forensic Evidence Integrity

Unchanged from the base ChimeraMesh design and still fully functional with
the Sentinel layer added on top: every event — honeypot, network,
protected-service, or Sentinel-internal (rule generation, demotion,
incidents) — is appended to one shared SHA-256 hash chain
(`storage.py`). `verify_integrity.py` walks the chain and reports the exact
first broken record if any row has been altered. This was re-verified after
adding the Sentinel layer: all new event types (`rule_generated`,
`sentinel_rule_match`, `network_scan_detected`, `attack_chain_incident`,
`hard_block`) participate in the same chain as the original honeypot events,
so tampering with a Sentinel-era record is caught exactly the same way as
tampering with a honeypot-era one.

---

## 7. Threat Model & Explicit Scope

### In Scope
- Lab-only, host-only or fully isolated internal network.
- Application-layer honeypots (SSH, HTTP) plus network-layer trap-port
  reconnaissance detection.
- Deception-fed rule generation protecting a genuinely separate real
  service.
- Multi-stage attack-chain correlation within a single actor's event
  history.
- Five-stage graduated, explainable, fully auditable response.
- Tamper-evident evidence logging with a live-demonstrable integrity
  check.

### Deliberately Out of Scope (stated explicitly, per the project's own
constraint against inflating claims)

- **Raw packet/flow-level detection** (SYN flood shape, TCP flag anomalies,
  ARP spoofing, DNS-exfiltration entropy patterns). This would require
  `scapy` or raw sockets with elevated privileges, and behaves
  inconsistently across host operating systems — the exact kind of
  demo-day fragility this project's design philosophy avoids elsewhere
  (see the original ChimeraMesh plan's treatment of `tc` traffic shaping).
  **Fallback implemented instead:** the trap-port approach in Section 4.2,
  which needs no elevated privileges and was fully tested.
- **Full high-interaction honeypots** (real shells, real binaries) — the
  SSH decoy's fake shell is intentionally limited to capturing commands,
  never executing them.
- **Black-box ML anywhere.** This is a hard constraint, not a style
  preference — every scoring and detection decision must be traceable to
  an explicit, human-readable rule or formula.
- **Perfect actor identification.** Sessions are identified by source IP
  (plus service), so two distinct attackers behind the same NAT gateway
  could appear as one actor. This is a real, named limitation, not solved
  by this project's scope.
- **Rule specificity guarantees.** As noted in Section 4.1, short
  credential-derived rule patterns can be overly broad; this is a known,
  documented weakness rather than a claimed strength.

---

## 8. Verification — What Was Actually Proven, Not Just Described

Every capability claimed in this document was demonstrated with a real,
runnable test during development, not merely described:

| Capability | Test Performed | Result |
|---|---|---|
| Deception-fed rule generation | SQLi payload sent to honeypot `/admin` | Rule R-001 generated, citing evidence event #2 |
| Rule protects a REAL separate service | Equivalent SQLi payload sent to `protected_service.py` on a different port | Rule matched, citing "learned from evidence #2" in the log |
| Network scan correlation | 3 connections to distinct trap ports (21/23/3306) within the window | Exactly ONE `network_scan_detected` event raised, not three |
| Causal attack-chain fusion | Recon (3 trap ports) → brute force (6 SSH attempts) → SQLi payload | ONE `attack_chain_incident` raised, citing 19 contributing event IDs |
| Stage 4 (previously unreachable) now fires | Repeated escalating payloads pushed score to 75 | Containment stage 4, `hard_block` event logged, simulate-mode TTL 900s |
| Operator false-positive feedback | `POST /rules/1/demote` | Confidence visibly dropped 0.8 → 0.5, logged to evidence chain |
| Evidence chain integrity | Manual database row edit, then re-verify | Verifier correctly identified the exact altered record |

---

## 9. Defects Found and Fixed During Development (Documented for Transparency)

A prior review of the base honeynet surfaced several real defects, all
confirmed against the actual code (not assumed) and fixed as part of this
project:

1. **Stage 4 was unreachable** — the scoring model only ever produced
   stages 0–3, but the containment code checked for stage ≥4. Fixed by
   introducing the EXTREME severity band.
2. **SSH command capture was entirely dead code** — `check_auth_password`
   always returned `AUTH_FAILED`, so no client could ever open a channel,
   meaning the command-logging code could never execute. Fixed with a
   small set of "lure" credentials that are allowed to succeed purely to
   open the fake shell (standard medium-interaction honeypot practice).
3. **`/files` endpoint bypassed soft containment** while every other route
   applied it. Fixed by centralizing all routes through one standardized
   `process_request()` pipeline.
4. **Plaintext credential storage.** Fixed by hashing captured passwords
   (SHA-256 + length) while retaining usernames and behavioral value.
5. **Wide-open CORS (`allow_origins=["*"]`)** on a security-monitoring API,
   despite the frontend never actually needing cross-origin access. Removed
   entirely.
6. **External CDN dependency** (Chart.js) risked failing on an offline lab
   VM. Replaced with a vendored, dependency-free canvas chart.
7. **A defect in the new Sentinel code itself**, found during this
   project's own testing: the attack-chain correlator's stage-matching
   used exact event-type equality, which silently failed to recognize
   event types like `bad_payload_confirmed` (only `bad_payload` was
   listed). Fixed to use substring matching, then re-verified with a full
   end-to-end multi-stage test.

This list is included deliberately: a system that only ever reports success
is less credible than one that shows its own debugging process.

---

## 10. Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| Honeypot services | Paramiko (SSH), Flask (HTTP) |
| Protected (real) service | Flask |
| Network detection | Plain TCP sockets (no root, no scapy) |
| API / Dashboard backend | FastAPI, Pydantic |
| Storage | SQLite |
| Integrity | `hashlib` (SHA-256) |
| Dashboard frontend | Vanilla HTML/CSS/JS, dependency-free canvas chart (no CDN) |
| Attack simulation | Custom Python scripts (`attack_scripts/`) |
| Environment | Linux (Ubuntu recommended), isolated/host-only lab network |

---

## 11. Day-Wise Build Plan with Milestones

Following the same risk-managed philosophy as the base ChimeraMesh plan: a
safe, fully-working core first, higher-risk items explicitly flagged as
stretch goals.

| Day | Milestone | Core / Stretch |
|---|---|---|
| 1 | Base honeynet running (decoys, scoring, containment, evidence log) — reuse from prior work | Core |
| 2 | `rule_engine.py`: rule table, generation, matching, decay, demotion — unit-tested standalone | Core |
| 3 | Hook rule generation into `http_decoy.py` and `ssh_decoy.py`; verify a honeypot event actually creates a rule | Core |
| 4 | `protected_service.py`: real asset stood up, wired to `rule_engine.match()` and the shared containment model | Core |
| 5 | **End-to-end deception-fed loop test**: honeypot payload → rule → protected-service catch, verified via the evidence log | Core |
| 6 | `network_detector.py`: trap ports + correlation window; verify 3 isolated hits become 1 correlated event | Core |
| 7 | `attack_chain.py`: multi-stage shape recognition; verify a full recon→credential→exploitation sequence fuses into one incident | Core |
| 8 | `sentinel_api.py` + dashboard extension (rule library, incidents, network events, demote button) | Core |
| 9 | Fix defects found during integration testing (the 7 items in Section 9); re-run every test | Core |
| 10 | Full rehearsal of the complete demo script (Section 12); prepare a backup recording | Core |

**Explicitly flagged stretch goals (not attempted in the core build, per
Section 7):** raw packet/flow-level detection via `scapy`; rule
auto-specificity scoring to address the short-credential rule weakness;
persistent cross-session actor fingerprinting beyond IP+service.

---

## 12. Demo Script

1. Start the full system: `python3 main.py`. Show the dashboard idle —
   zero rules, zero incidents, integrity intact.
2. **Reconnaissance:** connect to three trap ports from the attacker
   machine. Dashboard shows one correlated `network_scan_detected` event,
   not three.
3. **Credential attack:** run `ssh_bruteforce_sim.py` against the honeypot.
   Show the score climbing live and the SSH decoy's own containment
   delaying responses as severity rises.
4. **Exploitation:** send a SQL-injection payload to the honeypot's
   `/admin` endpoint. Show the new rule appearing in the dashboard's rule
   library, citing the exact evidence event it was learned from.
5. **The centerpiece moment:** send the *same kind* of payload to the real
   protected service on its own port. Show the dashboard logging a
   `sentinel_rule_match` event citing that same rule and evidence ID —
   proving the honeypot's intelligence just protected something it never
   directly observed an attack against.
6. **Correlation:** point out the `attack_chain_incident` that was raised
   automatically once all three stages were seen from one source, citing
   every contributing event ID.
7. **Operator feedback:** demote a rule from the dashboard, show its
   confidence visibly drop.
8. **Escalation to hard block:** continue sending payloads until the score
   crosses into EXTREME; show Stage 4 firing (simulate-mode block, TTL
   visible in the log).
9. **Integrity:** manually edit a database row, re-run
   `verify_integrity.py` live, show it pinpoint the exact tampered record.

---

## 13. Conclusion

ChimeraMesh Sentinel demonstrates that a honeypot's forensic value does not
have to end at hindsight. By treating confirmed honeypot evidence as a live,
continuously-updating, fully-auditable source of detection rules for a
genuinely separate protected asset, and by fusing that with transparent
behavioral scoring, network-layer reconnaissance correlation, and
causal multi-stage attack-chain recognition — all resolved through one
explainable score and one graduated five-stage response — this project
closes a specific, named gap between deception technology and live network
defense that most real-world deployments still handle as disconnected
manual processes. Every capability claimed here was verified with an actual
running test, including the defects found and fixed along the way, in the
interest of presenting a system that has been proven rather than merely
described.
