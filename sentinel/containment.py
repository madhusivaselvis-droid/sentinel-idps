"""
containment.py
Progressive soft containment: delay -> throttle -> redirect -> (optional) hard block.
Core implementation uses asyncio sleep + a token-bucket rate limiter -
deliberately avoids depending on live iptables/tc so the demo can't be
derailed by firewall permission issues in the room.
"""

import asyncio
import time

# Stage -> (min_delay_ms, max_delay_ms)
STAGE_DELAYS = {
    0: (0, 0),
    1: (100, 400),
    2: (500, 1500),
    3: (1500, 3000),   # applied on top of redirect to rabbit-hole persona
}

# Simple token bucket per IP for Stage 2+ rate limiting
_buckets = {}
BUCKET_CAPACITY = 5
BUCKET_REFILL_PER_SEC = 1

# Hard-block simulate mode: log-only unless explicitly enabled
HARD_BLOCK_SIMULATE_ONLY = True
_blocked_ips = {}  # ip -> unblock_timestamp


def _get_bucket(ip):
    now = time.time()
    if ip not in _buckets:
        _buckets[ip] = {"tokens": BUCKET_CAPACITY, "last": now}
    bucket = _buckets[ip]
    elapsed = now - bucket["last"]
    bucket["tokens"] = min(BUCKET_CAPACITY, bucket["tokens"] + elapsed * BUCKET_REFILL_PER_SEC)
    bucket["last"] = now
    return bucket


def allow_request(ip) -> bool:
    """Token-bucket check used at Stage 2+ to throttle request rate."""
    bucket = _get_bucket(ip)
    if bucket["tokens"] >= 1:
        bucket["tokens"] -= 1
        return True
    return False


def is_blocked(ip) -> bool:
    unblock_at = _blocked_ips.get(ip)
    if unblock_at is None:
        return False
    if time.time() >= unblock_at:
        del _blocked_ips[ip]
        return False
    return True


def apply_hard_block(ip, ttl_seconds=900):
    """
    Stage 4 - simulate mode by default: records the block decision
    without necessarily touching the real firewall, so a firewall/
    permissions issue on demo day can't break the live run.
    Flip HARD_BLOCK_SIMULATE_ONLY to False and wire in your iptables/ufw
    subprocess call here for the real stretch-goal version.
    """
    _blocked_ips[ip] = time.time() + ttl_seconds
    if HARD_BLOCK_SIMULATE_ONLY:
        return {"mode": "simulated", "ip": ip, "ttl_seconds": ttl_seconds}
    else:
        # Example real enforcement (Linux, requires root):
        # import subprocess
        # subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        return {"mode": "enforced", "ip": ip, "ttl_seconds": ttl_seconds}


async def apply_stage_delay(stage: int):
    """Await an artificial delay appropriate to the containment stage."""
    lo, hi = STAGE_DELAYS.get(stage, (0, 0))
    if hi > 0:
        import random
        delay_s = random.uniform(lo, hi) / 1000.0
        await asyncio.sleep(delay_s)


def should_redirect_to_rabbit_hole(stage: int) -> bool:
    return stage >= 3
