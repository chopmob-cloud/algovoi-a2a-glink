#!/usr/bin/env python3
"""clinic_transport.py -- the SEALED-TRANSPORT control layer for the gibberlink RFC 9421 clinic.

Turns the local simulation into something real agents can reach SAFELY. This is the security boundary
required BEFORE any open deploy:

  * ENROLLMENT / AUTH  -- only peers whose keyid->pubkey is anchored out of band may connect; the signing
                          key is resolved from the anchored table, NEVER from the envelope.
  * SCHEMA + SIZE      -- every external frame is size-bounded and schema-checked before any work.
  * REPLAY             -- a per-message nonce (the unique signature hash) is remembered within the window.
  * RATE + COST        -- per-peer rate limit + a hard global daily ceiling (caps the dedicated key spend).
  * AUDIT              -- tamper-evident hash-chained per-request records.
  * GRACEFUL FAILURE   -- every control FAILS CLOSED; no input can crash the pipeline.

Decoupled from the socket ON PURPOSE: the controls here are pure logic and unit-tested offline. The actual
network bind + PROCESS ISOLATION (no secrets/secret-store.db reach, egress firewalled) is the final step, built in
a sandbox and re-reviewed on the RUNNING listener before the gated open deploy. Signature
verification is injected (verify_fn) so this module needs no crypto deps to test; production wires the real
verify_envelope via make_verify_fn().
"""
from __future__ import annotations
import hashlib, json, time
from collections import deque, defaultdict

MAX_FRAME_BYTES = 16 * 1024        # hard size bound on any external frame
MAX_QUESTION_CHARS = 2000          # mirror clinic_responder's input bound
NONCE_TTL = 300                    # seconds a message nonce is remembered (>= freshness window)
RATE_WINDOW = 60                   # seconds
RATE_MAX_PER_PEER = 6              # requests / window / enrolled peer
GLOBAL_MAX_PER_DAY = 500           # hard request ceiling == cost cap proxy for the dedicated key

REQUIRED_TOP = ("method", "authority", "path", "headers", "body_b64", "keyid")
REQUIRED_HEADERS = ("Content-Digest", "Signature-Input", "Signature")


class TransportReject(Exception):
    """Raised (and audited) whenever a frame is refused. Fail-closed by construction."""


MAX_ENROLLED_PEERS = 5000          # hard cap: bounds the store + Sybil pressure
MAX_TRACKED_PEERS = 4096           # rate-limiter buckets retained before expired ones are swept
MAX_PUBKEY_HEX = 128               # an Ed25519 pubkey is 64 hex chars; bound the field


def _valid_pubkey_hex(v) -> bool:
    """Bound and shape-check a self-asserted pubkey BEFORE it is persisted. MAX_PUBKEY_HEX was
    declared for this and never applied here, so the registry would fsync an arbitrarily long
    non-hex string into the durable store if any caller skipped its own check."""
    return (isinstance(v, str) and 0 < len(v) <= MAX_PUBKEY_HEX and len(v) % 2 == 0
            and all(c in "0123456789abcdefABCDEF" for c in v))


class EnrollmentRegistry:
    """keyid->pubkey_hex peers allowed on the trusted tiers. Baked/anchored peers are established
    out of band; additional peers may SELF-ENROLL (proof-of-key-control) into a durable append-only
    store. Enrollment establishes IDENTITY ONLY, never trust: it just grants rate-bounded access to
    the public help tiers. The signing key for verification is always resolved from THIS table,
    never from a frame."""
    def __init__(self, anchored: dict | None = None, store_path: str | None = None,
                 max_peers: int = MAX_ENROLLED_PEERS):
        self._peers = dict(anchored or {})
        self._anchored = set(self._peers)          # baked peers are never evicted/overwritten
        self.store_path = store_path
        self.max_peers = max_peers
        if store_path:
            self._load_store()

    def _load_store(self) -> None:
        import os
        if not self.store_path or not os.path.exists(self.store_path):
            return
        with open(self.store_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                op, kid, pub = rec.get("op", "enroll"), rec.get("keyid"), rec.get("pubkey")
                if op == "revoke" and kid in self._peers and kid not in self._anchored:
                    del self._peers[kid]
                elif op == "enroll" and kid and _valid_pubkey_hex(pub) and kid not in self._anchored:
                    if len(self._peers) >= self.max_peers:
                        continue                       # the cap binds on LOAD too, not just enroll()
                    self._peers.setdefault(kid, pub)   # first-write wins; a re-enroll never rebinds

    def enroll(self, keyid: str, pubkey_hex: str) -> str:
        """Register a self-enrolled peer durably. Returns 'exists' (idempotent), 'full', 'conflict'
        (keyid already bound to a different key), 'invalid' (malformed/oversized pubkey), or
        'enrolled'."""
        if keyid in self._anchored:
            return "exists"
        if not _valid_pubkey_hex(pubkey_hex):
            return "invalid"                                       # never persist a malformed key
        cur = self._peers.get(keyid)
        if cur is not None:
            return "exists" if cur == pubkey_hex else "conflict"   # never silently rebind a keyid
        if len(self._peers) >= self.max_peers:
            return "full"
        self._persist({"op": "enroll", "keyid": keyid, "pubkey": pubkey_hex, "ts": int(time.time())})
        self._peers[keyid] = pubkey_hex
        return "enrolled"

    def _persist(self, rec: dict) -> None:
        import os
        if not self.store_path:
            return
        line = json.dumps(rec, sort_keys=True) + "\n"
        fd = os.open(self.store_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def is_enrolled(self, keyid) -> bool:
        return keyid in self._peers

    def pubkey(self, keyid):
        return self._peers.get(keyid)

    def count(self) -> int:
        return len(self._peers)


class ReplayCache:
    """Remember each message nonce until it expires; a repeat within the window is a replay."""
    def __init__(self, ttl: int = NONCE_TTL):
        self.ttl = ttl
        self._seen: dict[str, int] = {}

    def check_and_add(self, nonce: str, now: int | None = None) -> bool:
        now = int(time.time()) if now is None else now
        for k, exp in list(self._seen.items()):
            if exp < now:
                del self._seen[k]
        if nonce in self._seen:
            return False                 # replay
        self._seen[nonce] = now + self.ttl
        return True


class RateLimiter:
    """Per-peer sliding-window rate limit + a hard global daily ceiling (cost cap)."""
    def __init__(self, per_peer=RATE_MAX_PER_PEER, window=RATE_WINDOW, global_day=GLOBAL_MAX_PER_DAY,
                 max_tracked=MAX_TRACKED_PEERS):
        self.per_peer, self.window, self.global_day = per_peer, window, global_day
        self.max_tracked = max_tracked
        self._hits: dict[str, deque] = defaultdict(deque)
        self._day, self._day_count = None, 0

    def _evict_expired(self, now: int) -> None:
        """Drop peers whose window has fully expired. The open-explain path buckets under a
        caller-controlled 'self:<pubkey>' key, so without eviction a stream of one-shot
        identities grows _hits for the life of the process."""
        cutoff = now - self.window
        for k in [k for k, d in self._hits.items() if not d or d[-1] <= cutoff]:
            del self._hits[k]

    def allow(self, peer: str, now: int | None = None) -> tuple[bool, str]:
        now = int(time.time()) if now is None else now
        day = time.strftime("%Y-%m-%d", time.gmtime(now))
        if day != self._day:
            self._day, self._day_count = day, 0
        if self._day_count >= self.global_day:
            return False, "global-daily-cap"
        if len(self._hits) > self.max_tracked:
            self._evict_expired(now)
        dq = self._hits[peer]
        while dq and dq[0] <= now - self.window:
            dq.popleft()
        if len(dq) >= self.per_peer:
            return False, "peer-rate"
        dq.append(now)
        self._day_count += 1
        return True, ""


class AuditLog:
    """Tamper-evident: each record's hash = sha256(prev_hash + record); altering any record breaks the chain.

    DURABLE mode (path=...): every record is also appended as one JSON line to an append-only file and
    fsync'd before append() returns, so the chain survives a process restart/crash and can be verified
    offline (verify_audit_file). On construction with an existing file, the chain head is restored from its
    last line so a restarted process continues the SAME chain instead of forking a new one. Durability is
    a pre-staging requirement before any open deploy."""
    def __init__(self, path: str | None = None):
        self._prev = "0" * 64
        self.records: list[dict] = []
        self.path = path
        if path:
            self._prev = _audit_chain_head(path)   # resume the existing chain if the file is non-empty
        # The head this process STARTED from. verify_chain() only sees the records this process
        # appended, so it must verify forward from here, not from genesis -- otherwise a durable
        # log reports a false tamper on every restart. verify_audit_file() checks the whole file.
        self._start = self._prev

    def append(self, event: dict) -> str:
        rec = dict(event)
        rec["ts"] = int(time.time())
        rec["prev"] = self._prev
        h = hashlib.sha256((self._prev + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
        rec["hash"] = h
        self._prev = h
        self.records.append(rec)
        if self.path:
            self._persist(rec)
        return h

    def _persist(self, rec: dict) -> None:
        """Append one record as a JSON line and fsync it to disk before returning (durable, ordered)."""
        import os
        line = json.dumps(rec, sort_keys=True) + "\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def verify_chain(self) -> bool:
        """Verify the records appended by THIS process, continuing from the chain head it
        resumed. For an end-to-end check of a durable file, use verify_audit_file()."""
        return _verify_records(self.records, start=self._start)


def _verify_records(records, start: str = "0" * 64) -> bool:
    prev = start
    for e in records:
        body = {k: v for k, v in e.items() if k != "hash"}
        h = hashlib.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()
        if h != e.get("hash") or e.get("prev") != prev:
            return False
        prev = e["hash"]
    return True


def _audit_chain_head(path: str) -> str:
    """Return the last record's hash from a durable audit file, or the genesis hash if empty/missing."""
    import os
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return "0" * 64
    last = None
    with open(path, "rb") as f:
        for line in f:
            line = line.strip()
            if line:
                last = line
    if not last:
        return "0" * 64
    try:
        return json.loads(last).get("hash", "0" * 64)
    except Exception:
        return "0" * 64


def verify_audit_file(path: str) -> tuple[bool, int, str]:
    """Offline verifier for a durable audit file. Returns (ok, n_records, reason).
    Re-reads every line and recomputes the whole hash chain independently of any running process."""
    import os
    if not os.path.exists(path):
        return False, 0, "missing file"
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                return False, len(records), f"malformed json at line {i}"
    ok = _verify_records(records)
    return ok, len(records), "ok" if ok else "chain broken"


def validate_frame(raw) -> dict:
    """Size + JSON + schema gate. Fails closed on anything malformed BEFORE any crypto/model work."""
    if not isinstance(raw, (bytes, bytearray)):
        raise TransportReject("non-bytes frame")
    if len(raw) > MAX_FRAME_BYTES:
        raise TransportReject(f"frame too large ({len(raw)}>{MAX_FRAME_BYTES})")
    try:
        env = json.loads(raw)
    except Exception:
        raise TransportReject("malformed json")
    if not isinstance(env, dict):
        raise TransportReject("envelope not an object")
    for f in REQUIRED_TOP:
        if f not in env:
            raise TransportReject(f"missing field: {f}")
    h = env.get("headers")
    if not isinstance(h, dict):
        raise TransportReject("headers not an object")
    for f in REQUIRED_HEADERS:
        if f not in h:
            raise TransportReject(f"missing header: {f}")
    return env


def handle_frame(raw, *, replay: ReplayCache, limiter: RateLimiter, audit: AuditLog,
                 verify_fn, responder_fn, now: int | None = None) -> tuple[str, dict]:
    """Full fail-closed pipeline for one external frame.
    verify_fn(env, now) -> (ok, why, keyid, nonce, body_dict)   # enrollment + signature over the anchored key
    responder_fn(question) -> answer_dict
    Returns ('served'|'rejected', payload). Never raises: an unexpected error is audited and fails closed."""
    now = int(time.time()) if now is None else now
    try:
        env = validate_frame(raw)                                   # size + schema
        ok, why, keyid, nonce, body = verify_fn(env, now)           # enrolled peer + valid signature
        if not ok:
            raise TransportReject(f"verify: {why}")
        allowed, rwhy = limiter.allow(keyid, now)                   # rate + cost BEFORE replay-cache writes
        if not allowed:
            raise TransportReject(f"rate: {rwhy}")
        if not replay.check_and_add(nonce, now):
            raise TransportReject("replay")
        ans = responder_fn(body or {})            # responder routes concrete /explain vs conceptual
        audit.append({"event": "served", "keyid": keyid, "topic": ans.get("topic")})
        return "served", ans
    except TransportReject as e:
        audit.append({"event": "rejected", "reason": str(e)})
        return "rejected", {"error": str(e)}
    except Exception as e:  # noqa: BLE001  -- fail closed, never take the listener down
        audit.append({"event": "error", "reason": f"{type(e).__name__}: {str(e)[:80]}"})
        return "rejected", {"error": "internal"}


def make_verify_fn(registry: EnrollmentRegistry, *, allow_open_explain: bool = False):
    """Production verify_fn: enrollment + real RFC 9421 signature verify against the ANCHORED key.
    Imported lazily so the pure-logic layer + its tests need no crypto deps.

    allow_open_explain=True (public mode) additionally lets an UNENROLLED caller through, but
    ONLY for the stateless /explain debugger (intent == 'clinic_explain'), verified against the
    SELF-ASSERTED key in their envelope. This confers no trust (it only diagnoses the caller's
    own signed request); the caller is rate-limited under a namespaced 'self:<pubkey>' bucket so
    it can never touch an enrolled peer's quota, and the global daily cap still bounds abuse."""
    from negotiation_gibberlink_demo import (verify_envelope, verify_envelope_selfasserted,
                                             envelope_hash)

    def verify_fn(env: dict, now: int):
        keyid = env.get("keyid")
        if keyid and registry.is_enrolled(keyid):
            anchored = {keyid: registry.pubkey(keyid)}      # anchored out of band, NOT env["public_key_hex"]
            ok, why, body = verify_envelope(env, anchored_peers=anchored, expected_keyid=keyid, now=now)
            if not ok:
                return False, why, keyid, None, None
            return True, "ok", keyid, envelope_hash(env), body   # nonce = unique per-message signature hash

        if not allow_open_explain:
            return False, "unenrolled-peer", keyid, None, None
        # UNENROLLED, public mode: self-asserted, /explain only.
        ok, why, body = verify_envelope_selfasserted(env, now=now)
        if not ok:
            return False, why, keyid, None, None
        if not (isinstance(body, dict) and body.get("intent") == "clinic_explain"):
            return False, "unenrolled peers may only use the /explain debugger", keyid, None, None
        rl_key = "self:" + (env.get("public_key_hex") or "")[:32]   # namespaced; cannot touch enrolled quota
        return True, "ok-open-explain", rl_key, envelope_hash(env), body

    return verify_fn
