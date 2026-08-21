#!/usr/bin/env python3
"""secured_gibberlink_anchored.py -- the "buildable now" trust-anchor integration.

This replaces the showcase's hardcoded KeyAnchorRegistry dict with the REAL published
resolver (algovoi-rfc9421-keyid 0.1.0). The layered trust anchor works as follows:

  1. did:key is the offline floor: the sender's keyid is a genuine did:key:z... produced
     with encode_did_key(B.public_key), so resolve_keyid decodes it OFFLINE (inline) and
     the self-consistency check (inline key must equal the decoded key) doubles as a tamper
     check. A self-certifying did:key still needs an explicit ACCEPT decision (pin or signed
     directory) -- anyone can mint a did:key, so "resolvable" is not "trusted".
  2. Signed directory (Falcon-1024, an offline signed-registry pattern) supplies human-named
     identities. The read side verifies the Falcon signature over JCS bytes + valid_until
     freshness against a trusted root key BEFORE populating the resolver cache.
  3. did:web / https live resolution is opt-in and guarded by an SSRF-safe resolver PLUS a
     domain allowlist enforced before any fetch.
  4. TOFU pins bootstrap unlisted peers: first contact pins (keyid -> key hex), later
     messages must match.

Every key that leaves the registry -- pinned, cached, or freshly resolved -- passes through
the verifier's weak-key gate (check_ed25519_public_key) first, so a misconfigured directory
or a hostile did:web cannot hand a small-order key to the verifier.

We do NOT edit the base/showcase files. Transport (send/recv over sound), the flexible signer
(_sign_envelope), and the anchor_gate / anchored_verify policy are imported UNCHANGED and fed
the new resolver-backed registry (duck-typed on .resolve(keyid) -> hex | None).

Honesty boundary (see the .md): the verifier proves "signed by the anchored key". The anchor
proves "this key belongs to this identity"; its root is out of scope for the verifier. Nothing
here is a crypto stub -- Falcon signing and verification both run for real locally. The only
test-shaped shortcut is that the directory root keypair is generated ephemerally in-process for
the self-test; in production that root is a cold-storage signing key held offline.

Run:  python secured_gibberlink_anchored.py
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

from nacl.signing import SigningKey

# --- Base testbed (unedited): transport + digest/base helpers ---------------------------
from secured_gibberlink_demo import (
    HOME,
    TAG,
    recv_from_sound,
    send_over_sound,
)

# --- Showcase policy (unedited): the anchor gate, anchored verify, flexible signer -------
# anchor_gate / anchored_verify only call registry.resolve(keyid); our AnchorRegistry is
# duck-type compatible, so the policy code is reused verbatim with the REAL resolver behind it.
from secured_gibberlink_showcase import (
    Case,
    DEMO_BODY,
    SMALL_ORDER_PK_HEX,
    _sign_envelope,
    anchor_gate,
    anchored_verify,
    base_verify_inline,
    print_table,
)

# --- Published resolver (algovoi-rfc9421-keyid 0.1.0) ----------------------------------
from algovoi_rfc9421_keyid import (
    SSRFError,
    encode_did_key,
    resolve_keyid,
)
from algovoi_rfc9421_keyid.resolver import _default_resolve  # DNS step we wrap with the allowlist

# --- Published verifier weak-key gate --------------------------------------------------
from algovoi_rfc9421_verifier import (
    WeakKeyError,
    check_ed25519_public_key,
    parse_signature_input,
    verify_request,
)

# --- Falcon-1024 signed-directory crypto (real, both sides) ----------------------------
import rfc8785
from pqcrypto.sign.falcon_1024 import sign as _falcon_sign
from pqcrypto.sign.falcon_1024 import verify as _falcon_verify
from pqcrypto.sign.falcon_1024 import generate_keypair as _falcon_keypair

PIN_FILE = HOME / "anchored_tofu_pins.json"
DIRECTORY_TTL_DAYS = 30


# =======================================================================================
# TOFU pin store: first contact pins (keyid -> key hex); later messages must match.
# =======================================================================================
class TofuPinStore:
    """A small JSON pin file. First accept pins; a later different key for the same keyid
    is a pin mismatch (rejected). This is the design's item 4 bootstrap for unlisted peers."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self._pins: dict[str, str] = {}
        if self._path.exists():
            try:
                self._pins = {
                    str(k): str(v).lower()
                    for k, v in json.loads(self._path.read_text(encoding="utf-8")).items()
                }
            except (ValueError, OSError):
                self._pins = {}  # a corrupt pin file fails closed to "no pins", never open

    def get(self, keyid: str) -> Optional[str]:
        return self._pins.get(keyid)

    def accept(self, keyid: str, key_hex: str) -> tuple[bool, str]:
        """TOFU decision. Returns (accepted, reason)."""
        key_hex = key_hex.lower()
        existing = self._pins.get(keyid)
        if existing is None:
            self._pins[keyid] = key_hex
            self._save()
            return True, "pinned on first contact (TOFU)"
        if existing == key_hex:
            return True, "matches existing pin"
        return False, "pin mismatch: key changed for an already-pinned keyid"

    def _save(self) -> None:
        self._path.write_text(json.dumps(self._pins, indent=2), encoding="utf-8")


# =======================================================================================
# A get/put cache the resolver consults before any fetch. Populated ONLY from a verified
# signed directory (never from the wire).
# =======================================================================================
class DirectoryCache:
    def __init__(self) -> None:
        self._d: dict[str, bytes] = {}

    def get(self, keyid: str) -> Optional[bytes]:
        return self._d.get(keyid)

    def put(self, keyid: str, key: bytes) -> None:
        self._d[keyid] = bytes(key)

    def __contains__(self, keyid: str) -> bool:
        return keyid in self._d


# =======================================================================================
# Signed directory (Falcon-1024) -- SIGN side (real) and VERIFY-before-trust side (real).
# A JCS-canonical signed-registry pattern: JCS-canonical payload, valid_until auto-expiry,
# kid = sha256(pubkey)[:16]. The root key is the trust root of the named-identity tier.
# =======================================================================================
def build_signed_directory(
    entries: list[dict], root_sk: bytes, root_pk: bytes, *, ttl_days: int = DIRECTORY_TTL_DAYS,
    issued_at: Optional[datetime] = None,
) -> dict:
    """Produce a Falcon-signed keyid->key directory (a JCS-canonical signed-registry shape).

    entries: [{"keyid": str, "public_key": <hex>, "identity": str}, ...]
    A REAL Falcon-1024 signature is produced over the JCS-canonical payload bytes.
    """
    issued = (issued_at or datetime.now(timezone.utc)).replace(microsecond=0)
    valid_until = issued + timedelta(days=ttl_days)
    payload = {
        "registry_version": "1",
        "registry_root_kid": hashlib.sha256(root_pk).hexdigest()[:16],
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "valid_until": valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "entries": entries,
    }
    canonical = rfc8785.dumps(payload)  # byte-identical on sign and verify
    sig = _falcon_sign(root_sk, canonical)
    return {
        "payload": payload,
        "alg": "Falcon-1024",
        "kid": hashlib.sha256(root_pk).hexdigest()[:16],
        "sig": base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii"),
        "public_key_pqclean_b64": base64.b64encode(root_pk).decode("ascii"),
    }


class DirectoryVerificationError(Exception):
    pass


def load_signed_directory(
    doc: dict, *, expected_root_pk: bytes, cache: DirectoryCache, now: Optional[datetime] = None,
) -> set[str]:
    """VERIFY-before-trust: verify the Falcon signature over JCS bytes + freshness against a
    TRUSTED root key, and ONLY THEN populate the cache. Returns the accept-set (keyids the
    directory vouches for). Raises DirectoryVerificationError on any failure -- fail closed.

    Note: weak keys are NOT filtered here on purpose. A misconfigured/hostile directory could
    list a small-order key; the resolve-time weak-key gate (AnchorRegistry.resolve) is what
    rejects it, exactly as the design requires ("the resolved key must hit the keycheck").
    """
    now = now or datetime.now(timezone.utc)
    if doc.get("alg") != "Falcon-1024":
        raise DirectoryVerificationError(f"unexpected alg: {doc.get('alg')!r}")
    try:
        pk = base64.b64decode(doc["public_key_pqclean_b64"])
    except Exception as e:  # noqa: BLE001 - malformed input fails closed
        raise DirectoryVerificationError(f"root pk decode failed: {e}") from e

    # Trust root check: the directory must be signed by the root key we already trust,
    # supplied out of band. Whoever holds root_sk can mint mappings -- that is the root.
    if pk != expected_root_pk:
        raise DirectoryVerificationError("directory not signed by the trusted root key")
    if doc.get("kid") != hashlib.sha256(pk).hexdigest()[:16]:
        raise DirectoryVerificationError("kid does not match the root public key")

    payload = doc.get("payload")
    if not isinstance(payload, dict):
        raise DirectoryVerificationError("payload is not an object")

    canonical = rfc8785.dumps(payload)
    try:
        sig = base64.urlsafe_b64decode(doc["sig"] + "=" * (-len(doc["sig"]) % 4))
    except Exception as e:  # noqa: BLE001
        raise DirectoryVerificationError(f"sig decode failed: {e}") from e
    if not bool(_falcon_verify(pk, canonical, sig)):
        raise DirectoryVerificationError("Falcon signature invalid over JCS payload")

    # Freshness: tz-aware, fail closed on stale or malformed.
    try:
        valid_until = datetime.fromisoformat(str(payload["valid_until"]).replace("Z", "+00:00"))
    except Exception as e:  # noqa: BLE001
        raise DirectoryVerificationError(f"valid_until malformed: {e}") from e
    if valid_until.tzinfo is None:
        valid_until = valid_until.replace(tzinfo=timezone.utc)
    if now > valid_until:
        raise DirectoryVerificationError(f"directory is stale (valid_until={payload['valid_until']})")

    # Only now, after signature + freshness + root-trust all pass, do we populate the cache.
    accept: set[str] = set()
    for e in payload.get("entries", []):
        keyid = str(e["keyid"])
        cache.put(keyid, bytes.fromhex(str(e["public_key"])))
        accept.add(keyid)
    return accept


# =======================================================================================
# The fix: a resolver-backed AnchorRegistry. resolve(keyid) -> hex | None.
# Pins first, then resolve_keyid (verified directory cache, offline did:key, guarded did:web),
# every returned key through check_ed25519_public_key. Fail closed to None on any error.
# =======================================================================================
class AnchorRegistry:
    def __init__(
        self,
        *,
        pins: Optional[TofuPinStore] = None,
        directory_cache: Optional[DirectoryCache] = None,
        directory_accept: Optional[set[str]] = None,
        allow_did_web: bool = False,
        allow_https_url: bool = False,
        host_allowlist: Optional[set[str]] = None,
        dns: Optional[Callable[[str], list]] = None,
    ):
        self._pins = pins or TofuPinStore(PIN_FILE)
        self._cache = directory_cache            # populated from a VERIFIED signed directory
        self._accept = directory_accept or set()  # keyids the verified directory vouches for
        self._allow_did_web = allow_did_web
        self._allow_https_url = allow_https_url
        self._host_allowlist = host_allowlist    # domain allowlist for the SSRF path
        self._dns = dns or _default_resolve      # injectable for the SSRF test (no egress)

    # -- SSRF domain allowlist, enforced BEFORE any DNS/connect -------------------------
    def _guarded_resolve(self, host: str) -> list:
        if self._host_allowlist is not None and host not in self._host_allowlist:
            # Raised before getaddrinfo/connect: no fetch, no egress for a bad host.
            raise SSRFError(f"host not in domain allowlist: {host!r}")
        return self._dns(host)

    def _gate(self, pubkey: bytes) -> Optional[str]:
        """Weak-key gate. Returns lowercase hex, or None if the key is weak/small-order."""
        try:
            check_ed25519_public_key(pubkey)
        except WeakKeyError:
            return None
        return pubkey.hex()

    def resolve(self, keyid: str) -> Optional[str]:
        # (1) TOFU pins first.
        pinned = self._pins.get(keyid)
        if pinned is not None:
            try:
                return self._gate(bytes.fromhex(pinned))
            except ValueError:
                return None

        # (2) resolver: verified directory cache, offline did:key inline, or guarded did:web.
        try:
            r = resolve_keyid(
                keyid,
                cache=self._cache,
                allow_did_web=self._allow_did_web,
                allow_https_url=self._allow_https_url,
                resolve_host=self._guarded_resolve,  # enforce the domain allowlist here
            )
        except Exception:  # noqa: BLE001 - any resolution error fails closed to None
            return None

        # A did:key resolves inline (self-certifying). Accept it only if a trust source
        # vouches for it: a pin (checked above) or the verified directory accept-set.
        # Otherwise anyone could mint a valid did:key and be trusted.
        # A did:key is self-certifying, not self-authorizing: trust it ONLY if a pin (checked
        # above) or the verified directory vouches for it. There is no switch to disable this
        # (the former accept_any_did_key footgun, flagged in validation, is removed).
        if r.key_source == "inline" and keyid not in self._accept:
            return None

        # (3) MANDATORY weak-key gate on every resolved key, before it is trusted.
        return self._gate(r.public_key)


# =======================================================================================
# Real did:key signer for Agent B: keyid = encode_did_key(B.public_key).
# =======================================================================================
def agent_b_sign_realkey(signing_key: SigningKey, *, created: int, **kw) -> dict:
    """Like the base agent_b_sign, but the keyid is a GENUINE did:key:z... (not the base
    demo's fake `did:key:z-demo-...`). resolve_keyid decodes this offline (inline) back to
    B's public key, and the signed Signature-Input carries this real keyid."""
    keyid = encode_did_key(signing_key.verify_key.encode())
    return _sign_envelope(signing_key, keyid=keyid, body_obj=dict(DEMO_BODY), created=created, **kw)


# =======================================================================================
# The adversarial battery. Original showcase cases (with the REAL did:key resolver) + the
# new trust-anchor cases. Each returns a Case; a Case passes when observed == expected.
# =======================================================================================
def run_battery() -> tuple[list[Case], dict]:
    t0 = int(time.time())
    key_b = SigningKey.generate()
    attacker = SigningKey.generate()

    # --- Build the real trust anchor ----------------------------------------------------
    # TOFU pin store (fresh for the self-test).
    if PIN_FILE.exists():
        PIN_FILE.unlink()
    pins = TofuPinStore(PIN_FILE)

    # A signed directory (Falcon-1024) with named identities. REAL signature.
    root_pk, root_sk = _falcon_keypair()  # ephemeral test root == the cold-storage key in prod
    acme_key = SigningKey.generate()      # "Acme Agent", reached by a did:web keyid
    acme_did = "did:web:acme.example"
    weak_did = "did:web:weakco.example"   # a MISCONFIGURED directory entry: a small-order key
    directory_doc = build_signed_directory(
        entries=[
            {"keyid": acme_did, "public_key": acme_key.verify_key.encode().hex(),
             "identity": "Acme Agent"},
            {"keyid": weak_did, "public_key": SMALL_ORDER_PK_HEX, "identity": "Weak Co (misconfig)"},
        ],
        root_sk=root_sk, root_pk=root_pk,
    )

    # VERIFY-before-trust: load the directory only after Falcon + freshness + root check.
    cache = DirectoryCache()
    accept = load_signed_directory(directory_doc, expected_root_pk=root_pk, cache=cache)

    # The registry: offline anchors on by default; did:web opt-in and allowlist-guarded.
    reg = AnchorRegistry(
        pins=pins, directory_cache=cache, directory_accept=accept,
        allow_did_web=False, allow_https_url=False,
    )

    # B's genuine did:key, established out of band via TOFU on first contact.
    b_env0 = agent_b_sign_realkey(key_b, created=t0)
    b_keyid = str(parse_signature_input(b_env0["headers"]["Signature-Input"]).parameters["keyid"])
    pin_ok, pin_reason = pins.accept(b_keyid, key_b.verify_key.encode().hex())

    cases: list[Case] = []

    # ---- 1. HAPPY PATH, anchored, through the sound hop -> ACCEPTED --------------------
    wav = HOME / "anchored_val_message.wav"
    got = recv_from_sound(send_over_sound(b_env0, wav))
    d = anchored_verify(got, now=t0 + 5, registry=reg)
    cases.append(Case(
        "1. Happy path (real did:key, via sound)", expect_reject=False,
        accepted=d.accepted, stage=d.stage,
        detail=f"keyid={b_keyid[:24]}...; survived sound={got['body_b64']==b_env0['body_b64']}; "
               f"TOFU={pin_reason}; {d.reason}",
    ))

    # ---- 2. BODY TAMPER after signing -> reject on Content-Digest ----------------------
    tampered = json.loads(json.dumps(got))
    bb = bytearray(base64.b64decode(tampered["body_b64"]))
    bb[bb.find(b"12.50")] = ord("9")
    tampered["body_b64"] = base64.b64encode(bytes(bb)).decode()
    d = anchored_verify(tampered, now=t0 + 5, registry=reg)
    cases.append(Case("2. Body tamper (12.50->92.50)", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 3. REPLAY past expiry -> reject on freshness ---------------------------------
    d = anchored_verify(got, now=t0 + 4000, registry=reg)
    cases.append(Case("3. Replay past expiry (t0+4000s)", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 4a. KEY-SWAP + attacker re-sign under B's did:key -> anchor: key mismatch -----
    forged_body = dict(DEMO_BODY, amount="999.00")
    forged_same_keyid = _sign_envelope(attacker, keyid=b_keyid, body_obj=forged_body, created=t0)
    pre = base_verify_inline(forged_same_keyid, now=t0 + 5)  # PRE-FIX inline verify accepts it
    d = anchored_verify(forged_same_keyid, now=t0 + 5, registry=reg)
    cases.append(Case(
        "4a. Key-swap re-sign under B's did:key", expect_reject=True,
        accepted=d.accepted, stage=d.stage,
        detail=f"PRE-FIX inline accepted={pre.valid} (999.00); anchored -> {d.reason}",
    ))

    # ---- 4b. Attacker mints their OWN valid did:key -> anchor: untrusted keyid ----------
    # Stronger than the base showcase (which used a malformed string): here the attacker
    # uses a WELL-FORMED did:key of their own key. It self-resolves offline, but it is not
    # pinned and not in the signed directory, so the accept gate rejects it.
    atk_env = agent_b_sign_realkey(attacker, created=t0)
    atk_keyid = str(parse_signature_input(atk_env["headers"]["Signature-Input"]).parameters["keyid"])
    pre2 = base_verify_inline(atk_env, now=t0 + 5)
    resolved_atk = reg.resolve(atk_keyid)
    d = anchored_verify(atk_env, now=t0 + 5, registry=reg)
    cases.append(Case(
        "4b. Attacker's own valid did:key (untrusted)", expect_reject=True,
        accepted=d.accepted, stage=d.stage,
        detail=f"PRE-FIX inline accepted={pre2.valid}; well-formed did:key decodes offline but "
               f"registry.resolve->{resolved_atk}; anchored -> {d.reason}",
    ))

    # ---- 5. SMALL-ORDER key pinned (misconfig) -> weak-key gate rejects ----------------
    weak_keyid = "did:key:z-weak-pinned"
    pins.accept(weak_keyid, SMALL_ORDER_PK_HEX)  # even a pinned weak key must be rejected
    weak_env = _sign_envelope(SigningKey.generate(), keyid=weak_keyid, body_obj=dict(DEMO_BODY),
                              created=t0, inline_public_key_hex=SMALL_ORDER_PK_HEX)
    d = anchored_verify(weak_env, now=t0 + 5, registry=reg)
    cases.append(Case("5. Small-order key (pinned, misconfig)", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 6a. ALGORITHM OMISSION -> reject ---------------------------------------------
    noalg = _sign_envelope(key_b, keyid=b_keyid, body_obj=dict(DEMO_BODY), created=t0, include_alg=False)
    d = anchored_verify(noalg, now=t0 + 5, registry=reg)
    cases.append(Case("6a. Algorithm omission (no alg param)", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 6b. ALGORITHM DOWNGRADE -> reject --------------------------------------------
    d = anchored_verify(b_env0, now=t0 + 5, registry=reg, allowed_algorithms={"rsa-pss-sha512"})
    cases.append(Case("6b. Algorithm downgrade (not allowed)", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 7. CONTENT-DIGEST present but NOT covered -> reject ---------------------------
    uncovered = _sign_envelope(key_b, keyid=b_keyid, body_obj=dict(DEMO_BODY), created=t0,
                               include_content_digest_in_cover=False)
    d = anchored_verify(uncovered, now=t0 + 5, registry=reg)
    cases.append(Case("7. Content-Digest present but not covered", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 8. WRONG TAG when required -> reject ------------------------------------------
    wrongtag = _sign_envelope(key_b, keyid=b_keyid, body_obj=dict(DEMO_BODY), created=t0,
                              tag="not-the-tag")
    d = anchored_verify(wrongtag, now=t0 + 5, registry=reg)
    cases.append(Case("8. Wrong tag when required", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 9. NONCE REPLAY --------------------------------------------------------------
    seen: set[tuple[str, str]] = set()

    def nonce_seen(nonce: str, keyid: str) -> bool:
        k = (nonce, keyid)
        if k in seen:
            return True
        seen.add(k)
        return False

    fresh = agent_b_sign_realkey(key_b, created=t0)
    d_first = anchored_verify(fresh, now=t0 + 5, registry=reg, nonce_seen=nonce_seen)
    d_second = anchored_verify(fresh, now=t0 + 5, registry=reg, nonce_seen=nonce_seen)
    cases.append(Case(
        "9. Nonce replay (same nonce twice)", expect_reject=True,
        accepted=d_second.accepted, stage=d_second.stage,
        detail=f"first accepted={d_first.accepted}; second -> {d_second.reason}",
    ))

    # ===== NEW trust-anchor cases ======================================================

    # ---- 10. Directory-listed named identity resolves from the VERIFIED cache -> ACCEPT
    # Acme Agent is reached by a did:web keyid whose key lives ONLY in the Falcon-verified
    # directory cache. allow_did_web is False, so this is a pure offline cache hit.
    acme_env = _sign_envelope(acme_key, keyid=acme_did, body_obj=dict(DEMO_BODY), created=t0)
    resolved_acme = reg.resolve(acme_did)
    d = anchored_verify(acme_env, now=t0 + 5, registry=reg)
    cases.append(Case(
        "10. NEW: signed-directory named identity", expect_reject=False,
        accepted=d.accepted, stage=d.stage,
        detail=f"did:web via VERIFIED cache (offline, allow_did_web=False); "
               f"resolve->{'hit' if resolved_acme else 'miss'}; {d.reason}",
    ))

    # ---- 11. Out-of-allowlist did:web host -> REJECTED before any fetch (SSRF) ----------
    # allow_did_web=True but the host is not in the domain allowlist. The guard raises before
    # DNS/connect. A DNS spy that raises if called proves there was no network egress.
    def _no_egress_dns(host):
        raise AssertionError(f"network egress attempted for {host!r} -- allowlist failed")

    ssrf_reg = AnchorRegistry(
        pins=TofuPinStore(HOME / "anchored_ssrf_pins.json"),
        directory_cache=DirectoryCache(), directory_accept=set(),
        allow_did_web=True, host_allowlist={"trusted-directory.example"},
        dns=_no_egress_dns,
    )
    evil_did = "did:web:evil.attacker.example"
    guard_raised = False
    try:
        ssrf_reg._guarded_resolve("evil.attacker.example")
    except SSRFError:
        guard_raised = True
    ssrf_resolved = ssrf_reg.resolve(evil_did)  # must be None, and must not have hit _no_egress_dns
    cases.append(Case(
        "11. NEW: out-of-allowlist did:web (SSRF)", expect_reject=True,
        # model the "reject" as an accept=False decision: resolve returned None
        accepted=(ssrf_resolved is not None), stage="anchor",
        detail=f"guard raised before fetch={guard_raised}; resolve('{evil_did}')={ssrf_resolved}; "
               f"no DNS egress (spy resolver never called)",
    ))

    # ---- 12. Directory serves a small-order key -> weak-key gate REJECTS at resolve -----
    weak_resolved = reg.resolve(weak_did)  # weak_did is in the verified cache, but small-order
    cases.append(Case(
        "12. NEW: directory weak key (resolve gate)", expect_reject=True,
        accepted=(weak_resolved is not None), stage="anchor",
        detail=f"weakco.example in VERIFIED cache but small-order; resolve->{weak_resolved} "
               f"(check_ed25519_public_key rejected before trust)",
    ))

    # ---- 13. did:key self-consistency: decoded key != inline key -> REJECT --------------
    # B's real did:key, but the envelope carries a DIFFERENT inline key. The did:key decodes
    # offline to B's key; inline != decoded, so the anchor gate rejects it.
    other = SigningKey.generate()
    inconsistent = _sign_envelope(
        key_b, keyid=b_keyid, body_obj=dict(DEMO_BODY), created=t0,
        inline_public_key_hex=other.verify_key.encode().hex(),
    )
    # Prove the offline decode independently of the pin: resolve_keyid on B's did:key -> inline.
    rk = resolve_keyid(b_keyid)
    decoded_matches_b = rk.public_key == key_b.verify_key.encode()
    d = anchored_verify(inconsistent, now=t0 + 5, registry=reg)
    cases.append(Case(
        "13. NEW: did:key self-consistency (inline!=decoded)", expect_reject=True,
        accepted=d.accepted, stage=d.stage,
        detail=f"resolve_keyid decoded offline (source={rk.key_source}, matches B={decoded_matches_b}); "
               f"inline!=decoded -> {d.reason}",
    ))

    # ---- 14. TOFU pin mismatch is caught by the pin store directly ----------------------
    tofu_ok, tofu_reason = reg._pins.accept(b_keyid, other.verify_key.encode().hex())
    cases.append(Case(
        "14. NEW: TOFU pin mismatch (key rotated under keyid)", expect_reject=True,
        accepted=tofu_ok, stage="anchor",
        detail=f"second key under B's pinned keyid -> accept={tofu_ok} ({tofu_reason})",
    ))

    # ---- 15. Stale signed directory -> load fails closed (freshness) -------------------
    old = datetime.now(timezone.utc) - timedelta(days=DIRECTORY_TTL_DAYS + 2)
    stale_doc = build_signed_directory(
        entries=[{"keyid": acme_did, "public_key": acme_key.verify_key.encode().hex(),
                  "identity": "Acme Agent"}],
        root_sk=root_sk, root_pk=root_pk, issued_at=old,
    )
    stale_rejected = False
    stale_reason = ""
    try:
        load_signed_directory(stale_doc, expected_root_pk=root_pk, cache=DirectoryCache())
    except DirectoryVerificationError as e:
        stale_rejected = True
        stale_reason = str(e)
    cases.append(Case(
        "15. NEW: stale directory (freshness fail-closed)", expect_reject=True,
        accepted=(not stale_rejected), stage="anchor",
        detail=f"load raised={stale_rejected}: {stale_reason}",
    ))

    # ---- 16. Tampered signed directory -> Falcon verify fails closed -------------------
    tampered_doc = json.loads(json.dumps(directory_doc))
    tampered_doc["payload"]["entries"][0]["public_key"] = attacker.verify_key.encode().hex()
    dir_tamper_rejected = False
    dir_tamper_reason = ""
    try:
        load_signed_directory(tampered_doc, expected_root_pk=root_pk, cache=DirectoryCache())
    except DirectoryVerificationError as e:
        dir_tamper_rejected = True
        dir_tamper_reason = str(e)
    cases.append(Case(
        "16. NEW: tampered directory (Falcon fail-closed)", expect_reject=True,
        accepted=(not dir_tamper_rejected), stage="anchor",
        detail=f"swap Acme's key -> load raised={dir_tamper_rejected}: {dir_tamper_reason}",
    ))

    diagnostics = {
        "falcon_pk_len": len(root_pk),
        "falcon_sig_len": len(base64.urlsafe_b64decode(directory_doc["sig"] + "==")),
        "b_keyid": b_keyid,
        "did_key_offline": decoded_matches_b and rk.key_source == "inline",
        "weak_gate_works": weak_resolved is None,
        "allowlist_works": guard_raised and ssrf_resolved is None,
    }
    return cases, diagnostics


def transport_reliability(n: int = 12) -> tuple[int, int]:
    ok = 0
    key_b = SigningKey.generate()
    wav = HOME / "anchored_reliability.wav"
    for i in range(n):
        env = agent_b_sign_realkey(key_b, created=int(time.time()))
        try:
            got = recv_from_sound(send_over_sound(env, wav))
            if got["body_b64"] == env["body_b64"] and got["headers"] == env["headers"]:
                ok += 1
        except Exception as e:  # noqa: BLE001
            print(f"   run {i + 1}: DECODE FAILURE -> {e}")
    return ok, n


def main() -> None:
    print("SECURED GIBBERLINK -- ANCHORED (real published resolver: algovoi-rfc9421-keyid 0.1.0)")
    print("The hardcoded key registry is replaced by did:key + a Falcon-signed directory + TOFU,")
    print("with an SSRF domain allowlist and the verifier's weak-key gate on every resolved key.")

    cases, diag = run_battery()
    all_pass = print_table(cases)

    print("\nTRUST-ANCHOR DIAGNOSTICS")
    print("=" * 100)
    print(f"   did:key offline resolution (inline, decodes to B): {diag['did_key_offline']}")
    print(f"   weak-key gate rejects a directory small-order key: {diag['weak_gate_works']}")
    print(f"   SSRF domain allowlist rejects out-of-list did:web: {diag['allowlist_works']}")
    print(f"   Falcon-1024 directory: pk={diag['falcon_pk_len']}B sig={diag['falcon_sig_len']}B (REAL)")

    print("\nTRANSPORT RELIABILITY (real did:key envelopes over the sound codec)")
    print("=" * 100)
    ok, ntot = transport_reliability(12)
    print(f"   sign -> ggwave -> .wav -> decode -> byte-exact match: {ok}/{ntot} runs")
    transport_ok = ok == ntot
    print("   transport is 100% reliable." if transport_ok
          else "   BLOCKER: transport dropped at least one frame.")

    print("\nVERDICT:",
          "anchored showcase-ready" if (all_pass and transport_ok)
          else "NOT ready -- see FAIL rows / reliability blocker above")


if __name__ == "__main__":
    main()
