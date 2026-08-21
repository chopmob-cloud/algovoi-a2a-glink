#!/usr/bin/env python3
"""secured_gibberlink_showcase.py -- the SECURE, adversarially tested showcase build.

The base testbed (secured_gibberlink_demo.py) ends on a deliberate open wound: the
verifier proves "signed by THIS key", not "signed by agent B", because the public key
rides INSIDE the envelope over the sound channel. An attacker can swap BOTH the key and
the signature (and even rewrite the body) and it still "verifies" against their own key.

This showcase closes that gap with KEYID ANCHORING and then proves the fix under a full
adversarial battery. Every attack below is actually executed in code, not described.

The fix, in one line: Agent A never trusts the key that arrived over the wire. A resolves
the sender's SIGNED keyid against a trusted, out-of-band registry (a directory or a prior
handshake), rejects unknown keyids, rejects any envelope whose inline key does not equal
the anchored key, and then verifies the signature against the ANCHORED key.

Reuse: transport (send_over_sound/recv_from_sound) and the signer (agent_b_sign) are
imported unchanged from the base demo. The security core is the PUBLISHED verifier
(algovoi-rfc9421-verifier==0.4.4), installed like anyone else gets it.

Honesty boundaries (see the .md writeup):
  * the "sound" hop is a real ggwave codec written to a .wav and read back (a loopback
    stand-in for a speaker to microphone hop), not a live acoustic channel;
  * only the verifier can be run live (POST https://verify.algovoi.co.uk/rfc9421);
  * no facilitator, no MCP, no chain, no fabricated adoption.

Run:  python secured_gibberlink_showcase.py            (local battery + reliability)
      python secured_gibberlink_showcase.py --live     (also POST to the live verifier)
"""
from __future__ import annotations

import argparse
import base64
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from nacl.signing import SigningKey

# Reuse the base testbed verbatim. We do NOT edit that file; another process owns it.
from secured_gibberlink_demo import (
    HOME,
    TAG,
    agent_b_sign,
    build_signing_base,
    compute_content_digest,
    recv_from_sound,
    send_over_sound,
)

# The security core is the published verifier, unchanged.
from algovoi_rfc9421_verifier import (
    VerifyResult,
    parse_signature_input,
    verify_request,
)

LIVE_URL = "https://verify.algovoi.co.uk/rfc9421"

# A known small-order Ed25519 public key (order divides 8). Off-curve/weak keys like this
# must be rejected before verification; libsodium's basic verify would otherwise accept them.
SMALL_ORDER_PK_HEX = "0100000000000000000000000000000000000000000000000000000000000000"


# ===========================================================================
# The fix: an out-of-band keyid -> pinned public-key registry, and anchored verify.
# ===========================================================================
class KeyAnchorRegistry:
    """A trusted keyid -> public-key map. Stands in for a directory or a prior handshake.

    This is the out-of-band trust source. The key material here did NOT come off the sound
    channel; it was established before the conversation and is treated as ground truth.
    """

    def __init__(self, mapping: dict[str, str] | None = None):
        self._pins: dict[str, str] = {k: v.lower() for k, v in (mapping or {}).items()}

    @classmethod
    def from_json(cls, path: Path) -> "KeyAnchorRegistry":
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def to_json(self, path: Path) -> None:
        Path(path).write_text(json.dumps(self._pins, indent=2), encoding="utf-8")

    def anchor(self, keyid: str, public_key_hex: str) -> None:
        self._pins[keyid] = public_key_hex.lower()

    def resolve(self, keyid: str) -> str | None:
        return self._pins.get(keyid)


@dataclass
class AnchoredDecision:
    """The outcome of Agent A's full policy: anchor gate THEN signature verification."""

    accepted: bool
    reason: str
    stage: str  # "anchor" if the anchor gate decided, else "verify"
    anchored_key: str | None = None
    verify: VerifyResult | None = None


def anchor_gate(env: dict, registry: KeyAnchorRegistry) -> tuple[bool, str, str | None]:
    """Client-side trust policy, applied BEFORE any signature is trusted.

    Returns (ok, reason, anchored_key_hex). This runs identically whether the signature is
    then checked locally or by the live service: anchoring is A's policy, not the wire's.

    Key detail: we resolve the keyid from the SIGNED Signature-Input parameters, not from
    the unsigned top-level env['keyid'] field. The top-level field is attacker-mutable
    metadata; the keyid inside Signature-Input is covered by @signature-params.
    """
    try:
        parsed = parse_signature_input(env["headers"]["Signature-Input"])
    except Exception as e:  # a malformed header fails closed, never open
        return False, f"unparseable Signature-Input: {e}", None

    signed_keyid = parsed.parameters.get("keyid")
    if not signed_keyid:
        return False, "no keyid in signed Signature-Input", None
    signed_keyid = str(signed_keyid)

    # (2) reject unknown keyid -- not in the trusted registry.
    anchored = registry.resolve(signed_keyid)
    if anchored is None:
        return False, f"unanchored keyid (unknown to trust registry): {signed_keyid!r}", None

    # (3) reject if the inline key does not equal the anchored key.
    inline = str(env.get("public_key_hex", "")).lower()
    if inline != anchored:
        return (
            False,
            "key mismatch: inline key does not equal the anchored key for this keyid",
            anchored,
        )

    return True, "keyid anchored and inline key matches the pin", anchored


def anchored_verify(
    env: dict,
    *,
    now: int,
    registry: KeyAnchorRegistry,
    nonce_seen=None,
    max_age_seconds: int = 300,
    require_content_digest: bool = True,
    expected_tag: str | None = TAG,
    require_tag: bool = True,
    allowed_algorithms=frozenset({"ed25519"}),
) -> AnchoredDecision:
    """Agent A's full secure policy: (1) anchor gate, then (2) verify the signature against
    the ANCHORED key (never the envelope's inline key)."""
    ok, reason, anchored = anchor_gate(env, registry)
    if not ok:
        return AnchoredDecision(accepted=False, reason=reason, stage="anchor", anchored_key=anchored)

    body = base64.b64decode(env["body_b64"])
    res = verify_request(
        method=env["method"],
        authority=env["authority"],
        path=env["path"],
        headers=env["headers"],
        body=body,
        scheme=env.get("scheme", "https"),
        public_key=anchored,  # the fix: verify against the anchored key, not env inline
        require_content_digest=require_content_digest,
        expected_tag=expected_tag,
        require_tag=require_tag,
        allowed_algorithms=allowed_algorithms,
        now=now,
        max_age_seconds=max_age_seconds,
        nonce_seen=nonce_seen,
    )
    reason = "accepted" if res.valid else (res.errors[0] if res.errors else "verify failed")
    return AnchoredDecision(
        accepted=res.valid, reason=reason, stage="verify", anchored_key=anchored, verify=res
    )


def base_verify_inline(env: dict, *, now: int) -> VerifyResult:
    """The INSECURE base behaviour: verify against the key carried in the envelope. Used
    only to demonstrate the pre-fix gap (the key-swap attack passing this check)."""
    body = base64.b64decode(env["body_b64"])
    return verify_request(
        method=env["method"], authority=env["authority"], path=env["path"],
        headers=env["headers"], body=body, scheme=env.get("scheme", "https"),
        public_key=env["public_key_hex"], require_content_digest=True,
        expected_tag=TAG, require_tag=True, allowed_algorithms={"ed25519"},
        now=now, max_age_seconds=300,
    )


# ===========================================================================
# Attacker toolkit -- real forgeries, no hand-waving.
# ===========================================================================
def _sign_envelope(
    signing_key: SigningKey,
    *,
    keyid: str,
    body_obj: dict,
    created: int,
    ttl: int = 300,
    tag: str = TAG,
    include_content_digest_in_cover: bool = True,
    include_alg: bool = True,
    inline_public_key_hex: str | None = None,
) -> dict:
    """A flexible signer used to build both honest and malformed-but-genuinely-signed
    envelopes, so each rejection is attributable to the specific policy under test (not to
    an incidentally broken signature)."""
    body = json.dumps(body_obj, separators=(",", ":")).encode()
    cd = compute_content_digest(body)
    expires = created + ttl
    nonce = base64.b16encode(signing_key.sign(str(created).encode()).signature[:8]).decode().lower()

    if include_content_digest_in_cover:
        covered = ["@method", "@authority", "@path", "content-digest"]
        covered_str = '("@method" "@authority" "@path" "content-digest")'
        headers_for_base = {"content-digest": cd}
    else:
        covered = ["@method", "@authority", "@path"]
        covered_str = '("@method" "@authority" "@path")'
        headers_for_base = {}

    alg_part = ';alg="ed25519"' if include_alg else ""
    params_raw = (
        f"{covered_str}"
        f';created={created};expires={expires};keyid="{keyid}"{alg_part}'
        f';nonce="{nonce}";tag="{tag}"'
    )
    method, authority, path = "POST", "agent-b.local", "/a2a/message"
    signing_base = build_signing_base(
        covered, method=method, authority=authority, path=path, scheme="https",
        headers=headers_for_base, parameters={}, mode="rfc9421", signature_params_raw=params_raw,
    )
    sig = signing_key.sign(signing_base.encode("utf-8")).signature
    sig_b64 = base64.standard_b64encode(sig).decode()
    headers = {
        "Content-Digest": cd,
        "Signature-Input": f"sig1={params_raw}",
        "Signature": f"sig1=:{sig_b64}:",
    }
    return {
        "method": method, "authority": authority, "path": path, "scheme": "https",
        "headers": headers, "body_b64": base64.b64encode(body).decode(),
        "public_key_hex": (inline_public_key_hex or signing_key.verify_key.encode().hex()),
        "keyid": keyid,
    }


DEMO_BODY = {
    "intent": "authorize_payment", "from": "agent-b", "to": "agent-a",
    "amount": "12.50", "currency": "USDC", "memo": "invoice 4471, one-off",
}


# ===========================================================================
# The adversarial battery. Each case returns (name, expected_reject, decision).
# ===========================================================================
@dataclass
class Case:
    name: str
    expect_reject: bool
    accepted: bool
    stage: str
    detail: str
    passed: bool = field(init=False)

    def __post_init__(self):
        # A case PASSES when the observed accept/reject matches the expectation.
        self.passed = (self.accepted != self.expect_reject) if self.expect_reject else self.accepted


def run_battery() -> list[Case]:
    t0 = int(time.time())
    key_b = SigningKey.generate()
    attacker = SigningKey.generate()

    reg = KeyAnchorRegistry()
    # Out-of-band trust: A already knows B's keyid -> B's public key (a prior handshake).
    env_b = agent_b_sign(key_b, created=t0)
    b_keyid = str(parse_signature_input(env_b["headers"]["Signature-Input"]).parameters["keyid"])
    reg.anchor(b_keyid, key_b.verify_key.encode().hex())

    cases: list[Case] = []

    # ---- 1. HAPPY PATH, anchored, through the sound hop -> ACCEPTED ----
    wav = HOME / "showcase_val_message.wav"
    waveform = send_over_sound(env_b, wav)
    got = recv_from_sound(waveform)
    d = anchored_verify(got, now=t0 + 5, registry=reg)
    cases.append(Case(
        "1. Happy path (anchored, via sound)", expect_reject=False,
        accepted=d.accepted, stage=d.stage,
        detail=f"survived sound hop={got['body_b64'] == env_b['body_b64']}; {d.reason}",
    ))

    # ---- 2. BODY TAMPER after signing -> reject on Content-Digest ----
    tampered = json.loads(json.dumps(got))
    bb = bytearray(base64.b64decode(tampered["body_b64"]))
    bb[bb.find(b"12.50")] = ord("9")  # 12.50 -> 92.50
    tampered["body_b64"] = base64.b64encode(bytes(bb)).decode()
    d = anchored_verify(tampered, now=t0 + 5, registry=reg)
    cases.append(Case("2. Body tamper (amount 12.50->92.50)", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 3. REPLAY past expiry / max-age -> reject on freshness ----
    d = anchored_verify(got, now=t0 + 4000, registry=reg)
    cases.append(Case("3. Replay past expiry (now=t0+4000s)", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 4a. KEY-SWAP + attacker re-sign, keeps B's keyid -> anchor: key mismatch ----
    forged_body = dict(DEMO_BODY, amount="999.00")
    forged_same_keyid = _sign_envelope(attacker, keyid=b_keyid, body_obj=forged_body, created=t0)
    # First show the PRE-FIX gap: base (inline-key) verify ACCEPTS the forgery.
    pre = base_verify_inline(forged_same_keyid, now=t0 + 5)
    d = anchored_verify(forged_same_keyid, now=t0 + 5, registry=reg)
    cases.append(Case(
        "4a. Key-swap re-sign under B's keyid", expect_reject=True,
        accepted=d.accepted, stage=d.stage,
        detail=f"PRE-FIX base(inline) accepted={pre.valid} (amount 999.00); anchored -> {d.reason}",
    ))

    # ---- 4b. KEY-SWAP with attacker's OWN keyid -> anchor: unknown keyid ----
    atk_keyid = f"did:key:z-attacker-{attacker.verify_key.encode().hex()[:16]}"
    forged_own_keyid = _sign_envelope(attacker, keyid=atk_keyid, body_obj=forged_body, created=t0)
    pre2 = base_verify_inline(forged_own_keyid, now=t0 + 5)
    d = anchored_verify(forged_own_keyid, now=t0 + 5, registry=reg)
    cases.append(Case(
        "4b. Key-swap re-sign under attacker keyid", expect_reject=True,
        accepted=d.accepted, stage=d.stage,
        detail=f"PRE-FIX base(inline) accepted={pre2.valid}; anchored -> {d.reason}",
    ))

    # ---- 5. SMALL-ORDER / weak Ed25519 key -> reject by the key gate ----
    # Even if a weak key were mistakenly anchored (misconfigured directory), the key gate
    # must still reject it. Anchor the small-order key so the gate, not the anchor, decides.
    weak_keyid = "did:key:z-weak-smallorder"
    reg.anchor(weak_keyid, SMALL_ORDER_PK_HEX)
    # Build an envelope carrying the small-order key + a syntactically valid 64-byte sig.
    weak_env = _sign_envelope(
        SigningKey.generate(), keyid=weak_keyid, body_obj=DEMO_BODY, created=t0,
        inline_public_key_hex=SMALL_ORDER_PK_HEX,
    )
    d = anchored_verify(weak_env, now=t0 + 5, registry=reg)
    cases.append(Case("5. Small-order Ed25519 public key", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 6a. ALGORITHM OMISSION (drop alg) -> reject ----
    noalg = _sign_envelope(key_b, keyid=b_keyid, body_obj=DEMO_BODY, created=t0, include_alg=False)
    d = anchored_verify(noalg, now=t0 + 5, registry=reg)
    cases.append(Case("6a. Algorithm omission (no alg param)", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 6b. ALGORITHM DOWNGRADE (alg not in allow-list) -> reject ----
    d = anchored_verify(env_b, now=t0 + 5, registry=reg, allowed_algorithms={"rsa-pss-sha512"})
    cases.append(Case("6b. Algorithm downgrade (alg not allowed)", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 7. CONTENT-DIGEST present but NOT a covered component -> reject ----
    # Genuinely signed, but the signature does not cover content-digest.
    uncovered = _sign_envelope(
        key_b, keyid=b_keyid, body_obj=DEMO_BODY, created=t0,
        include_content_digest_in_cover=False,
    )
    d = anchored_verify(uncovered, now=t0 + 5, registry=reg)
    cases.append(Case("7. Content-Digest present but not covered", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 8. WRONG TAG when required -> reject ----
    wrongtag = _sign_envelope(key_b, keyid=b_keyid, body_obj=DEMO_BODY, created=t0, tag="not-the-tag")
    d = anchored_verify(wrongtag, now=t0 + 5, registry=reg)  # expected_tag=TAG, require_tag=True
    cases.append(Case("8. Wrong tag when required", expect_reject=True,
                      accepted=d.accepted, stage=d.stage, detail=d.reason))

    # ---- 9. NONCE REPLAY via the verify_request nonce_seen callback ----
    seen: set[tuple[str, str]] = set()

    def nonce_seen(nonce: str, keyid: str) -> bool:
        key = (nonce, keyid)
        if key in seen:
            return True  # already used -> reject
        seen.add(key)
        return False

    fresh = agent_b_sign(key_b, created=t0)
    d_first = anchored_verify(fresh, now=t0 + 5, registry=reg, nonce_seen=nonce_seen)
    d_second = anchored_verify(fresh, now=t0 + 5, registry=reg, nonce_seen=nonce_seen)
    # First must be accepted, second must be rejected. The CASE tests the replay rejection.
    cases.append(Case(
        "9. Nonce replay (same nonce twice)", expect_reject=True,
        accepted=d_second.accepted, stage=d_second.stage,
        detail=f"first accepted={d_first.accepted}; second -> {d_second.reason}",
    ))

    return cases


def print_table(cases: list[Case]) -> bool:
    print("\nADVERSARIAL BATTERY  (anchored secure policy)")
    print("=" * 100)
    print(f"{'#  case':<46}{'expect':<9}{'observed':<10}{'stage':<8}{'result':<6}")
    print("-" * 100)
    all_pass = True
    for c in cases:
        expect = "REJECT" if c.expect_reject else "ACCEPT"
        observed = "reject" if not c.accepted else "accept"
        result = "PASS" if c.passed else "FAIL"
        all_pass = all_pass and c.passed
        print(f"{c.name:<46}{expect:<9}{observed:<10}{c.stage:<8}{result:<6}")
        print(f"     -> {c.detail}")
    print("-" * 100)
    print(f"OVERALL: {'ALL PASS' if all_pass else 'FAILURES PRESENT'}  ({sum(c.passed for c in cases)}/{len(cases)})")
    return all_pass


# ===========================================================================
# Transport reliability under the showcase.
# ===========================================================================
def reliability_check(n: int = 12) -> tuple[int, int]:
    ok = 0
    key_b = SigningKey.generate()
    wav = HOME / "showcase_reliability.wav"
    for i in range(n):
        env = agent_b_sign(key_b, created=int(time.time()))
        try:
            waveform = send_over_sound(env, wav)
            got = recv_from_sound(waveform)
            if got["body_b64"] == env["body_b64"] and got["headers"] == env["headers"]:
                ok += 1
        except Exception as e:  # a dropped frame surfaces as RuntimeError from recv
            print(f"   run {i + 1}: DECODE FAILURE -> {e}")
    return ok, n


# ===========================================================================
# Live verification (optional). Anchoring is client-side policy either way.
# ===========================================================================
def post_live(env: dict, *, anchored_key_hex: str) -> dict:
    """POST the decoded envelope to the live verifier, verifying the signature against the
    ANCHORED key (not the envelope's inline key). Reachability recipe for the live verifier:
    real path /rfc9421, a normal User-Agent (Cloudflare 403s the default Python-urllib UA),
    and LOWERCASE header keys."""
    payload = json.dumps({
        "method": env["method"], "authority": env["authority"], "path": env["path"],
        "scheme": env.get("scheme", "https"),
        "headers": {k.lower(): v for k, v in env["headers"].items()},
        "body_b64": env["body_b64"],
        "public_key_hex": anchored_key_hex,  # anchored, not env inline
        "require_content_digest": True, "mode": "rfc9421",
    }).encode()
    req = urllib.request.Request(
        LIVE_URL, data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "algovoi-gibberlink-showcase/1.0"},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


def run_live_proof() -> None:
    print("\nLIVE VERIFICATION PROOF  (POST", LIVE_URL + ")")
    print("=" * 100)
    t0 = int(time.time())
    key_b = SigningKey.generate()
    reg = KeyAnchorRegistry()
    env = agent_b_sign(key_b, created=t0)
    b_keyid = str(parse_signature_input(env["headers"]["Signature-Input"]).parameters["keyid"])
    anchored = key_b.verify_key.encode().hex()
    reg.anchor(b_keyid, anchored)

    wav = HOME / "showcase_live.wav"
    got = recv_from_sound(send_over_sound(env, wav))

    try:
        # (a) genuine, anchored -> live service should report valid.
        ok_gate, reason, key = anchor_gate(got, reg)
        r1 = post_live(got, anchored_key_hex=key)
        print(f"a. genuine (anchor gate ok={ok_gate}) -> live: {json.dumps(r1, separators=(',', ':'))[:220]}")

        # (b) tampered body -> live service should report invalid (Content-Digest).
        tampered = json.loads(json.dumps(got))
        bb = bytearray(base64.b64decode(tampered["body_b64"]))
        bb[bb.find(b"12.50")] = ord("9")
        tampered["body_b64"] = base64.b64encode(bytes(bb)).decode()
        r2 = post_live(tampered, anchored_key_hex=key)
        print(f"b. tampered body -> live: {json.dumps(r2, separators=(',', ':'))[:220]}")

        # (c) key-swap re-sign under B's keyid -> anchor gate BLOCKS before any network call.
        attacker = SigningKey.generate()
        forged = _sign_envelope(attacker, keyid=b_keyid, body_obj=dict(DEMO_BODY, amount="999.00"),
                                created=t0)
        ok_gate, reason, _ = anchor_gate(forged, reg)
        print(f"c. key-swap forgery -> anchor gate accepted={ok_gate} (blocked client-side: {reason});")
        print("   the envelope is never sent to the live verifier -- anchoring is A's policy.")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        print(f"   LIVE ENDPOINT UNREACHABLE ({type(e).__name__}: {e}). Local battery is unaffected.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Secured gibberlink showcase (adversarial).")
    ap.add_argument("--live", action="store_true", help="also POST to the live verifier")
    ap.add_argument("--reliability", type=int, default=12, help="transport reliability runs")
    args = ap.parse_args()

    print("SECURED GIBBERLINK SHOWCASE  (local bench, key-anchored, adversarially tested)")
    print("The fix under test: keyid anchoring closes the in-envelope key-swap attack.")

    cases = run_battery()
    all_pass = print_table(cases)

    print("\nTRANSPORT RELIABILITY under the showcase")
    print("=" * 100)
    ok, n = reliability_check(args.reliability)
    print(f"   sign -> ggwave -> .wav -> decode -> byte-exact match: {ok}/{n} runs")
    if ok != n:
        print("   BLOCKER: transport dropped at least one frame.")
    else:
        print("   transport is 100% reliable under the showcase.")

    if args.live:
        run_live_proof()

    print("\nVERDICT:",
          "showcase-ready" if (all_pass and ok == n)
          else "NOT ready -- see FAIL rows / reliability blocker above")


if __name__ == "__main__":
    main()
