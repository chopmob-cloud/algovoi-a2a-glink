#!/usr/bin/env python3
"""negotiation_gibberlink_demo.py -- a REAL two-way agent negotiation over sound.

Two agents actually haggle. Agent A (buyer) and Agent B (seller) exchange signed
offers and counter-offers over gibberlink (ggwave) audio until they agree a price,
and every message is verified offline with AlgoVoi's shipped RFC 9421 verifier.

This goes past the one-way secured_gibberlink_demo in three ways that matter for a
negotiation:

  1. Two-way. Both parties sign with their OWN Ed25519 key and verify the other's
     messages. A conversation, not a broadcast.
  2. Anchored keys (the secure-usage rule, actually enforced). Before talking, each
     party pins the other's keyid -> public key out of band (a stand-in for a
     directory or prior handshake). On every message the receiver resolves the key
     from its ANCHORED table by keyid and verifies against THAT, never the key that
     arrived inside the envelope. So "signed by this key" becomes "signed by the
     party I already know", which is exactly what a negotiation needs.
  3. Transcript binding. Each message carries session_id + seq + prev_hash (a hash
     of the previous message) inside the signed body. That chains the whole haggle,
     so a message cannot be reordered, replayed into a later round, or spliced in
     from a different negotiation.

Honesty (same as the one-way bench): the "sound" is real ggwave audio written to and
read back from an in-memory buffer / .wav, a stand-in for a live speaker->microphone
hop. The security core (RFC 9421 signing base, Ed25519, Content-Digest, freshness,
tag) is the REAL shipped code. This is a bench, not a live channel to anyone.

Run:  python negotiation_gibberlink_demo.py
"""
from __future__ import annotations
import base64, hashlib, json, re, secrets, time
from pathlib import Path

# Shipped, published verifier -- pip install "algovoi-rfc9421-verifier==0.4.4"
from algovoi_rfc9421_verifier import (
    compute_content_digest, build_signing_base, verify_request,
)
from nacl.signing import SigningKey

# The sound stack (ggwave + the one-way bench) is OPTIONAL: the VAL-envelope crypto below (sign/verify/
# hash) needs only the RFC 9421 verifier + nacl, so a network listener can import this module WITHOUT
# ggwave. When ggwave is absent the sound helpers are unavailable (None); behaviour is identical when
# it is present.
try:
    import ggwave  # noqa: F401  (used via the sound helpers below)
    from secured_gibberlink_demo import send_over_sound, recv_from_sound, HOME
except Exception:  # noqa: BLE001
    ggwave = None
    send_over_sound = recv_from_sound = None
    HOME = Path.home() / ".algovoi" / "gibberlink"

TAG = "algovoi-negotiation-v1"          # protocol tag: scopes signatures to this negotiation protocol
TTL = 300                                # freshness window (seconds)


# ---------------------------------------------------------------------------
# Signing / verifying one envelope (shipped RFC 9421 core)
# ---------------------------------------------------------------------------
def sign_envelope(signing_key: SigningKey, keyid: str, *, authority: str,
                  body: bytes, created: int) -> dict:
    """Sign an agent message as an RFC 9421 VAL envelope (transport-agnostic)."""
    cd = compute_content_digest(body)                       # RFC 9530, binds the body
    expires = created + TTL
    # Ed25519 is deterministic, so deriving the nonce from (key, created) gave two DIFFERENT
    # messages signed in the same second an IDENTICAL nonce -- no per-message entropy at all.
    nonce = secrets.token_hex(8)
    covered = ["@method", "@authority", "@path", "content-digest"]
    params_raw = (
        '("@method" "@authority" "@path" "content-digest")'
        f';created={created};expires={expires};keyid="{keyid}";alg="ed25519"'
        f';nonce="{nonce}";tag="{TAG}"'
    )
    method, path = "POST", "/a2a/negotiate"
    signing_base = build_signing_base(
        covered, method=method, authority=authority, path=path, scheme="https",
        headers={"content-digest": cd}, parameters={},
        mode="rfc9421", signature_params_raw=params_raw,
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
        "headers": headers,
        "body_b64": base64.b64encode(body).decode(),
        "public_key_hex": signing_key.verify_key.encode().hex(),  # rides along, but is NOT trusted
        "keyid": keyid,
    }


def envelope_hash(env: dict) -> str:
    """A stable hash of a message: chains the transcript (prev_hash) and doubles as the
    per-message replay nonce in the clinic's verify_fn.

    Covers the signature AND the material it commits to. Hashing the Signature header alone
    left body_b64 outside the digest, so an envelope whose body had been swapped produced an
    IDENTICAL transcript hash. verify_envelope still rejected it on Content-Digest, but the
    chain itself carried no evidence of the swap -- a transcript should not be blind to it."""
    h = env.get("headers") or {}
    material = {"signature": h.get("Signature", ""),
                "signature_input": h.get("Signature-Input", ""),
                "content_digest": h.get("Content-Digest", ""),
                "body_b64": env.get("body_b64", ""), "keyid": env.get("keyid", ""),
                "method": env.get("method", ""), "authority": env.get("authority", ""),
                "path": env.get("path", "")}
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def compute_transcript_hash(envs: list) -> str:
    """Hash of an ordered list of messages: the whole exchange, bound into one digest."""
    return hashlib.sha256("".join(envelope_hash(e) for e in envs).encode()).hexdigest()


_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")


def check_transcript_commitment(body: dict, envs_seen: list, expected_intent: str = "accept"):
    """The receiver INDEPENDENTLY recomputes the transcript hash over what it actually
    saw and compares it to the hash the acceptance committed to. Without this, a signed
    'agreed_transcript_sha256' only proves the sender committed to SOME transcript, not
    the one the receiver witnessed.

    Self-defending: it enforces the message is the expected kind (an acceptance), that the
    commitment is a well-formed sha-256 hex digest, and that there is a real prior
    transcript to commit to, before it recomputes and compares. A caller cannot get a
    pass out of an empty, absent, or malformed commitment."""
    if body.get("intent") != expected_intent:
        return False, f"message intent {body.get('intent')!r} is not {expected_intent!r}; not an acceptance"
    claimed = body.get("agreed_transcript_sha256")
    if not isinstance(claimed, str) or not _SHA256_HEX.match(claimed):
        return False, "acceptance carries no well-formed sha-256 transcript commitment"
    if not envs_seen:
        return False, "no prior transcript to commit to; refusing an empty-transcript commitment"
    actual = compute_transcript_hash(envs_seen)
    if claimed != actual:
        return False, f"acceptance commits to transcript {claimed[:16]}... but receiver computed {actual[:16]}..."
    return True, "ok"


def verify_envelope(env: dict, *, anchored_peers: dict, expected_keyid: str, now: int):
    """Verify a received message. Resolves the key from the ANCHORED table by keyid,
    never from the envelope. Returns (ok, reason, body_dict_or_None)."""
    keyid = env.get("keyid")
    if keyid not in anchored_peers:
        return False, f"keyid {keyid!r} is not anchored (unknown party); refusing", None
    if keyid != expected_keyid:
        return False, f"keyid {keyid!r} is not the expected counterparty {expected_keyid!r}", None
    anchored_pub = anchored_peers[keyid]                    # the key we already trust
    try:
        body = base64.b64decode(env.get("body_b64") or "")
    except Exception:                                       # noqa: BLE001 -- reject, never raise
        return False, "bad body_b64", None
    res = verify_request(
        method=env["method"], authority=env["authority"], path=env["path"],
        headers=env["headers"], body=body, scheme=env.get("scheme", "https"),
        public_key=anchored_pub,                            # <-- anchored, not env["public_key_hex"]
        require_content_digest=True, expected_tag=TAG, require_tag=True,
        allowed_algorithms={"ed25519"}, now=now, max_age_seconds=TTL,
    )
    if not res.valid:
        return False, (res.errors[0] if res.errors else "signature verify failed"), None
    return True, "ok", json.loads(body)


def verify_envelope_selfasserted(env: dict, *, now: int):
    """Verify a VAL envelope against the SELF-ASSERTED key it carries (env['public_key_hex']).

    This proves the caller controls that key and that the signature covers the body
    (Content-Digest), the tag, the algorithm, and the freshness window, exactly like
    verify_envelope, EXCEPT the key is not anchored. It therefore confers NO TRUST: the
    identity is only 'whoever holds this key'. Used ONLY for the stateless /explain
    debugger, which diagnoses the caller's OWN request and never acts on their identity.
    Returns (ok, reason, body_dict_or_None)."""
    pub = env.get("public_key_hex")
    if not isinstance(pub, str) or not pub:
        return False, "no self-asserted public_key_hex", None
    try:
        body = base64.b64decode(env["body_b64"])
    except Exception:
        return False, "bad body_b64", None
    res = verify_request(
        method=env["method"], authority=env["authority"], path=env["path"],
        headers=env["headers"], body=body, scheme=env.get("scheme", "https"),
        public_key=pub, require_content_digest=True, expected_tag=TAG, require_tag=True,
        allowed_algorithms={"ed25519"}, now=now, max_age_seconds=TTL,
    )
    if not res.valid:
        return False, (res.errors[0] if res.errors else "signature verify failed"), None
    try:
        return True, "ok", json.loads(body)
    except Exception:
        return False, "body not json", None


def check_transcript(body: dict, *, session_id: str, expected_seq: int, expected_prev: str):
    """The negotiation-layer checks on top of a valid signature: right session,
    right position in the chain, chained to the exact previous message."""
    if body.get("session_id") != session_id:
        return False, f"wrong session_id (spliced from another negotiation): {body.get('session_id')!r}"
    if body.get("seq") != expected_seq:
        return False, f"out-of-order seq {body.get('seq')} (expected {expected_seq}); replay or reorder"
    if body.get("prev_hash") != expected_prev:
        return False, "prev_hash does not chain to the last message; transcript tampered or spliced"
    return True, "ok"


# ---------------------------------------------------------------------------
# The sound hop for one message: sign -> ggwave audio -> decode
# ---------------------------------------------------------------------------
def over_sound(env: dict, label: str) -> dict:
    wav = HOME / f"nego_{label}.wav"
    waveform = send_over_sound(env, wav)
    got = recv_from_sound(waveform)
    frames = len(waveform) // 4
    return got, frames


def money(x: float) -> str:
    return f"{x:.2f}"


# ---------------------------------------------------------------------------
# The negotiation
# ---------------------------------------------------------------------------
def main():
    t0 = int(time.time())
    line = lambda s="": print(s)
    rule = lambda: print("-" * 74)

    # --- Setup: keys + OUT-OF-BAND anchoring (the trusted handshake) ----------
    key_a = SigningKey.generate()
    key_b = SigningKey.generate()
    keyid_a = f"did:key:z-agentA-{key_a.verify_key.encode().hex()[:16]}"
    keyid_b = f"did:key:z-agentB-{key_b.verify_key.encode().hex()[:16]}"

    # Each side's anchored directory: keyid -> the public key it already trusts.
    # This is the "resolve the key out of band" step, done once, before talking.
    a_knows = {keyid_b: key_b.verify_key.encode().hex()}   # A trusts B's key
    b_knows = {keyid_a: key_a.verify_key.encode().hex()}   # B trusts A's key

    session_id = base64.b16encode(hashlib.sha256(f"{keyid_a}|{keyid_b}|{t0}".encode()).digest()[:8]).decode().lower()

    line("TWO-WAY SECURED GIBBERLINK NEGOTIATION  (local bench, real ggwave, offline verify)")
    line(f"Item under negotiation: 'API access, 1M calls'.  Session {session_id}")
    line(f"Agent A (buyer)  keyid {keyid_a}")
    line(f"Agent B (seller) keyid {keyid_b}")
    line("Keys anchored out of band before any message is sent (A knows B, B knows A).")
    rule()

    # --- Policy ---------------------------------------------------------------
    A_CEILING = 12.00     # buyer will not pay more than this
    B_FLOOR = 11.00       # seller will not accept less than this

    transcript = []       # every accepted envelope, in order
    last_hash = ""        # prev_hash for the next message
    seq = 0

    def emit(signing_key, keyid, authority, body_obj, label):
        nonlocal seq, last_hash
        body_obj = {"session_id": session_id, "seq": seq, "prev_hash": last_hash, **body_obj}
        env = sign_envelope(signing_key, keyid, authority=authority,
                            body=json.dumps(body_obj, separators=(",", ":")).encode(),
                            created=t0 + seq)     # each step a moment later
        got, frames = over_sound(env, label)
        return env, got, frames, body_obj

    def receive(got, *, anchored, expected_keyid, who):
        nonlocal seq, last_hash
        ok, reason, body = verify_envelope(got, anchored_peers=anchored,
                                           expected_keyid=expected_keyid, now=t0 + seq + 1)
        if not ok:
            line(f"   {who} REJECTS: {reason}")
            return None
        ok2, reason2 = check_transcript(body, session_id=session_id,
                                        expected_seq=seq, expected_prev=last_hash)
        if not ok2:
            line(f"   {who} REJECTS: {reason2}")
            return None
        transcript.append(got)
        last_hash = envelope_hash(got)
        seq += 1
        return body

    # --- Round 1: A opens with a low offer ------------------------------------
    offer_a = 8.00
    env, got, frames, _ = emit(key_a, keyid_a, "agent-a.local",
                               {"role": "buyer", "intent": "offer", "amount": money(offer_a),
                                "currency": "USDC", "item": "API access, 1M calls"}, "1_A_offer")
    line(f"1. A -> B  offer {money(offer_a)} USDC   ({frames} audio samples over sound)")
    body = receive(got, anchored=b_knows, expected_keyid=keyid_a, who="B")
    line(f"   B verifies A's signature against A's anchored key: OK. A offers {body['amount']}.")
    rule()

    # --- Round 2: B counters high ---------------------------------------------
    counter_b = 15.00
    env, got, frames, _ = emit(key_b, keyid_b, "agent-b.local",
                               {"role": "seller", "intent": "counter", "amount": money(counter_b),
                                "currency": "USDC", "item": "API access, 1M calls"}, "2_B_counter")
    line(f"2. B -> A  counter {money(counter_b)} USDC   ({frames} audio samples over sound)")
    body = receive(got, anchored=a_knows, expected_keyid=keyid_b, who="A")
    line(f"   A verifies B's signature against B's anchored key: OK. B counters {body['amount']}.")
    rule()

    # --- Round 3: A meets in the middle, within its ceiling -------------------
    counter_a = min(A_CEILING, round((offer_a + counter_b) / 2, 2))   # 11.50
    env, got, frames, _ = emit(key_a, keyid_a, "agent-a.local",
                               {"role": "buyer", "intent": "counter", "amount": money(counter_a),
                                "currency": "USDC", "item": "API access, 1M calls"}, "3_A_counter")
    line(f"3. A -> B  counter {money(counter_a)} USDC   ({frames} audio samples over sound)")
    body = receive(got, anchored=b_knows, expected_keyid=keyid_a, who="B")
    line(f"   B verifies: OK. A counters {body['amount']}. B's floor is {money(B_FLOOR)}.")
    rule()

    # --- Round 4: B accepts (A's counter clears the floor) --------------------
    assert counter_a >= B_FLOOR, "policy sanity: this run should converge"
    # B commits to the exact exchange so far (the three prior messages).
    agreed = compute_transcript_hash(transcript)
    env_accept, got, frames, accept_body = emit(
        key_b, keyid_b, "agent-b.local",
        {"role": "seller", "intent": "accept", "amount": money(counter_a),
         "currency": "USDC", "item": "API access, 1M calls",
         "agreed_transcript_sha256": agreed}, "4_B_accept")
    line(f"4. B -> A  ACCEPT {money(counter_a)} USDC   ({frames} audio samples over sound)")
    body = receive(got, anchored=a_knows, expected_keyid=keyid_b, who="A")
    # A independently recomputes the transcript hash over what IT saw (everything before
    # this acceptance) and checks that B committed to the same exchange.
    ok_c, reason_c = check_transcript_commitment(body, transcript[:-1])
    if not ok_c:
        line(f"   A REJECTS the acceptance: {reason_c}")
    else:
        line("   A verifies B's acceptance AND independently recomputes the transcript hash: match.")
        line(f"   DEAL: both agents now hold a signed agreement at {money(counter_a)} USDC.")
        line(f"   Agreement covers session {session_id}, {len(transcript)} signed messages, "
             f"transcript sha256 {agreed[:16]}...")
    rule()

    # --- Adversarial checks: what makes the negotiation trustworthy -----------
    line("ADVERSARIAL CHECKS (each MUST be rejected for the negotiation to mean anything):")

    # (a) Tamper the accepted price in transit.
    tampered = json.loads(json.dumps(got))
    tb = json.loads(base64.b64decode(tampered["body_b64"]))
    tb["amount"] = "5.00"                                   # attacker rewrites the deal price
    tampered["body_b64"] = base64.b64encode(json.dumps(tb, separators=(",", ":")).encode()).decode()
    ok, reason, _ = verify_envelope(tampered, anchored_peers=a_knows, expected_keyid=keyid_b, now=t0 + seq)
    line(f"  a) Tamper accepted price 11.50 -> 5.00 : rejected={not ok}  ({reason})")

    # (b) A forged acceptance signed by an UNANCHORED key (attacker posing as B).
    attacker = SigningKey.generate()
    forged = sign_envelope(attacker, "did:key:z-attacker-deadbeef", authority="agent-b.local",
                           body=json.dumps({"session_id": session_id, "seq": seq, "prev_hash": last_hash,
                                            "role": "seller", "intent": "accept", "amount": "5.00",
                                            "currency": "USDC"}, separators=(",", ":")).encode(),
                           created=t0 + seq)
    ok, reason, _ = verify_envelope(forged, anchored_peers=a_knows, expected_keyid=keyid_b, now=t0 + seq)
    line(f"  b) Forged 'B accepts 5.00' signed by an UNANCHORED key : rejected={not ok}  ({reason})")

    # (c) Replay A's round-1 opening offer back into the live chain.
    replay = transcript[0]                                   # A's 8.00 offer, seq 0
    ok, reason, body = verify_envelope(replay, anchored_peers=b_knows, expected_keyid=keyid_a, now=t0 + seq)
    ok2, reason2 = (True, "sig ok") if ok else (False, reason)
    if ok:
        ok3, reason3 = check_transcript(body, session_id=session_id, expected_seq=seq, expected_prev=last_hash)
        line(f"  c) Replay A's round-1 offer into round {seq} : rejected={not ok3}  ({reason3})")
    else:
        line(f"  c) Replay A's round-1 offer : rejected=True  ({reason})")

    # (d) Splice a message from a DIFFERENT session_id.
    other = json.loads(json.dumps(transcript[0]))
    ob = json.loads(base64.b64decode(other["body_b64"]))
    ob["session_id"] = "deadbeefdeadbeef"                    # different negotiation
    # re-sign so the signature is valid but the session is wrong
    other = sign_envelope(key_a, keyid_a, authority="agent-a.local",
                          body=json.dumps(ob, separators=(",", ":")).encode(), created=t0 + seq)
    ok, reason, body = verify_envelope(other, anchored_peers=b_knows, expected_keyid=keyid_a, now=t0 + seq)
    if ok:
        ok4, reason4 = check_transcript(body, session_id=session_id, expected_seq=seq, expected_prev=last_hash)
        line(f"  d) Splice a validly-signed message from another session : rejected={not ok4}  ({reason4})")
    else:
        line(f"  d) Splice from another session : rejected=True  ({reason})")

    # (e) A validly-signed acceptance that commits to the WRONG transcript hash.
    wrong_body = {"session_id": session_id, "seq": seq, "prev_hash": last_hash,
                  "role": "seller", "intent": "accept", "amount": money(counter_a),
                  "currency": "USDC", "agreed_transcript_sha256": "0" * 64}
    wrong_accept = sign_envelope(key_b, keyid_b, authority="agent-b.local",
                                 body=json.dumps(wrong_body, separators=(",", ":")).encode(),
                                 created=t0 + seq)
    okv, rv, bodyv = verify_envelope(wrong_accept, anchored_peers=a_knows, expected_keyid=keyid_b, now=t0 + seq)
    if okv:
        okc2, rc2 = check_transcript_commitment(bodyv, transcript[:-1])
        line(f"  e) Validly-SIGNED acceptance committing to a DIFFERENT transcript : rejected={not okc2}  ({rc2})")
    else:
        line(f"  e) Wrong-transcript acceptance : rejected=True  ({rv})")
    rule()

    line("SUMMARY: a real two-way negotiation ran end to end over ggwave sound. Each offer and")
    line("counter-offer was signed by its author's key and verified offline against a key the")
    line("other party had anchored in advance, so both sides know WHO they are dealing with, not")
    line("just that 'a key' signed. The transcript is chained (session + seq + prev_hash), so the")
    line("haggle cannot be reordered, replayed, forged by an unknown key, or spliced across")
    line("negotiations. The acceptance commits to a hash of the whole exchange, and the receiver")
    line("independently recomputes and checks that hash, so both agents hold a signed agreement")
    line("over the exact transcript, not just the final price.")


if __name__ == "__main__":
    main()
