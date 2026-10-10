"""VAL envelope sign/verify: the RFC 9421 security core for gibberlink (transport-agnostic).

Extracted from algovoi-a2a-glink/clinic/negotiation_gibberlink_demo.py. Identity/integrity
live here, not in the audio codec: the same signed envelope verifies identically over HTTP
or gibberlink. verify_envelope() anchors the key by keyid (TRUST); verify_envelope_selfasserted()
checks the carried key (INTEGRITY only, no trust). Uses the published algovoi-rfc9421-verifier."""
from __future__ import annotations
import base64, hashlib, json, re, secrets

from algovoi_rfc9421_verifier import (
    compute_content_digest, build_signing_base, verify_request,
)
from nacl.signing import SigningKey

TAG = "algovoi-negotiation-v1"          # protocol tag: scopes signatures to this protocol
TTL = 300                                # freshness window (seconds)


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
