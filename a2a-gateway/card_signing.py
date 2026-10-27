#!/usr/bin/env python3
"""card_signing.py -- sign and verify an A2A Agent Card (A2A v1.0 section 8.4).

An A2A AgentCard signature is a DETACHED JWS (RFC 7515) over the RFC 8785 (JCS)
canonicalization of the card with (a) the `signatures` field excluded and
(b) default-valued properties removed (proto3 semantics). The signature covers
`ASCII(BASE64URL(protected) + "." + BASE64URL(payload))`; the payload is NOT
embedded, the verifier reconstructs it from the card.

We sign with Ed25519 (`alg: "EdDSA"`) and embed the public key as a `jwk` in the
protected header so the card is self-verifiable OFFLINE. As always with a
self-asserted key, that proves integrity and key-of-signing, not identity: the
key should still be anchored out of band (the same trust model as the clinic).

The private key is NEVER stored here; it is supplied at runtime (a 32-byte
Ed25519 seed as hex). With no key the card is simply served unsigned.
"""
from __future__ import annotations
import base64
import json

import rfc8785
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _strip_defaults(x):
    """Remove proto3 default-valued properties recursively: null, false, 0, "",
    empty array, empty object. A fully-emptied object is dropped by its parent."""
    if isinstance(x, dict):
        out = {}
        for k, v in x.items():
            v = _strip_defaults(v)
            if v is None or v is False or v == "" or v == [] or v == {} or v == 0:
                continue
            out[k] = v
        return out
    if isinstance(x, list):
        return [_strip_defaults(v) for v in x]
    return x


def canonical_payload(card: dict) -> bytes:
    """The exact bytes that get signed: card minus `signatures`, defaults removed,
    then RFC 8785 (JCS) canonicalized."""
    trimmed = {k: v for k, v in card.items() if k != "signatures"}
    return rfc8785.dumps(_strip_defaults(trimmed))


def sign_card(card: dict, seed_hex: str, kid: str = "algovoi-agent-ed25519-v1") -> dict:
    """Return one AgentCardSignature {protected, signature} for `card`. Ed25519.
    The protected header carries alg/typ/kid plus the public key as an OKP jwk."""
    # M3: validate seed is exactly 32 bytes before handing to PyNaCl; a short seed
    # is silently zero-padded by some implementations which produces a weak key.
    seed_bytes = bytes.fromhex(seed_hex)
    if len(seed_bytes) != 32:
        raise ValueError(f"Ed25519 seed must be exactly 32 bytes, got {len(seed_bytes)}")
    sk = SigningKey(seed_bytes)
    pub = sk.verify_key.encode()
    protected = {"alg": "EdDSA", "typ": "JOSE", "kid": kid,
                 "jwk": {"kty": "OKP", "crv": "Ed25519", "x": _b64u(pub)}}
    protected_b64 = _b64u(rfc8785.dumps(protected))
    payload_b64 = _b64u(canonical_payload(card))
    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
    sig = sk.sign(signing_input).signature
    return {"protected": protected_b64, "signature": _b64u(sig)}


def verify_card(card: dict, trusted_pub_hex: str | None = None) -> list[dict]:
    """Verify every entry in card['signatures']. For each, reconstruct the signing
    input from the card and check the detached signature. If `trusted_pub_hex` is
    given the signature must be by THAT key (anchored); otherwise the embedded jwk
    is used (self-asserted, integrity only). Returns a verdict per signature."""
    payload_b64 = _b64u(canonical_payload(card))
    verdicts = []
    for s in (card.get("signatures") or []):
        try:
            protected = json.loads(_b64u_dec(s["protected"]))
            jwk = protected.get("jwk") or {}
            emb = _b64u_dec(jwk["x"]) if jwk.get("kty") == "OKP" else None
            pub = bytes.fromhex(trusted_pub_hex) if trusted_pub_hex else emb
            if pub is None:
                verdicts.append({"kid": protected.get("kid"), "valid": False,
                                 "reason": "no key (no anchored key and no embedded jwk)"})
                continue
            anchored = trusted_pub_hex is not None and emb is not None and bytes(pub) == bytes(emb)
            signing_input = (s["protected"] + "." + payload_b64).encode("ascii")
            VerifyKey(pub).verify(signing_input, _b64u_dec(s["signature"]))
            verdicts.append({"kid": protected.get("kid"), "alg": protected.get("alg"),
                             "valid": True,
                             "trust": "anchored" if trusted_pub_hex else "self-asserted (embedded jwk)",
                             "anchored_matches_embedded": anchored if trusted_pub_hex else None})
        except (BadSignatureError, KeyError, ValueError) as e:
            verdicts.append({"valid": False, "reason": type(e).__name__ + ": " + str(e)})
    return verdicts
