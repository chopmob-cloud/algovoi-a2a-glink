"""verifier_tool.py -- the offline RFC 9421 verify logic, transport-free so it can be
unit-tested and reused by both the HTTP app and an MCP tool. No gateway, no network:
this container verifies signed agent messages OFFLINE with the shipped verifier.
"""
from __future__ import annotations
import base64
import time
from typing import Any

from algovoi_rfc9421_verifier import (
    verify_request, build_signing_base, compute_content_digest,
    parse_signature_input, __version__ as VERIFIER_VERSION,
)


class VerifyToolError(ValueError):
    """Bad request shape (caller error), distinct from a verification failure."""


def _decode_pubkey(payload: dict) -> str:
    """Return the signer public key as hex. Accept either raw hex or a did:key.
    We NEVER trust a key carried inside the signed envelope -- the caller states
    which key they expect (that is the whole anchoring model)."""
    pk = payload.get("public_key_hex") or payload.get("public_key")
    if pk:
        return pk.strip()
    did = payload.get("did_key") or payload.get("keyid_did")
    if did and did.startswith("did:key:"):
        try:
            # lazy import: only needed for the did:key convenience path
            from algovoi_rfc9421_verifier import decode_did_key  # type: ignore
            return decode_did_key(did)
        except Exception as e:  # noqa: BLE001
            raise VerifyToolError(f"could not decode did:key: {e}") from e
    raise VerifyToolError(
        "supply the signer key you expect: 'public_key_hex' (32-byte Ed25519 hex) or 'did_key'"
    )


def verify_rfc9421(payload: dict) -> dict[str, Any]:
    """Verify one RFC 9421 signed HTTP message envelope offline.

    Expected payload (the VAL-envelope shape):
      method, authority, path, scheme, headers{Signature-Input, Signature, Content-Digest},
      body_b64  (base64 of the raw body),
      public_key_hex | did_key  (the key the caller EXPECTS -- anchoring, not the envelope's),
      optional: require_content_digest(bool, default true), expected_tag(str),
                allowed_algorithms(list, default ["ed25519"]), max_age_seconds(int), now(int).
    Returns {valid, errors, verifier_version, checked}.
    """
    if not isinstance(payload, dict):
        raise VerifyToolError("payload must be a JSON object")
    for req in ("method", "authority", "path", "headers", "body_b64"):
        if req not in payload:
            raise VerifyToolError(f"missing required field: {req}")
    public_key = _decode_pubkey(payload)
    try:
        body = base64.b64decode(payload["body_b64"], validate=True)
    except Exception as e:  # noqa: BLE001
        raise VerifyToolError(f"body_b64 is not valid base64: {e}") from e

    # M1: pin to a hard server-side safe-algorithm set; the caller may only
    # restrict further, never widen to an unsafe algorithm (hmac, rsa-pkcs1v15…).
    _SAFE_ALGORITHMS = frozenset({"ed25519"})
    caller_algs = {a.lower() for a in (payload.get("allowed_algorithms") or ["ed25519"])}
    allowed_algorithms = caller_algs & _SAFE_ALGORITHMS
    if not allowed_algorithms:
        raise VerifyToolError(
            f"allowed_algorithms must be a subset of {sorted(_SAFE_ALGORITHMS)}; "
            f"got {sorted(caller_algs)}"
        )

    kwargs: dict[str, Any] = dict(
        method=payload["method"],
        authority=payload["authority"],
        path=payload["path"],
        headers=payload["headers"],
        body=body,
        scheme=payload.get("scheme", "https"),
        public_key=public_key,
        require_content_digest=bool(payload.get("require_content_digest", True)),
        allowed_algorithms=allowed_algorithms,
    )
    if payload.get("expected_tag"):
        kwargs["expected_tag"] = payload["expected_tag"]
        kwargs["require_tag"] = True
    # M2: ignore caller-supplied `now` — always use real wall-clock time so the
    # caller cannot bypass freshness by injecting a future or far-past timestamp.
    # Cap max_age_seconds at 1 h so a caller cannot open an arbitrarily wide window.
    _MAX_AGE_CAP = 3600
    if payload.get("max_age_seconds") is not None:
        kwargs["max_age_seconds"] = min(int(payload["max_age_seconds"]), _MAX_AGE_CAP)

    res = verify_request(**kwargs)
    return {
        "valid": bool(res.valid),
        "errors": list(res.errors or []),
        "verifier_version": VERIFIER_VERSION,
        "checked": {
            "content_digest": kwargs["require_content_digest"],
            "algorithms": sorted(kwargs["allowed_algorithms"]),
            "tag_enforced": bool(payload.get("expected_tag")),
            "freshness_enforced": kwargs.get("max_age_seconds") is not None,
        },
    }


def _diagnose(valid: bool, errors: list, cd_match: bool | None) -> list[str]:
    """Turn a pass/fail into human 'why + how to fix' notes -- the whole point of /explain."""
    if valid:
        return ["Signature is VALID. The bytes in 'signature_base' below are exactly what was signed; "
                "if your own library computes a different base, that string is your reference."]
    notes = []
    joined = " ".join(errors).lower()
    if cd_match is False or "content-digest" in joined or "digest" in joined:
        notes.append("Content-Digest mismatch: the body does not hash to the Content-Digest header. "
                     "Re-run compute_content_digest(raw_body) and re-sign -- a common cause is signing a "
                     "different byte encoding of the body than you send.")
    if "signature" in joined and ("verify" in joined or "does not" in joined or "invalid" in joined):
        notes.append("Ed25519 signature does not match the recomputed signing base. Your library almost "
                     "certainly built a DIFFERENT canonical base -- compare yours byte-for-byte against "
                     "'signature_base' below (usual culprits: component order, missing @authority/@path, "
                     "quoting, or trailing whitespace).")
    if "alg" in joined:
        notes.append("Algorithm problem: include alg=\"ed25519\" in Signature-Input and use an Ed25519 key.")
    if "expire" in joined or "created" in joined or "fresh" in joined or "age" in joined:
        notes.append("Freshness failed: check created/expires and clock skew between signer and verifier.")
    if "keyid" in joined:
        notes.append("keyid issue: the keyid in Signature-Input must resolve to the public key you expect.")
    if not notes:
        notes.append("See 'errors'. Compare your canonical base against 'signature_base' below.")
    return notes


def sign_rfc9421_demo(payload: dict) -> dict:
    """Known-good SIGNER / playground: give raw request inputs, get a correctly-signed request +
    the signing base + an explain view. NEVER accepts a private key -- it signs with a FRESH
    EPHEMERAL demo key and returns it, so builders diff their own pipeline against a reference
    without ever sending us a secret. The inverse of /explain; the AIs' #1 'ship next'."""
    from nacl.signing import SigningKey  # lazy: only the signer path needs it

    if any(k in payload for k in ("private_key", "private_key_hex", "secret_key", "seed", "seed_hex")):
        raise VerifyToolError(
            "do not send a private key. This playground signs with a fresh EPHEMERAL demo key and returns "
            "it; in production sign with your own key locally, never over the wire.")
    for req in ("method", "authority", "path"):
        if req not in payload:
            raise VerifyToolError(f"missing required field: {req}")
    try:
        body = base64.b64decode(payload["body_b64"], validate=True) if payload.get("body_b64") else b""
    except Exception as e:  # noqa: BLE001
        raise VerifyToolError(f"body_b64 is not valid base64: {e}") from e

    covered = payload.get("covered_components") or ["@method", "@authority", "@path", "content-digest"]
    keyid = str(payload.get("keyid", "demo-key"))
    created = int(payload.get("now", time.time())); expires = created + int(payload.get("ttl", 300))
    sk = SigningKey.generate()
    headers = {str(k): str(v) for k, v in (payload.get("headers") or {}).items()}
    if any(c.lower() == "content-digest" for c in covered):
        headers["Content-Digest"] = compute_content_digest(body)

    comp_str = " ".join(f'"{c}"' for c in covered)
    params = f'({comp_str});created={created};expires={expires};keyid="{keyid}";alg="ed25519"'
    if payload.get("tag"):
        params += f';tag="{payload["tag"]}"'
    base = build_signing_base(covered, method=payload["method"], authority=payload["authority"],
                              path=payload["path"], scheme=payload.get("scheme", "https"),
                              headers={k.lower(): v for k, v in headers.items()}, parameters={},
                              mode="rfc9421", signature_params_raw=params)
    sig = base64.standard_b64encode(sk.sign(base.encode()).signature).decode()
    headers["Signature-Input"] = f"sig1={params}"
    headers["Signature"] = f"sig1=:{sig}:"
    return {
        "signed_request": {"method": payload["method"], "authority": payload["authority"],
                           "path": payload["path"], "scheme": payload.get("scheme", "https"),
                           "headers": headers, "body_b64": base64.b64encode(body).decode()},
        "signature_base": base,
        "ephemeral_key": {
            "public_key_hex": sk.verify_key.encode().hex(),
            "private_key_hex": sk.encode().hex(),
            "note": "EPHEMERAL DEMO KEY — verify the request above with public_key_hex, or diff your own "
                    "signer's output against 'signature_base'. Do NOT use this key in production.",
        },
        "verifier_version": VERIFIER_VERSION,
    }


def _vis(s: str) -> str:
    """Make whitespace visible so a diff shows the real culprit."""
    return s.replace(" ", "·").replace("\t", "→")


def _diff_signing_base(expected: str, provided: str) -> dict:
    """Byte/char-level diff of the caller's own signing base against the canonical one.
    Where 80-90% of RFC 9421 bugs hide: whitespace, casing, component order, trailing chars."""
    if expected == provided:
        return {"match": True, "lines": []}
    exp, got = expected.split("\n"), provided.split("\n")
    lines = []
    for i in range(max(len(exp), len(got))):
        e = exp[i] if i < len(exp) else None
        g = got[i] if i < len(got) else None
        if e == g:
            continue
        entry = {"line": i + 1,
                 "expected": _vis(e) if e is not None else "(missing line)",
                 "yours": _vis(g) if g is not None else "(missing line)"}
        if e is not None and g is not None:
            col = next((c for c in range(min(len(e), len(g))) if e[c] != g[c]), None)
            if col is not None:
                entry["first_diff_col"] = col + 1
                entry["hint"] = f"col {col + 1}: expected {e[col]!r}, you have {g[col]!r}"
            else:
                entry["hint"] = "prefix matches but lengths differ (trailing whitespace or extra chars)"
        lines.append(entry)
    return {"match": False, "lines": lines}


def explain_rfc9421(payload: dict) -> dict:
    """Verify a signed message AND explain WHY it passed/failed -- the free debugger builders asked for.
    Returns the exact canonical signing base (the bytes that must be signed), the covered components and
    signature params, a Content-Digest recomputation, and human 'how to fix' notes. Same input shape as
    verify_rfc9421."""
    if not isinstance(payload, dict):
        raise VerifyToolError("payload must be a JSON object")
    for req in ("method", "authority", "path", "headers", "body_b64"):
        if req not in payload:
            raise VerifyToolError(f"missing required field: {req}")
    headers = payload["headers"]
    lc = {str(k).lower(): v for k, v in headers.items()}
    sig_input = lc.get("signature-input")
    if not sig_input:
        raise VerifyToolError("no Signature-Input header to explain")
    try:
        parsed = parse_signature_input(sig_input)
    except Exception as e:  # noqa: BLE001
        raise VerifyToolError(f"could not parse Signature-Input: {e}") from e

    try:
        body = base64.b64decode(payload["body_b64"], validate=True)
    except Exception as e:  # noqa: BLE001
        raise VerifyToolError(f"body_b64 is not valid base64: {e}") from e

    # reconstruct the canonical signing base (the reference bytes)
    signing_base = None; base_err = None
    try:
        signing_base = build_signing_base(
            parsed.covered_components,
            method=payload["method"], authority=payload["authority"], path=payload["path"],
            scheme=payload.get("scheme", "https"), headers=lc, parameters=parsed.parameters,
            mode="rfc9421", signature_params_raw=parsed.params_block,
        )
    except Exception as e:  # noqa: BLE001
        base_err = str(e)

    # Content-Digest recomputation
    cd_header = lc.get("content-digest")
    cd_match = None; cd_recomputed = None
    if cd_header is not None:
        try:
            cd_recomputed = compute_content_digest(body)
            cd_match = (cd_recomputed == cd_header)
        except Exception:  # noqa: BLE001
            pass

    # verify (only if a key was supplied; the base + params are still explained without one)
    valid, errors = None, []
    try:
        public_key = _decode_pubkey(payload)
        _caller_algs = {a.lower() for a in (payload.get("allowed_algorithms") or ["ed25519"])}
        _safe_algs = frozenset({"ed25519"})
        _algs = (_caller_algs & _safe_algs) or _safe_algs
        res = verify_request(method=payload["method"], authority=payload["authority"],
                             path=payload["path"], headers=headers, body=body,
                             scheme=payload.get("scheme", "https"), public_key=public_key,
                             require_content_digest=bool(payload.get("require_content_digest", True)),
                             allowed_algorithms=_algs)
        valid, errors = bool(res.valid), list(res.errors or [])
    except VerifyToolError:
        errors = ["no public_key_hex/did_key supplied: showing the signing base + params only, not a verdict"]

    # DIFF MODE: if the builder pastes THEIR OWN reconstructed signing base, show the exact
    # divergence against ours -- the #1 requested feature (80-90% of bugs hide here).
    client_base = (payload.get("your_signing_base") or payload.get("client_base")
                   or payload.get("computed_base"))
    base_diff = _diff_signing_base(signing_base, client_base) if (client_base and signing_base) else None

    diagnosis = _diagnose(bool(valid), errors, cd_match)
    if base_diff and not base_diff["match"]:
        diagnosis.insert(0, f"Your signing base differs from ours at {len(base_diff['lines'])} line(s) — "
                            "see base_diff below; that divergence is almost certainly why verification fails.")
    elif base_diff and base_diff["match"]:
        diagnosis.insert(0, "Your signing base matches ours byte-for-byte — the base is correct; "
                            "look at the key, algorithm, or the signature bytes instead.")

    return {
        "valid": valid,
        "errors": errors,
        "signature_base": signing_base,
        "signing_base_error": base_err,
        "base_diff": base_diff,
        "covered_components": parsed.covered_components,
        "signature_params": parsed.parameters,
        "content_digest": {"header": cd_header, "recomputed": cd_recomputed, "match": cd_match},
        "diagnosis": diagnosis,
        "verifier_version": VERIFIER_VERSION,
    }
