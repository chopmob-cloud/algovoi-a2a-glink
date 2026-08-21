#!/usr/bin/env python3
"""gibberlink_client.py -- the ambassador's OUTBOUND native gibberlink (ggwave audio) client.

Gives the ambassador the second transport: as well as HTTP A2A message/send, it can now speak
NATIVE gibberlink to any peer that exposes a gibberlink endpoint (our clinic does). It reuses the
EXACT same ggwave codec + VAL sign/verify the clinic uses, so the two are wire-compatible by
construction (no re-implementation, no drift):

  enroll(base, sk, keyid)              -> self-signed VAL {intent:'clinic_enroll'} over HTTP (proves key control)
  exchange(base, sk, keyid, inner, ..) -> VAL envelope -> REAL ggwave audio -> POST /clinic/gibberlink
                                          -> decode the signed audio reply -> verify the peer's signature

Public data only; the reply signature is verified against the peer's anchored key when provided.
"""
from __future__ import annotations
import base64, json, re, sys, time, urllib.request, urllib.error
from pathlib import Path

# Reuse the clinic's own gibberlink codec + VAL helpers (single source of truth, wire-compatible).
# The clinic/ tree ships ALONGSIDE this file; import the codec from there.
GIBBERLINK_DIR = Path(__file__).resolve().parent.parent / "clinic"
sys.path.insert(0, str(GIBBERLINK_DIR))
import clinic_gibberlink as _gl                                   # noqa: E402  native ggwave codec (requires ggwave)
from negotiation_gibberlink_demo import sign_envelope, verify_envelope  # noqa: E402

ENROLL_TIMEOUT = 30
AUDIO_TIMEOUT = 180
DEFAULT_CLINIC_KID = "algovoi-clinic"


class GibberlinkError(Exception):
    pass


def fetch_clinic_pubkey(base_url: str) -> dict | None:
    """Fetch the peer clinic's agent-card over TLS and return its published signing key
    {keyid, public_key_hex, anchorable} if present and WELL-FORMED, else None. This is the
    OUT-OF-BAND anchor: the key's provenance is the card served from the peer's own domain
    (TLS-authenticated), not the audio reply we are trying to verify. Only anchor when anchorable
    is true (stable key).

    Hardened: anchoring trust requires HTTPS (a plain-HTTP base could be tampered
    on the wire), except loopback for local testing; and the key must be a valid Ed25519 identity
    (alg=ed25519, non-empty keyid, exactly 32-byte / 64-hex public key) before we anchor it."""
    base = base_url.rstrip("/")
    scheme = base.split("://", 1)[0].lower() if "://" in base else ""
    host = base.split("://", 1)[1].split("/")[0].split(":")[0].lower() if "://" in base else ""
    if scheme != "https" and host not in ("127.0.0.1", "localhost", "::1"):
        return None                                   # refuse to anchor a key learned over plain HTTP
    for path in ("/clinic/agent-card.json", "/.well-known/agent-card.json"):
        req = urllib.request.Request(base + path, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=ENROLL_TIMEOUT) as r:
                card = json.loads(r.read(1_000_000))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError):
            continue
        sig = card.get("signing") if isinstance(card, dict) else None
        if not isinstance(sig, dict):
            continue
        pub = sig.get("public_key_hex"); kid = sig.get("keyid")
        alg = str(sig.get("alg") or "").lower()
        if alg == "ed25519" and kid and isinstance(pub, str) and re.fullmatch(r"[0-9a-fA-F]{64}", pub):
            return {"keyid": kid, "public_key_hex": pub.lower(), "anchorable": bool(sig.get("anchorable"))}
    return None


def enroll(base_url: str, sk, keyid: str, *, authority: str = "algovoi-ambassador") -> dict:
    """Self-enroll with a gibberlink peer (proof-of-key-control). Returns the parsed JSON result."""
    body = json.dumps({"intent": "clinic_enroll"}).encode()
    env = sign_envelope(sk, keyid, authority=authority, body=body, created=int(time.time()))
    req = urllib.request.Request(base_url.rstrip("/") + "/clinic/enroll",
                                 data=json.dumps(env).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=ENROLL_TIMEOUT) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            raise GibberlinkError(f"enroll HTTP {e.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise GibberlinkError(f"enroll unreachable: {getattr(e, 'reason', e)}")


def exchange(base_url: str, sk, keyid: str, inner: dict, *, authority: str = "algovoi-ambassador",
             peer_pubkey_hex: str | None = None, peer_kid: str = DEFAULT_CLINIC_KID) -> dict:
    """One native gibberlink exchange: sign a VAL envelope carrying `inner`, encode to REAL ggwave
    audio, POST it to the peer's /clinic/gibberlink, decode the signed audio reply, and (when the
    peer's key is known) verify the reply signature. Returns a structured result dict."""
    env = sign_envelope(sk, keyid, authority=authority, body=json.dumps(inner).encode(),
                        created=int(time.time()))
    wave = _gl.envelope_to_waveform(env)                          # REAL ggwave float32 audio
    req = urllib.request.Request(base_url.rstrip("/") + "/clinic/gibberlink", data=wave,
                                 headers={"Content-Type": "application/octet-stream"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=AUDIO_TIMEOUT) as r:
            http_status, reply_audio = r.status, r.read()
    except urllib.error.HTTPError as e:
        http_status, reply_audio = e.code, e.read()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "reached": False, "error": f"unreachable: {getattr(e, 'reason', e)}"}
    rtt = time.time() - t0

    # A busy/oversized/error response may be small JSON, not audio -- surface it honestly.
    if reply_audio[:1] == b"{":
        try:
            return {"ok": False, "reached": True, "http_status": http_status,
                    "audio_in": len(wave), "rtt": rtt, "peer_json": json.loads(reply_audio)}
        except Exception:
            pass
    try:
        reply_env = _gl.waveform_to_envelope(reply_audio)         # audio -> signed reply envelope
    except Exception as e:
        return {"ok": False, "reached": True, "http_status": http_status, "audio_in": len(wave),
                "audio_out": len(reply_audio), "rtt": rtt, "error": f"reply decode failed: {e}"}

    # The reply body is readable from the envelope regardless of signature anchoring; decode it
    # first, then (optionally) verify the signature against the peer's anchored key.
    body = None
    try:
        body = json.loads(base64.b64decode(reply_env.get("body_b64", "")))
    except Exception:
        body = None
    sig_ok, why = (None, "peer key not provided (reply signature unverified)")
    if peer_pubkey_hex:
        sig_ok, why, vbody = verify_envelope(reply_env, anchored_peers={peer_kid: peer_pubkey_hex},
                                             expected_keyid=peer_kid, now=int(time.time()))
        if sig_ok and isinstance(vbody, dict):
            body = vbody
    answer = (body or {}).get("answer") if isinstance(body, dict) else None
    status = (body or {}).get("status") if isinstance(body, dict) else None
    return {"ok": True, "reached": True, "http_status": http_status, "audio_in": len(wave),
            "audio_out": len(reply_audio), "rtt": rtt, "sig_verified": sig_ok, "sig_note": why,
            "status": status, "answer": answer, "reply_envelope": reply_env}
