#!/usr/bin/env python3
"""clinic_selftest.py -- prove a RUNNING clinic endpoint actually serves, from OUTSIDE the process.

Used against the deployed staging container: signs a concrete broken /explain request as a VAL envelope
with an enrolled staging-tester key, POSTs it to the live listener, and verifies the clinic's SIGNED answer
carries the correct diagnosis. Also checks an unenrolled peer and a replay are rejected. Real Ed25519.

Env:
  CLINIC_URL        default http://127.0.0.1:8799/clinic
  VISITOR_SK_HEX    seed hex of the ENROLLED staging-tester signing key (matches clinic_enrolled.json)
  VISITOR_KID       default 'staging-tester'
  CLINIC_KID        default 'algovoi-clinic'  (to verify the reply signature; needs CLINIC_PUB_HEX)
  CLINIC_PUB_HEX    clinic public key hex (optional; if unset, reply signature is not re-verified here)
"""
from __future__ import annotations
import base64, json, os, sys, time, urllib.request, urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from clinic_responder import _load_explain
from negotiation_gibberlink_demo import sign_envelope, verify_envelope
from nacl.signing import SigningKey

URL = os.environ.get("CLINIC_URL", "http://127.0.0.1:8799/clinic")
KID = os.environ.get("VISITOR_KID", "staging-tester")


def _post(env):
    req = urllib.request.Request(URL, data=json.dumps(env).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _broken_request():
    _explain, sign_demo, _err = _load_explain()
    good = sign_demo({"method": "POST", "authority": "api.example.com", "path": "/v1/pay",
                      "body_b64": base64.b64encode(b'{"amount":10,"to":"acct_9"}').decode(),
                      "covered_components": ["@method", "@authority", "@path", "content-digest"],
                      "keyid": "builder-key"})
    sr = good["signed_request"]; pub = good["ephemeral_key"]["public_key_hex"]
    tampered = base64.b64encode(b'{"amount":9999,"to":"acct_9"}').decode()
    return {"method": sr["method"], "authority": sr["authority"], "path": sr["path"],
            "scheme": sr["scheme"], "headers": sr["headers"], "body_b64": tampered, "public_key_hex": pub}


def main():
    sk_hex = os.environ.get("VISITOR_SK_HEX")
    pub_hex = os.environ.get("CLINIC_PUB_HEX")
    if not sk_hex or not pub_hex:
        print("VISITOR_SK_HEX and CLINIC_PUB_HEX required"); return 2
    visitor = SigningKey(bytes.fromhex(sk_hex))
    clinic_kid = os.environ.get("CLINIC_KID", "algovoi-clinic")
    now = int(time.time())
    passes = []

    def decode_reply(resp):
        """The listener returns the clinic's SIGNED envelope; verify it and return the inner
        {status, answer} body. Returns (sig_ok, body)."""
        ok, _why, body = verify_envelope(resp, anchored_peers={clinic_kid: pub_hex},
                                         expected_keyid=clinic_kid, now=now)
        return ok, (body if ok else {})

    # 1. enrolled concrete /explain -> served, signed reply, correct tamper diagnosis
    inner = {"intent": "clinic_explain", "request": _broken_request()}
    env = sign_envelope(visitor, KID, authority="visiting-agent", body=json.dumps(inner).encode(), created=now)
    code, resp = _post(env)
    sig_ok, body = decode_reply(resp)
    ex = (body.get("answer") or {}).get("explain") or {}
    served = (code == 200 and sig_ok and body.get("status") == "served"
              and ex.get("valid") is False and (ex.get("content_digest") or {}).get("match") is False)
    passes.append(("enrolled /explain served + signed reply + correct diagnosis", served))
    print(f"1. enrolled /explain: http={code} reply-sig={'OK' if sig_ok else 'BAD'} status={body.get('status')} "
          f"explain.valid={ex.get('valid')} digest_match={(ex.get('content_digest') or {}).get('match')}")

    # 2. unenrolled peer -> rejected
    stranger = SigningKey.generate()
    env2 = sign_envelope(stranger, "stranger-9", authority="visiting-agent",
                         body=json.dumps({"q": "hi"}).encode(), created=now)
    code2, resp2 = _post(env2)
    sig_ok2, body2 = decode_reply(resp2)
    rej2 = (code2 == 400 and sig_ok2 and body2.get("status") == "rejected"
            and "unenrolled" in (body2.get("answer") or {}).get("error", ""))
    passes.append(("unenrolled peer rejected", rej2))
    print(f"2. unenrolled: http={code2} status={body2.get('status')} reason={(body2.get('answer') or {}).get('error')}")

    # 3. replay envelope 1 -> rejected
    code3, resp3 = _post(env)
    sig_ok3, body3 = decode_reply(resp3)
    rej3 = (code3 == 400 and sig_ok3 and body3.get("status") == "rejected"
            and "replay" in (body3.get("answer") or {}).get("error", ""))
    passes.append(("replayed envelope rejected", rej3))
    print(f"3. replay: http={code3} status={body3.get('status')} reason={(body3.get('answer') or {}).get('error')}")

    allok = all(p for _, p in passes)
    print("\n=== SELFTEST ===")
    for n, p in passes:
        print(f"  {'PASS' if p else 'FAIL'} {n}")
    print("ALL PASS -- deployed clinic serves signed round-trips" if allok else "FAILURES")
    return 0 if allok else 1


if __name__ == "__main__":
    raise SystemExit(main())
