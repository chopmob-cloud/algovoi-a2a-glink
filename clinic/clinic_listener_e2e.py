#!/usr/bin/env python3
"""End-to-end proof that the clinic listener is a REAL running endpoint, not a sim.

Starts the listener in-process, then a real agent: enrolls, signs a concrete broken /explain request as a
VAL envelope, POSTs it over HTTP, and verifies the clinic's SIGNED answer. Also proves an unenrolled agent
and a replayed envelope are rejected, and the audit chain is intact. Real Ed25519 signatures throughout."""
from __future__ import annotations
import base64, json, sys, threading, time, urllib.request, urllib.error
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clinic_listener as cl
from clinic_responder import _load_explain
from negotiation_gibberlink_demo import sign_envelope, verify_envelope
from nacl.signing import SigningKey

PORT = 8811


def make_broken_request() -> dict:
    _explain, sign_demo, _err = _load_explain()
    good = sign_demo({"method": "POST", "authority": "api.example.com", "path": "/v1/pay",
                      "body_b64": base64.b64encode(b'{"amount":10,"to":"acct_9"}').decode(),
                      "covered_components": ["@method", "@authority", "@path", "content-digest"],
                      "keyid": "builder-key"})
    sr = good["signed_request"]; pub = good["ephemeral_key"]["public_key_hex"]
    tampered = base64.b64encode(b'{"amount":9999,"to":"acct_9"}').decode()   # altered after signing
    return {"method": sr["method"], "authority": sr["authority"], "path": sr["path"],
            "scheme": sr["scheme"], "headers": sr["headers"], "body_b64": tampered, "public_key_hex": pub}


def post(env: dict):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/clinic", data=json.dumps(env).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main():
    clinic_sk = SigningKey.generate()
    visitor = SigningKey.generate(); vkid = "test-agent-1"
    clinic = cl.Clinic(clinic_sk, {vkid: visitor.verify_key.encode().hex()})
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), cl.make_handler(clinic))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    clinic_pub = {clinic.kid: clinic_sk.verify_key.encode().hex()}

    def verify_answer(resp):
        ok, why, body = verify_envelope(resp, anchored_peers=clinic_pub, expected_keyid=clinic.kid,
                                        now=int(time.time()))
        return ok, why, (body if ok else {})

    now = int(time.time())
    passes = []

    # 1. enrolled agent, concrete /explain -> served + valid signed answer with a real diagnosis
    inner = {"intent": "clinic_explain", "request": make_broken_request()}
    env = sign_envelope(visitor, vkid, authority="visiting-agent", body=json.dumps(inner).encode(), created=now)
    code, resp = post(env)
    ok, why, body = verify_answer(resp)
    ans = (body.get("answer") or {}) if ok else {}
    ex = ans.get("explain") or {}
    served_ok = (code == 200 and ok and body.get("status") == "served" and ex.get("valid") is False
                 and (ex.get("content_digest") or {}).get("match") is False)
    passes.append(("enrolled /explain served + signed answer + correct diagnosis", served_ok))
    print(f"1. enrolled /explain: http={code} clinic-sig={'OK' if ok else why} status={body.get('status')} "
          f"explain.valid={ex.get('valid')} digest_match={(ex.get('content_digest') or {}).get('match')}")

    # 2. unenrolled agent -> rejected
    stranger = SigningKey.generate()
    env2 = sign_envelope(stranger, "stranger-9", authority="visiting-agent",
                         body=json.dumps({"q": "hi"}).encode(), created=now)
    code2, resp2 = post(env2)
    ok2, _, body2 = verify_answer(resp2)
    rej2 = (code2 == 400 and ok2 and body2.get("status") == "rejected"
            and "unenrolled" in (body2.get("answer") or {}).get("error", ""))
    passes.append(("unenrolled agent rejected", rej2))
    print(f"2. unenrolled: http={code2} status={body2.get('status')} reason={(body2.get('answer') or {}).get('error')}")

    # 3. replay the same enrolled envelope -> rejected
    code3, resp3 = post(env)
    ok3, _, body3 = verify_answer(resp3)
    rej3 = (code3 == 400 and ok3 and body3.get("status") == "rejected"
            and "replay" in (body3.get("answer") or {}).get("error", ""))
    passes.append(("replayed envelope rejected", rej3))
    print(f"3. replay: http={code3} status={body3.get('status')} reason={(body3.get('answer') or {}).get('error')}")

    srv.shutdown()
    chain = clinic.audit.verify_chain()
    passes.append(("audit chain intact", chain))
    print(f"\naudit records={len(clinic.audit.records)} chain_intact={chain}")
    allok = all(p for _, p in passes)
    print("\n=== E2E RESULT ===")
    for name, p in passes:
        print(f"  {'PASS' if p else 'FAIL'} {name}")
    print(f"\n{'ALL PASS -- listener is a real running endpoint' if allok else 'FAILURES'}")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
