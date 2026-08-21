#!/usr/bin/env python3
"""clinic_gibberlink_e2e.py -- end-to-end proof that NATIVE gibberlink (ggwave audio) is REAL.

Unlike clinic_listener_e2e.py (HTTP-JSON path), this drives the actual audio transport through the
running listener: a real agent SELF-ENROLLS, then encodes a concrete broken /explain request as a real
ggwave float32 waveform, POSTs that AUDIO to /clinic/gibberlink, and decodes + verifies the clinic's
SIGNED audio reply. Also proves the audio path is enrolled-only and admission-controlled (503 when busy).
Real ggwave codec + real Ed25519 signatures throughout -- no simulation.

Proves:
  1. self-enroll over HTTP, then a native ggwave AUDIO exchange returns a signed, correct diagnosis
  2. an UNENROLLED agent's audio is decoded but rejected (enrolled-only), reply still signed
  3. admission control: when the single decode slot is taken, a new audio POST gets 503 (no decode)
  4. the hash-chained audit survives the whole exchange
"""
from __future__ import annotations
import base64, json, sys, threading, time, urllib.request, urllib.error
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import NamedTemporaryFile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clinic_listener as cl
import clinic_gibberlink as gl                       # native ggwave codec (requires ggwave)
from clinic_responder import _load_explain
from negotiation_gibberlink_demo import sign_envelope, verify_envelope
from nacl.signing import SigningKey

PORT = 8813


def make_broken_request() -> dict:
    """A signed request whose body was altered after signing (Content-Digest must fail)."""
    _explain, sign_demo, _err = _load_explain()
    good = sign_demo({"method": "POST", "authority": "api.example.com", "path": "/v1/pay",
                      "body_b64": base64.b64encode(b'{"amount":10,"to":"acct_9"}').decode(),
                      "covered_components": ["@method", "@authority", "@path", "content-digest"],
                      "keyid": "builder-key"})
    sr = good["signed_request"]; pub = good["ephemeral_key"]["public_key_hex"]
    tampered = base64.b64encode(b'{"amount":9999,"to":"acct_9"}').decode()
    return {"method": sr["method"], "authority": sr["authority"], "path": sr["path"],
            "scheme": sr["scheme"], "headers": sr["headers"], "body_b64": tampered, "public_key_hex": pub}


def post_json(path: str, env: dict):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=json.dumps(env).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def post_audio(waveform: bytes):
    """POST a raw ggwave waveform to the native gibberlink endpoint. Returns (http_status, raw_bytes)."""
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/clinic/gibberlink", data=waveform,
                                 headers={"Content-Type": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main():
    clinic_sk = SigningKey.generate()
    enroll_store = NamedTemporaryFile(prefix="gl_enroll_", suffix=".jsonl", delete=False).name
    # NO anchored peers: the agent must self-enroll to reach the enrolled-only audio path.
    clinic = cl.Clinic(clinic_sk, {}, open_explain=True, gibberlink_enabled=True,
                       enroll_store=enroll_store)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), cl.make_handler(clinic))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    clinic_pub = {clinic.kid: clinic_sk.verify_key.encode().hex()}
    now = int(time.time())
    passes = []

    def verify_reply_audio(audio: bytes):
        env = gl.waveform_to_envelope(audio)                       # audio -> signed reply envelope
        ok, why, body = verify_envelope(env, anchored_peers=clinic_pub, expected_keyid=clinic.kid,
                                        now=int(time.time()))
        return ok, why, (body if ok else {})

    # --- 1. self-enroll, then a native AUDIO /explain exchange ------------------------------
    agent = SigningKey.generate(); akid = "gl-agent-1"
    enroll_env = sign_envelope(agent, akid, authority="visiting-agent",
                               body=json.dumps({"intent": "clinic_enroll"}).encode(), created=now)
    ecode, ebody = post_json("/clinic/enroll", enroll_env)
    enrolled = json.loads(ebody)
    print(f"1a. self-enroll: http={ecode} status={enrolled.get('status')} enrolled={enrolled.get('enrolled')}")

    inner = {"intent": "clinic_explain", "request": make_broken_request()}
    env = sign_envelope(agent, akid, authority="visiting-agent",
                        body=json.dumps(inner).encode(), created=int(time.time()))
    wave = gl.envelope_to_waveform(env)                            # REAL ggwave audio
    t0 = time.time()
    code, audio = post_audio(wave)
    dt = time.time() - t0
    ok, why, body = verify_reply_audio(audio) if code == 200 else (False, f"http {code}", {})
    ans = (body.get("answer") or {}) if ok else {}
    ex = ans.get("explain") or {}
    served_ok = (ecode == 200 and enrolled.get("enrolled") and code == 200 and ok
                 and body.get("status") == "served" and ex.get("valid") is False
                 and (ex.get("content_digest") or {}).get("match") is False)
    passes.append(("native audio: enrolled /explain served + signed audio answer + correct diagnosis", served_ok))
    print(f"1b. native audio /explain: http={code} audio_in={len(wave)}B audio_out={len(audio)}B "
          f"rtt={dt:.1f}s clinic-sig={'OK' if ok else why} status={body.get('status')} "
          f"explain.valid={ex.get('valid')} digest_match={(ex.get('content_digest') or {}).get('match')}")

    # --- 2. UNENROLLED agent's audio is decoded but rejected (enrolled-only) -----------------
    stranger = SigningKey.generate()
    senv = sign_envelope(stranger, "gl-stranger-9", authority="visiting-agent",
                         body=json.dumps({"intent": "clinic_explain", "request": make_broken_request()}).encode(),
                         created=int(time.time()))
    swave = gl.envelope_to_waveform(senv)
    scode, saudio = post_audio(swave)
    sok, swhy, sbody = verify_reply_audio(saudio) if scode in (200, 400) else (False, f"http {scode}", {})
    rejected_ok = (scode == 400 and sok and sbody.get("status") == "rejected"
                   and "unenrolled" in (sbody.get("answer") or {}).get("error", ""))
    passes.append(("native audio: unenrolled agent rejected (still signed)", rejected_ok))
    print(f"2. unenrolled audio: http={scode} clinic-sig={'OK' if sok else swhy} "
          f"status={sbody.get('status')} reason={(sbody.get('answer') or {}).get('error')}")

    # --- 3. admission control: single slot taken -> new audio POST gets 503, no decode --------
    gl.acquire_slot()                                             # occupy the only decode slot
    try:
        bcode, bbody = post_audio(wave)
    finally:
        gl.release_slot()
    busy_ok = (bcode == 503 and b"busy" in bbody)
    passes.append(("native audio: admission control returns 503 when busy", busy_ok))
    print(f"3. busy: http={bcode} body={bbody[:60]!r}")

    # --- 4. audit chain intact across the whole exchange -------------------------------------
    srv.shutdown()
    chain = clinic.audit.verify_chain()
    passes.append(("audit chain intact", chain))
    print(f"\naudit records={len(clinic.audit.records)} chain_intact={chain}")

    allok = all(p for _, p in passes)
    print("\n=== NATIVE GIBBERLINK E2E RESULT ===")
    for name, p in passes:
        print(f"  {'PASS' if p else 'FAIL'} {name}")
    print(f"\n{'ALL PASS -- native gibberlink (ggwave audio) is a real, signed, sealed transport' if allok else 'FAILURES'}")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
