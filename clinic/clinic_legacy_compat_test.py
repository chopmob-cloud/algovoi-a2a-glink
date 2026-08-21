#!/usr/bin/env python3
"""clinic_legacy_compat_test.py -- the clinic never answers a LEGACY v1 peer in v2 audio.

Why this exists: the v1 wire format is `{seq}:{n}:{piece}`; its decoder does split(":", 2). A v2
frame is `GL2|zlib|<proto>|<seq>|<n>|<piece>` -- no colons -- so a v1 peer raises
`ValueError: not enough values to unpack` on a v2 reply. The clinic can DECODE v1 (compat path),
but it has no v1 ENCODER, so serving a v1 request over audio hands the peer a reply it cannot
read while returning HTTP 200. That looks like success and is the worst possible failure shape.

`clinic_gibberlink_test.legacy-round-trip` only proves the NEW decoder reads OLD frames; it says
nothing about the reply direction. This test covers the direction that actually broke.

Contract: the clinic REPLIES IN KIND -- a v1 request is answered with v1 frames, a v2 request
with v2 frames -- so both peer generations share one endpoint with no flag day.
"""
from __future__ import annotations
import base64, json, sys, threading, time, urllib.request, urllib.error, zlib
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import NamedTemporaryFile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ggwave
import clinic_listener as cl
import clinic_gibberlink as gl
from negotiation_gibberlink_demo import sign_envelope, verify_envelope
from secured_gibberlink_demo import SILENCE, _audio_segments
from nacl.signing import SigningKey

PORT = 8817

# A well-formed (deliberately broken-signature) request. An empty dict makes the explain engine
# raise, which the pipeline correctly turns into a signed "internal" rejection -- that would test
# the error path, not the codec.
SAMPLE_REQUEST = {
    "method": "POST", "authority": "peer.example", "path": "/a2a/message",
    "headers": {"Content-Digest": "sha-256=:AAAA:",
                "Signature-Input": 'sig1=("@method")', "Signature": "sig1=:BBBB:"},
    "body_b64": "e30="}


def legacy_waveform(env: dict) -> bytes:
    """Encode an envelope in the ORIGINAL v1 frame format, byte-for-byte as the pre-GL2 codec
    did: zlib -> urlsafe base64 -> `{seq}:{n}:{piece}` frames separated by silence."""
    b64 = base64.urlsafe_b64encode(zlib.compress(json.dumps(env).encode(), 9)).decode()
    pieces = [b64[i:i + 100] for i in range(0, len(b64), 100)]
    n = len(pieces)
    return b"".join((b"" if i == 0 else SILENCE) +
                    ggwave.encode(f"{i}:{n}:{p}", protocolId=1, volume=25)
                    for i, p in enumerate(pieces))


def post(path: str, data: bytes, ctype: str):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=data,
                                 headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main() -> int:
    clinic_sk = SigningKey.generate()
    store = NamedTemporaryFile(prefix="legacy_enroll_", suffix=".jsonl", delete=False).name
    clinic = cl.Clinic(clinic_sk, {}, open_explain=True, gibberlink_enabled=True, enroll_store=store)
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), cl.make_handler(clinic))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    clinic_pub = {clinic.kid: clinic_sk.verify_key.encode().hex()}
    checks = []

    # An ENROLLED peer, so the refusal is about the codec and nothing else.
    agent = SigningKey.generate(); akid = "gl-legacy-agent"
    now = int(time.time())
    post("/clinic/enroll", json.dumps(sign_envelope(
        agent, akid, authority="legacy-agent",
        body=json.dumps({"intent": "clinic_enroll"}).encode(), created=now)).encode(),
        "application/json")

    env = sign_envelope(agent, akid, authority="legacy-agent",
                        body=json.dumps({"intent": "clinic_explain", "request": SAMPLE_REQUEST}).encode(),
                        created=int(time.time()))
    wave = legacy_waveform(env)

    # The clinic must still UNDERSTAND v1 (inbound compat is real and should not regress).
    decoded, profile = gl.decode_waveform(wave)
    checks.append(("legacy-request-still-decodes", decoded == env))
    checks.append(("legacy-request-reports-a-v1-reply-profile",
                   profile is not None and profile.version == gl.LEGACY_CODEC_VERSION))

    code, body = post("/clinic/gibberlink", wave, "application/octet-stream")
    checks.append(("legacy-request-served-not-refused", code == 200))
    checks.append(("reply-is-audio-not-a-json-refusal", body[:1] != b"{"))

    # The decisive check: decode the reply with a STRICT v1 decoder -- the same split(":", 2)
    # the real pre-GL2 codec uses. If the clinic replied in v2 this raises, which is exactly
    # the failure a v1 peer used to hit after receiving HTTP 200.
    reply_ok, reason, fb_env = False, None, None
    try:
        frames, total = {}, None
        for seg in _audio_segments(body):
            inst = ggwave.init()
            try:
                r = ggwave.decode(inst, seg)
            finally:
                ggwave.free(inst)
            if r:
                seq, tot, piece = r.decode().split(":", 2)   # STRICT v1 parse
                frames[int(seq)] = piece; total = int(tot)
        b64 = "".join(frames[i] for i in range(total))
        fb_env = json.loads(zlib.decompress(base64.urlsafe_b64decode(b64)))
        reply_ok = True
    except Exception as e:  # noqa: BLE001
        reason = f"{type(e).__name__}: {e}"
    checks.append(("v1-peer-can-decode-the-reply", reply_ok))

    sig_ok = False
    if fb_env:
        sig_ok, why, rbody = verify_envelope(fb_env, anchored_peers=clinic_pub,
                                             expected_keyid=clinic.kid, now=int(time.time()))
        checks.append(("reply-is-signed-by-the-clinic", sig_ok))
        checks.append(("reply-carries-a-served-answer", (rbody or {}).get("status") == "served"))
    else:
        checks.extend([("reply-is-signed-by-the-clinic", False),
                       ("reply-carries-a-served-answer", False)])

    # A v2 request on the SAME endpoint must still get v2 frames back.
    # A SECOND enrolled peer, so the v2 leg is not blocked by the 1-request/min/peer limiter.
    agent2 = SigningKey.generate(); akid2 = "gl-v2-agent"
    post("/clinic/enroll", json.dumps(sign_envelope(
        agent2, akid2, authority="v2-agent",
        body=json.dumps({"intent": "clinic_enroll"}).encode(), created=int(time.time()))).encode(),
        "application/json")
    env2 = sign_envelope(agent2, akid2, authority="v2-agent",
                         body=json.dumps({"intent": "clinic_explain", "request": SAMPLE_REQUEST}).encode(),
                         created=int(time.time()))
    code2, body2 = post("/clinic/gibberlink", gl.envelope_to_waveform(env2), "application/octet-stream")
    v2_ok = False
    if code2 == 200 and body2[:1] != b"{":
        try:
            renv, rprof = gl.decode_waveform(body2)
            v2_ok = rprof is not None and rprof.version == gl.CODEC_VERSION
        except Exception:
            v2_ok = False
    checks.append(("v2-request-still-answered-in-v2", v2_ok))

    caps = gl.capabilities()
    checks.append(("capabilities-advertise-both-versions",
                   caps["versions"] == [gl.CODEC_VERSION, gl.LEGACY_CODEC_VERSION]))

    print("=== LEGACY (v1) GIBBERLINK COMPAT ===")
    for name, value in checks:
        print(f"  {'PASS' if value else 'FAIL'} {name}")
    print(f"  v1 request http={code} | v1 decode of reply: {'OK' if reply_ok else reason}")
    print(f"  v2 request http={code2} | answered in v2: {v2_ok}")
    ok = all(v for _, v in checks)
    print(f"\nRESULT: {'ALL PASS' if ok else 'FAILURES'} ({sum(v for _, v in checks)}/{len(checks)})")
    srv.shutdown()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
