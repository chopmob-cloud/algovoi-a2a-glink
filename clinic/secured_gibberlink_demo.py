#!/usr/bin/env python3
"""secured_gibberlink_demo.py -- a LOCAL research testbed: how two AI agents can
exchange a message over sound (gibberlink / ggwave) and PROVE who said what, using
AlgoVoi's shipped RFC 9421 verifier. No external party, no network, nothing to send.
The point is to learn how the tech is used SECURELY, and to see exactly what it does
and does not guarantee.

Pipeline (all local):
  Agent B  --sign (RFC 9421 + Ed25519, real shipped verifier's signing base)-->
           --serialise VAL envelope--> --ggwave encode to audio (a real .wav)-->
  [sound]  --ggwave decode--> Agent A --verify with algovoi-rfc9421-verifier-->

Then it runs the security lessons: tamper the body, replay a stale message, verify
with the wrong key, and (the subtle one) swap the sender's key in transit. Each shows
what the verifier catches and why.

Honesty: the "sound" here is a .wav file passed from B to A (a stand-in for a real
speaker->microphone hop). The codec IS gibberlink's ggwave. The security core (RFC 9421
signing base, Ed25519, Content-Digest, freshness, key gate) is the REAL shipped code,
not a lookalike. This is a bench experiment, not a live channel to anyone.

Run:  python secured_gibberlink_demo.py
"""
from __future__ import annotations
import base64, json, time, wave
from pathlib import Path

# The security core is the PUBLISHED, open-source verifier, installed like anyone else gets it.
# Reproduce this bench with exactly:
#   pip install "algovoi-rfc9421-verifier==0.4.4" ggwave pynacl
from algovoi_rfc9421_verifier import (
    compute_content_digest, build_signing_base, verify_request,
)
from nacl.signing import SigningKey, VerifyKey
import ggwave

HOME = Path.home() / ".algovoi" / "gibberlink"
# Best-effort ONLY. This directory exists to hold demo .wav artifacts; nothing the clinic
# listener does at runtime needs it. Making it a hard import-time side effect meant that on a
# --read-only container rootfs the mkdir raised EROFS, which propagated out of `import
# clinic_gibberlink` and made the listener disable the ENTIRE audio transport -- reported as
# "ggwave unavailable", which is not what failed. Never let an artifact dir gate the codec.
try:
    HOME.mkdir(parents=True, exist_ok=True)
except OSError:
    pass
SR = 48000            # ggwave sample rate
FRAME_DATA = 118      # payload bytes per ggwave frame after the "seq:total:" prefix (<=140 total)
TAG = "algovoi-val-demo"


# ---------------------------------------------------------------------------
# Agent B: compose an agent-to-agent message and sign it (the REAL security core)
# ---------------------------------------------------------------------------
def agent_b_sign(signing_key: SigningKey, *, created: int, ttl: int = 300) -> dict:
    """Return a VAL envelope: an RFC 9421-signed agent message, transport-agnostic."""
    vk_hex = signing_key.verify_key.encode().hex()
    keyid = f"did:key:z-demo-{vk_hex[:16]}"
    body = json.dumps({
        "intent": "authorize_payment",
        "from": "agent-b",
        "to": "agent-a",
        "amount": "12.50",
        "currency": "USDC",
        "memo": "invoice 4471, one-off",
    }, separators=(",", ":")).encode()

    cd = compute_content_digest(body)                      # RFC 9530 Content-Digest
    expires = created + ttl
    nonce = base64.b16encode(signing_key.sign(str(created).encode()).signature[:8]).decode().lower()
    covered = ["@method", "@authority", "@path", "content-digest"]

    # The post-label portion of Signature-Input, signed verbatim as @signature-params.
    params_raw = (
        '("@method" "@authority" "@path" "content-digest")'
        f';created={created};expires={expires};keyid="{keyid}";alg="ed25519"'
        f';nonce="{nonce}";tag="{TAG}"'
    )
    method, authority, path = "POST", "agent-b.local", "/a2a/message"
    signing_base = build_signing_base(
        covered, method=method, authority=authority, path=path, scheme="https",
        headers={"content-digest": cd}, parameters={},
        mode="rfc9421", signature_params_raw=params_raw,
    )
    sig = signing_key.sign(signing_base.encode("utf-8")).signature   # 64-byte Ed25519
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
        "public_key_hex": vk_hex,     # NOTE: in transit; A must anchor this out of band (see lesson 4)
        "keyid": keyid,
    }


# ---------------------------------------------------------------------------
# The sound channel: real ggwave codec, chunked, written to a playable .wav
# ---------------------------------------------------------------------------
def _frames(data: bytes) -> list[str]:
    b64 = base64.urlsafe_b64encode(data).decode()
    pieces = [b64[i:i + FRAME_DATA] for i in range(0, len(b64), FRAME_DATA)]
    n = len(pieces)
    return [f"{i}:{n}:{p}" for i, p in enumerate(pieces)]


SILENCE = b"\x00" * (4800 * 4)   # 0.1s of silence @48k float32: clean separation between frames


def send_over_sound(envelope: dict, wav_path: Path) -> bytes:
    """Encode the envelope to gibberlink audio, save a real .wav, return the raw waveform.

    Frames are separated by a short silence so the streaming decoder completes each frame
    before the next begins (without it, a long multi-frame message can drop a frame)."""
    data = json.dumps(envelope).encode()
    parts: list[bytes] = []
    for i, f in enumerate(_frames(data)):
        if i:
            parts.append(SILENCE)
        parts.append(ggwave.encode(f, protocolId=1, volume=25))
    waveform = b"".join(parts)
    # write a listenable 16-bit PCM wav (ggwave emits float32 @ 48k)
    import struct
    floats = struct.unpack("<%df" % (len(waveform) // 4), waveform)
    ints = b"".join(struct.pack("<h", max(-32768, min(32767, int(s * 32767)))) for s in floats)
    with wave.open(str(wav_path), "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(SR); w.writeframes(ints)
    return waveform


def _audio_segments(waveform: bytes, thresh: float = 0.02,
                    gap: int = 2400, min_seg: int = 4000) -> list[bytes]:
    """Split the waveform into per-frame segments on the silence gaps. Decoding each
    frame from its own clean segment is 100% reliable, unlike streaming a concatenated
    multi-frame buffer (which drops a frame at boundaries)."""
    import array
    a = array.array("f")
    a.frombytes(waveform)
    segs: list[tuple[int, int]] = []
    start = None
    run = 0
    for i, s in enumerate(a):
        if abs(s) > thresh:
            if start is None:
                start = i
            run = 0
        elif start is not None:
            run += 1
            if run >= gap:
                end = i - run + 1
                if end - start >= min_seg:
                    segs.append((start, end))
                start = None
                run = 0
    if start is not None and len(a) - start >= min_seg:
        segs.append((start, len(a)))
    return [a[s:e].tobytes() for s, e in segs]


def recv_from_sound(waveform: bytes) -> dict:
    """Decode the gibberlink audio back to the envelope. The receiver segments the audio
    on the silence gaps and decodes each frame independently, then reassembles by seq."""
    ggwave.disableLog()
    frames: dict[int, str] = {}
    total = None
    for seg in _audio_segments(waveform):
        inst = ggwave.init()
        try:
            r = ggwave.decode(inst, seg)
        finally:
            ggwave.free(inst)
        if r:
            seq, tot, piece = r.decode().split(":", 2)
            frames[int(seq)] = piece
            total = int(tot)
    if total is None or len(frames) != total:
        raise RuntimeError(f"incomplete transmission: got {len(frames)} of {total} frames")
    b64 = "".join(frames[i] for i in range(total))
    return json.loads(base64.urlsafe_b64decode(b64))


# ---------------------------------------------------------------------------
# Agent A: verify with the shipped verifier
# ---------------------------------------------------------------------------
def agent_a_verify(env: dict, *, now: int, public_key: str | None = None):
    body = base64.b64decode(env["body_b64"])
    return verify_request(
        method=env["method"], authority=env["authority"], path=env["path"],
        headers=env["headers"], body=body, scheme=env.get("scheme", "https"),
        public_key=public_key or env["public_key_hex"],
        require_content_digest=True, expected_tag=TAG, require_tag=True,
        allowed_algorithms={"ed25519"}, now=now, max_age_seconds=300,
    )


def line(msg): print(msg)
def rule(): print("-" * 72)


def main():
    ggwave.disableLog()
    t0 = int(time.time())
    key_b = SigningKey.generate()                 # Agent B's private key (never leaves B)
    attacker = SigningKey.generate()              # an unrelated key for the lessons
    wav = HOME / "val_message.wav"

    line("SECURED GIBBERLINK TESTBED  (local bench, no network, nothing sent to anyone)")
    rule()

    # 1) HAPPY PATH -----------------------------------------------------------
    env = agent_b_sign(key_b, created=t0)
    waveform = send_over_sound(env, wav)
    got = recv_from_sound(waveform)
    res = agent_a_verify(got, now=t0 + 5)
    line(f"1. HAPPY PATH: B signs -> {len(waveform)//4} audio samples "
         f"({wav.stat().st_size//1024} KB wav) -> A decodes -> verifies")
    line(f"   payload survived the sound hop: {got['body_b64'] == env['body_b64']}")
    line(f"   VERIFY valid={res.valid}  signature_valid={res.signature_valid}  "
         f"content_digest_valid={res.content_digest_valid}")
    line(f"   -> LESSON: sound is just a transport; the signature proves integrity + origin end to end.")
    rule()

    # 2) TAMPER THE BODY IN TRANSIT ------------------------------------------
    tampered = json.loads(json.dumps(got))
    b = bytearray(base64.b64decode(tampered["body_b64"]))
    b[b.find(b"12.50")] = ord("9")               # 12.50 -> 92.50, a payment amount swap
    tampered["body_b64"] = base64.b64encode(bytes(b)).decode()
    r2 = agent_a_verify(tampered, now=t0 + 5)
    line(f"2. TAMPER BODY (amount 12.50 -> 92.50 after signing):")
    line(f"   VERIFY valid={r2.valid}  reason: {r2.errors[0] if r2.errors else '(none)'}")
    line(f"   -> LESSON: an in-transit edit breaks the Content-Digest binding; the message is rejected.")
    rule()

    # 3) REPLAY / STALE -------------------------------------------------------
    r3 = agent_a_verify(got, now=t0 + 4000)      # long after expires (created+300)
    line(f"3. REPLAY a valid message later ({4000}s, past its expiry):")
    line(f"   VERIFY valid={r3.valid}  reason: {r3.errors[0] if r3.errors else '(none)'}")
    line(f"   -> LESSON: freshness/expiry rejects captured-and-replayed messages.")
    rule()

    # 4) WRONG / SUBSTITUTED KEY ---------------------------------------------
    r4 = agent_a_verify(got, now=t0 + 5, public_key=attacker.verify_key.encode().hex())
    line(f"4. VERIFY AGAINST THE WRONG KEY (attacker's public key):")
    line(f"   VERIFY valid={r4.valid}  reason: {r4.errors[0] if r4.errors else '(none)'}")
    line("   -> LESSON: the signature only verifies against B's real key. BUT the key travels")
    line("      inside the envelope, so an attacker could swap BOTH the key and the signature and")
    line("      it would 'verify' against their own key. The verifier proves 'signed by THIS key',")
    line("      not 'signed by B'. To use this securely, A must anchor B's keyid to a trusted source")
    line("      (a directory / prior handshake), NOT trust the key that arrived over the sound.")
    rule()

    line("SUMMARY: over an untrusted channel (even sound), a signed VAL envelope gives agents")
    line("integrity, origin-authentication-to-a-key, replay resistance, and tamper evidence,")
    line("offline and transport-agnostic. The one thing sound (or any channel) cannot give you is")
    line("trust in WHICH key is really B's, that must come from an anchored keyid. That is the")
    line("secure-usage rule for agent-to-agent gibberlink.")
    line(f"\nArtifact: {wav}")


if __name__ == "__main__":
    main()
