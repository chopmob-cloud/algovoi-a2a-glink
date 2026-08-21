#!/usr/bin/env python3
"""Focused codec tests for versioning, compact encoding, and fail-closed framing."""
from __future__ import annotations
import base64
import json
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clinic_gibberlink as gl
import ggwave
from secured_gibberlink_demo import SILENCE


def sample() -> dict:
    return {"keyid": "agent-a", "body": {"intent": "clinic_explain", "q": "signing base"},
            "headers": {"Signature": "sig", "Content-Digest": "digest"}}


def main() -> int:
    checks: list[tuple[str, bool]] = []
    env = sample()
    compact = gl.canonical_envelope_bytes(env)
    checks.append(("jcs-is-deterministic", compact == b'{"body":{"intent":"clinic_explain","q":"signing base"},"headers":{"Content-Digest":"digest","Signature":"sig"},"keyid":"agent-a"}'))
    wave = gl.envelope_to_waveform(env)
    checks.append(("versioned-round-trip", gl.waveform_to_envelope(wave) == env))
    legacy_data = zlib.compress(json.dumps(env).encode(), 9)
    legacy_b64 = base64.urlsafe_b64encode(legacy_data).decode()
    legacy_frames = [legacy_b64[i:i + 100] for i in range(0, len(legacy_b64), 100)]
    legacy_wave = b"".join((b"" if i == 0 else SILENCE) +
                             ggwave.encode(f"{i}:{len(legacy_frames)}:{piece}", protocolId=2, volume=25)
                             for i, piece in enumerate(legacy_frames))
    checks.append(("legacy-round-trip", gl.waveform_to_envelope(legacy_wave) == env))
    caps = gl.capabilities()
    # Both versions are advertised because both are genuinely exchangeable: we decode either and
    # reply in the SAME version we were addressed in.
    checks.append(("capabilities-advertise-both-versions", caps["versions"] == [2, 1]))
    # A legacy waveform must report a v1 REPLY profile, so the caller answers in v1 rather than
    # falling through to the v2 default and handing a v1 peer audio it cannot parse.
    legacy_profile = gl.decode_waveform(legacy_wave)[1]
    checks.append(("legacy-reports-a-v1-reply-profile",
                   legacy_profile is not None and legacy_profile.version == gl.LEGACY_CODEC_VERSION))
    # And that profile must actually emit v1 framing ("{seq}:{n}:{piece}", no GL prefix).
    v1_frames = gl._frames(b"x" * 300, legacy_profile)
    checks.append(("v1-profile-emits-v1-framing",
                   all(not f.startswith("GL") and f.split(":", 2)[0].isdigit() for f in v1_frames)))
    selected = gl.select_profile({"versions": [2], "protocols": [0, 2], "max_frame_data_chars": 80, "silence_ms": 50})
    checks.append(("profile-selection", selected.protocol_id == 2 and selected.frame_data_chars == 80 and selected.silence_ms == 50))
    try:
        gl.select_profile({"versions": [1], "protocols": [2]})
    except ValueError:
        checks.append(("unsupported-version-rejected", True))
    else:
        checks.append(("unsupported-version-rejected", False))
    ok = all(value for _, value in checks)
    for name, value in checks:
        print(f"{'PASS' if value else 'FAIL'} {name}")
    print(f"RESULT: {'ALL PASS' if ok else 'FAILURES'} ({sum(v for _, v in checks)}/{len(checks)})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
