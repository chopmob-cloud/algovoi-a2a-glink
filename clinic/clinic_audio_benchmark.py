#!/usr/bin/env python3
"""Reproducible offline bandwidth benchmark for the clinic audio codec.

Writes JSON to stdout or --output. It measures useful payload throughput, not WAV
file size, and can inject deterministic frame loss to compare reliability.
"""
from __future__ import annotations
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clinic_gibberlink as gl


def envelope(size: int) -> dict:
    return {"keyid": "benchmark-agent", "body": {"intent": "clinic_explain",
            "request": {"q": "x" * size}}, "headers": {"Signature": "s", "Content-Digest": "d"}}


def impair(waveform: bytes, drop_every: int) -> bytes:
    if not drop_every:
        return waveform
    segments = gl._audio_segments(waveform)
    kept = [segment for i, segment in enumerate(segments, 1) if i % drop_every]
    return b"".join(kept)


def run(size: int, protocol: int, frame_data: int, silence_ms: int, drop_every: int) -> dict:
    env = envelope(size)
    profile = gl.CodecProfile(protocol_id=protocol, frame_data_chars=frame_data, silence_ms=silence_ms)
    canonical = gl.canonical_envelope_bytes(env)
    compressed = gl.compressed_envelope_bytes(env)
    t0 = time.perf_counter()
    waveform = gl.envelope_to_waveform(env, profile)
    encode_ms = (time.perf_counter() - t0) * 1000
    t1 = time.perf_counter()
    decoded = None
    error = None
    try:
        decoded = gl.waveform_to_envelope(impair(waveform, drop_every))
    except Exception as exc:  # benchmark records controlled failures rather than hiding them
        error = type(exc).__name__ + ": " + str(exc)
    decode_ms = (time.perf_counter() - t1) * 1000
    duration_s = (len(waveform) / 4) / 48000
    return {"codec_version": profile.version, "protocol": protocol, "frame_data_chars": frame_data,
            "silence_ms": silence_ms, "logical_payload_bytes": len(canonical),
            "compressed_bytes": len(compressed), "audio_bytes": len(waveform),
            "audio_duration_s": round(duration_s, 6),
            "effective_payload_bytes_per_s": round(len(canonical) / duration_s, 4) if duration_s else 0,
            "encode_ms": round(encode_ms, 3), "decode_ms": round(decode_ms, 3),
            "success": decoded == env, "error": error, "drop_every": drop_every}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path)
    p.add_argument("--sizes", default="64,256,1024")
    p.add_argument("--protocols", default="0,1,2")
    p.add_argument("--frame-data", type=int, default=gl.DEFAULT_FRAME_DATA)
    p.add_argument("--silence-ms", type=int, default=gl.DEFAULT_SILENCE_MS)
    p.add_argument("--drop-every", type=int, default=0)
    a = p.parse_args()
    gl.ggwave.disableLog()
    report = {"schema": "algovoi.gibberlink.bandwidth.v1", "results": [
        run(size, protocol, a.frame_data, a.silence_ms, a.drop_every)
        for size in map(int, a.sizes.split(","))
        for protocol in map(int, a.protocols.split(","))]}
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if a.output:
        a.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
