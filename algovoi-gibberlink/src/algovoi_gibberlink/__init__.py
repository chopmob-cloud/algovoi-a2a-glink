"""algovoi-gibberlink: the hardened gibberlink (ggwave data-over-sound) codec for the
transport-agnostic RFC 9421 VAL envelope.

This is the canonical, reusable extraction of the clinic's native gibberlink transport
(algovoi-a2a-glink/clinic/clinic_gibberlink.py). It carries a SIGNED VAL envelope over
ggwave audio with hard DoS bounds (audio-size ceiling, frame cap, bounded decompression,
float32 alignment, an admission semaphore) and fails closed on anything malformed.

It is ONLY the audio codec. Identity/authorisation/trust remain properties of the signed
VAL envelope, which callers verify with algovoi-rfc9421-verifier — unchanged whether the
envelope arrived over HTTP or gibberlink. `ggwave` is an optional extra ([audio]); the
module imports without it (encode/decode then raise a clear error) so an HTTP-only service
can import the envelope helpers without the audio stack.
"""
from __future__ import annotations

from .codec import (
    CODEC_VERSION,
    LEGACY_CODEC_VERSION,
    MAX_AUDIO_BYTES,
    MAX_ENVELOPE_BYTES,
    MAX_FRAMES,
    CodecProfile,
    GibberlinkBusy,
    acquire_slot,
    canonical_envelope_bytes,
    capabilities,
    compressed_envelope_bytes,
    decode_waveform,
    default_profile,
    envelope_to_waveform,
    release_slot,
    select_profile,
    waveform_to_envelope,
)
from .envelope import (
    TAG,
    TTL,
    envelope_hash,
    sign_envelope,
    verify_envelope,
    verify_envelope_selfasserted,
)

__all__ = [
    "TAG",
    "TTL",
    "envelope_hash",
    "sign_envelope",
    "verify_envelope",
    "verify_envelope_selfasserted",
    "CODEC_VERSION",
    "LEGACY_CODEC_VERSION",
    "MAX_AUDIO_BYTES",
    "MAX_ENVELOPE_BYTES",
    "MAX_FRAMES",
    "CodecProfile",
    "GibberlinkBusy",
    "acquire_slot",
    "release_slot",
    "canonical_envelope_bytes",
    "compressed_envelope_bytes",
    "capabilities",
    "decode_waveform",
    "default_profile",
    "envelope_to_waveform",
    "select_profile",
    "waveform_to_envelope",
]

__version__ = "0.1.0"
