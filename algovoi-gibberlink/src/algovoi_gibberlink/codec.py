#!/usr/bin/env python3
"""clinic_gibberlink.py -- the NATIVE gibberlink (ggwave audio) transport for the clinic.

Carries the SAME RFC 9421-signed VAL envelope as the HTTP path, but over gibberlink's real
ggwave audio codec instead of JSON-over-HTTPS: an agent sends the envelope encoded as sound
(a float32 @48k waveform), the clinic decodes it, runs the IDENTICAL sealed control pipeline
(clinic_transport.handle_frame -- enrollment/self-asserted, schema+size, replay, rate+cap,
audit, fail-closed), then encodes the SIGNED reply back to gibberlink audio. The security
core is transport-agnostic by design; this module is only the audio codec + hard bounds.

Reality check (measured): a ~700-byte envelope is ~12 MB of audio and ~2.7s CPU to
encode+decode. That is inherent to ggwave. So this transport is deliberately bounded hard
(MAX_AUDIO_BYTES, frame cap) and is intended for a LOW request rate; the global daily cap and
per-peer limiter in clinic_transport still apply on the decoded envelope. ggwave is a pure
codec (no audio device), so this runs headless in the container.
"""
from __future__ import annotations
from dataclasses import dataclass
import base64, json, os, threading, zlib

try:
    import ggwave  # audio codec; optional (install algovoi-gibberlink[audio])
except ImportError:  # pragma: no cover
    ggwave = None


def _require_ggwave():
    if ggwave is None:
        raise RuntimeError("ggwave not installed; pip install algovoi-gibberlink[audio]")
import rfc8785
from ._audio import SILENCE, _audio_segments

# The clinic is a one-at-a-time SIGNED DESK / holding area: agents are served serially over the
# gibberlink channel. Serialization is a security property (no interleaving) AND the DoS control.
# So the default concurrency is 1; excess agents get 503 "busy, hold and retry" without any decode.
# (A garbled 26 MB waveform must be DECODED before its signature can be checked, so admission
# control -- not enrollment -- is what stops pre-auth CPU exhaustion.)
GIBBERLINK_CONCURRENCY = int(os.environ.get("CLINIC_GIBBERLINK_CONCURRENCY", "1"))
_SEM = threading.BoundedSemaphore(GIBBERLINK_CONCURRENCY)

# Wire efficiency: we carry the waveform BYTES over the network (not a real speaker->mic hop), so
# the slow, robust acoustic protocol is pointless. Use ggwave's fastest protocol + zlib on the
# envelope. Measured: a concrete /explain envelope drops ~26 MB -> ~10 MB (protocol 2 + zlib),
# the reply ~45 MB -> ~18 MB. Both sides MUST agree on protocol + compression.
CODEC_VERSION = 2
LEGACY_CODEC_VERSION = 1
SUPPORTED_PROTOCOLS = (0, 1, 2)
DEFAULT_PROTOCOL = int(os.environ.get("CLINIC_GIBBERLINK_PROTOCOL", "2"))
DEFAULT_FRAME_DATA = int(os.environ.get("CLINIC_GIBBERLINK_FRAME_DATA", "100"))
DEFAULT_SILENCE_MS = int(os.environ.get("CLINIC_GIBBERLINK_SILENCE_MS", "100"))
MAX_FRAME_DATA = 110       # keep the complete GL2 frame below ggwave's practical 140-char limit


@dataclass(frozen=True)
class CodecProfile:
    """A negotiated, self-describing audio wire profile.

    The profile describes transport encoding only. It does not establish identity,
    authorisation, or trust. Those remain properties of the signed VAL envelope.
    """

    version: int = CODEC_VERSION
    protocol_id: int = DEFAULT_PROTOCOL
    compression: str = "zlib"
    frame_data_chars: int = DEFAULT_FRAME_DATA
    silence_ms: int = DEFAULT_SILENCE_MS

    def __post_init__(self):
        # v1 is a fully supported EXCHANGE version, not just a decode curiosity: production
        # peers speak it. A v1 profile encodes v1 frames so we can answer them in kind.
        if self.version not in (CODEC_VERSION, LEGACY_CODEC_VERSION):
            raise ValueError(f"unsupported codec version: {self.version}")
        if self.protocol_id not in SUPPORTED_PROTOCOLS:
            raise ValueError(f"unsupported ggwave protocol: {self.protocol_id}")
        if self.compression != "zlib":
            raise ValueError(f"unsupported compression: {self.compression}")
        if not 40 <= self.frame_data_chars <= MAX_FRAME_DATA:
            raise ValueError("frame_data_chars outside safe range")
        if not 0 <= self.silence_ms <= 1000:
            raise ValueError("silence_ms outside safe range")


def default_profile() -> CodecProfile:
    return CodecProfile()


def capabilities() -> dict:
    """Return public, non-secret capabilities for agent-card negotiation."""
    return {
        "codec": "algovoi-gibberlink",
        # Both are full exchange versions: we decode either and REPLY IN THE SAME VERSION we
        # were addressed in, so v1 and v2 peers interoperate without a flag day.
        "versions": [CODEC_VERSION, LEGACY_CODEC_VERSION],
        "reply_policy": "reply-in-kind (a v1 request is answered with v1 frames)",
        "compression": ["zlib"],
        "protocols": list(SUPPORTED_PROTOCOLS),
        "default_protocol": DEFAULT_PROTOCOL,
        "default_frame_data_chars": DEFAULT_FRAME_DATA,
        "default_silence_ms": DEFAULT_SILENCE_MS,
        "max_audio_bytes": MAX_AUDIO_BYTES,
        "fallback": {"transport": "http-val", "endpoint": "/clinic"},
    }


def select_profile(peer: dict | None = None) -> CodecProfile:
    """Select a safe common profile from public peer capabilities.

    Until reliability data is persisted, protocol preference is conservative:
    the local configured protocol is used when shared, otherwise the slowest
    supported common protocol is selected. A future benchmark table may refine
    this choice without changing the wire format.
    """
    if peer is None:
        peer = {}
    if not isinstance(peer, dict):
        raise ValueError("peer capabilities must be an object")
    raw_versions = peer.get("versions", [CODEC_VERSION, LEGACY_CODEC_VERSION])
    raw_protocols = peer.get("protocols", SUPPORTED_PROTOCOLS)
    if not isinstance(raw_versions, (list, tuple, set, frozenset)):
        raise ValueError("peer versions must be an array")
    if not isinstance(raw_protocols, (list, tuple, set, frozenset)):
        raise ValueError("peer protocols must be an array")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in raw_versions):
        raise ValueError("peer versions must contain integers")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in raw_protocols):
        raise ValueError("peer protocols must contain integers")
    peer_versions = set(raw_versions)
    common_versions = sorted({CODEC_VERSION, LEGACY_CODEC_VERSION} & peer_versions, reverse=True)
    if not common_versions:
        raise ValueError("peer supports neither codec version 2 nor legacy version 1")
    peer_protocols = set(raw_protocols)
    common = sorted(set(SUPPORTED_PROTOCOLS) & peer_protocols)
    if not common:
        raise ValueError("no common ggwave protocol")
    protocol = DEFAULT_PROTOCOL if DEFAULT_PROTOCOL in common else common[0]
    peer_frame = int(peer.get("max_frame_data_chars", DEFAULT_FRAME_DATA))
    peer_silence = int(peer.get("silence_ms", DEFAULT_SILENCE_MS))
    return CodecProfile(version=common_versions[0],
                        frame_data_chars=min(DEFAULT_FRAME_DATA, peer_frame),
                        protocol_id=protocol, silence_ms=min(DEFAULT_SILENCE_MS, peer_silence))


def canonical_envelope_bytes(env: dict) -> bytes:
    """Serialise the full envelope using RFC 8785 JCS before compression."""
    return rfc8785.dumps(env)


def compressed_envelope_bytes(env: dict) -> bytes:
    return zlib.compress(canonical_envelope_bytes(env), 9)


def _silence(profile: CodecProfile) -> bytes:
    # ggwave emits float32 at 48 kHz in this project.
    samples = round(48000 * profile.silence_ms / 1000)
    return b"\x00" * (samples * 4)


class GibberlinkBusy(Exception):
    """Raised when all decode slots are in use; the caller returns 503 without decoding."""


def acquire_slot() -> None:
    if not _SEM.acquire(blocking=False):
        raise GibberlinkBusy("all gibberlink decode slots busy")


def release_slot() -> None:
    try:
        _SEM.release()
    except ValueError:
        pass

# Hard bound on the AUDIO payload (the decoded envelope is separately bounded to 16KB by
# clinic_transport.validate_frame). With protocol 2 + zlib a /explain reply is ~18 MB, so 32 MB
# is a safe ceiling that still fails an unbounded-decode DoS closed. The global daily cap +
# per-peer limiter in clinic_transport still bound the decoded envelope regardless of transport.
MAX_AUDIO_BYTES = 32 * 1024 * 1024
MAX_FRAMES = 4096                         # cap reassembly work on adversarial audio

# The DECODED envelope is bounded to 16KB by clinic_transport.validate_frame -- but that check
# runs AFTER decompression, so it cannot stop a compression bomb. A ~200KB crafted payload fits
# inside MAX_FRAMES yet inflates to >200MB, and the gibberlink decode happens BEFORE any
# enrollment/signature check (admission control is the only pre-auth gate). So bound the
# EXPANSION itself: decode at most MAX_ENVELOPE_BYTES and fail closed if the stream has more.
MAX_ENVELOPE_BYTES = 16 * 1024            # mirrors clinic_transport.MAX_FRAME_BYTES


def _decompress_bounded(compressed: bytes, limit: int = MAX_ENVELOPE_BYTES) -> bytes:
    """zlib.decompress with a hard output ceiling. Fails closed on an over-large expansion,
    a truncated stream, or trailing data after the stream."""
    d = zlib.decompressobj()
    out = d.decompress(compressed, limit + 1)
    if len(out) > limit or d.unconsumed_tail:
        raise ValueError(f"decompressed envelope exceeds {limit} bytes")
    if not d.eof:
        raise ValueError("truncated zlib stream")
    if d.unused_data:
        raise ValueError("trailing data after zlib stream")
    return out


def _frames(data: bytes, profile: CodecProfile) -> list[str]:
    b64 = base64.urlsafe_b64encode(data).decode()
    if profile.version == LEGACY_CODEC_VERSION:
        # Original wire format: "{seq}:{n}:{piece}", no profile prefix. The payload is still
        # JCS+zlib, which a v1 decoder reads fine (it only does json.loads on the inflated
        # bytes), so answering a v1 peer costs nothing but the framing.
        pieces = [b64[i:i + profile.frame_data_chars]
                  for i in range(0, len(b64), profile.frame_data_chars)] or [""]
        return [f"{i}:{len(pieces)}:{p}" for i, p in enumerate(pieces)]
    # The prefix carries the codec version and profile so the receiver can reject
    # downgrade/ambiguity rather than guessing from an opaque audio stream.
    provisional = f"GL{profile.version}|{profile.compression}|{profile.protocol_id}|"
    # Account for sequence and total fields before choosing the piece size.
    # Shrink the payload slice until the COMPLETE frame (prefix + seq/total + payload) fits
    # ggwave's practical 140-char limit. piece_size was previously reset at the top of every
    # iteration, so the decrement never took effect and the loop could not converge.
    piece_size = profile.frame_data_chars
    while piece_size > 40:
        n = max(1, (len(b64) + piece_size - 1) // piece_size)
        if len(f"{provisional}{n - 1}|{n}|") + piece_size <= 140:
            break
        piece_size -= 4
    pieces = [b64[i:i + piece_size] for i in range(0, len(b64), piece_size)]
    n = len(pieces)
    return [f"GL{profile.version}|{profile.compression}|{profile.protocol_id}|{i}|{n}|{p}"
            for i, p in enumerate(pieces)]


def envelope_to_waveform(env: dict, profile: CodecProfile | None = None) -> bytes:
    """Encode a VAL envelope using compact JCS, zlib, versioned frames, and ggwave."""
    _require_ggwave()
    profile = profile or default_profile()
    data = compressed_envelope_bytes(env)
    parts: list[bytes] = []
    for i, f in enumerate(_frames(data, profile)):
        if i:
            parts.append(_silence(profile))
        parts.append(ggwave.encode(f, protocolId=profile.protocol_id, volume=25))
    out = b"".join(parts)
    if len(out) > MAX_AUDIO_BYTES:          # never emit a reply larger than the accepted ceiling
        raise ValueError(f"reply audio too large ({len(out)}>{MAX_AUDIO_BYTES})")
    return out


def decode_waveform(waveform: bytes) -> tuple[dict, CodecProfile | None]:
    """Decode a gibberlink waveform back to the VAL envelope. Fails closed (raises) on an
    oversized buffer, an unaligned/garbled buffer, too many frames, or an incomplete
    transmission, so the caller can reject it without trusting anything.

    The returned profile records which wire version the request arrived in (v1 or v2). Pass it
    straight back to envelope_to_waveform so the reply is encoded in the SAME version -- that is
    what keeps v1 and v2 peers interoperating on one endpoint."""
    _require_ggwave()
    if not isinstance(waveform, (bytes, bytearray)):
        raise ValueError("non-bytes audio")
    if len(waveform) > MAX_AUDIO_BYTES:
        raise ValueError(f"audio too large ({len(waveform)}>{MAX_AUDIO_BYTES})")
    if len(waveform) % 4 != 0:
        raise ValueError("waveform not float32-aligned")
    ggwave.disableLog()
    frames: dict[int, str] = {}
    frame_meta: tuple[str, int, int] | None = None
    total = None
    segs = _audio_segments(bytes(waveform))
    if len(segs) > MAX_FRAMES:
        raise ValueError("too many audio frames")
    for seg in segs:
        # The Python wrapper retains end-marker state after a completed frame.
        # A fresh instance per separated frame is required for correctness with
        # the current segmentation strategy; streaming decoder reuse is a future
        # optimisation only when the wrapper exposes an explicit reset.
        inst = ggwave.init()
        try:
            r = ggwave.decode(inst, seg)
        finally:
            ggwave.free(inst)
        if not r:
            continue
        decoded = r.decode()
        if decoded.startswith("GL2|"):
            version, compression, protocol, seq_s, total_s, piece = decoded.split("|", 5)
            if version != "GL2" or compression != "zlib":
                raise ValueError("unsupported gibberlink frame profile")
            seq, total = int(seq_s), int(total_s)
            if int(protocol) not in SUPPORTED_PROTOCOLS:
                raise ValueError("unsupported ggwave protocol in frame")
            if frame_meta is None:
                frame_meta = (compression, total, int(protocol))
            elif frame_meta != (compression, total, int(protocol)):
                raise ValueError("mixed gibberlink frame profiles")
        else:
            # Compatibility with the original clinic codec: compressed JSON
            # with seq:total:piece frames and no profile prefix.
            seq_s, total_s, piece = decoded.split(":", 2)
            seq, total = int(seq_s), int(total_s)
            if frame_meta is None:
                frame_meta = ("zlib", total, -1)
            elif frame_meta[1:] != (total, -1):
                raise ValueError("mixed legacy and versioned frames")
        if total < 1 or total > MAX_FRAMES or seq < 0 or seq >= total:
            raise ValueError("invalid frame sequence")
        if seq in frames and frames[seq] != piece:
            raise ValueError("conflicting duplicate frame")
        frames[seq] = piece
    total = frame_meta[1] if frame_meta else None
    if total is None or len(frames) != total:
        raise RuntimeError(f"incomplete transmission: {len(frames)} of {total} frames")
    b64 = "".join(frames[i] for i in range(total))
    try:
        compressed = base64.b64decode(b64.encode(), altchars=b"-_", validate=True)
        env = json.loads(_decompress_bounded(compressed))
        # A v1 request yields a v1 profile so the caller answers in the SAME format it was
        # addressed in. Previously this returned None, which fell through to the v2 default
        # and handed v1 peers a reply their decoder raises on.
        profile = (CodecProfile(protocol_id=frame_meta[2]) if frame_meta and frame_meta[2] >= 0
                   else CodecProfile(version=LEGACY_CODEC_VERSION, protocol_id=DEFAULT_PROTOCOL))
        return env, profile
    except (ValueError, zlib.error, json.JSONDecodeError) as exc:
        raise ValueError("invalid compressed gibberlink payload") from exc


def waveform_to_envelope(waveform: bytes) -> dict:
    """Backward-compatible wrapper returning only the decoded envelope."""
    env, _profile = decode_waveform(waveform)
    return env
