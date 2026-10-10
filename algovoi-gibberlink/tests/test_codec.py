"""Pure codec contract tests that do not require the optional audio backend."""

from __future__ import annotations

import zlib

import pytest

from algovoi_gibberlink import codec


def test_profile_selection_prefers_v2_but_supports_v1_only_peers() -> None:
    assert codec.select_profile({"versions": [2, 1]}).version == codec.CODEC_VERSION
    legacy = codec.select_profile({"versions": [1], "protocols": [2]})
    assert legacy.version == codec.LEGACY_CODEC_VERSION
    assert legacy.protocol_id == 2


@pytest.mark.parametrize(
    "peer",
    [
        [1],
        {"versions": [9]},
        {"versions": [1], "protocols": [9]},
        {"versions": None},
        {"versions": [1], "protocols": None},
        {"versions": [[1]]},
        {"versions": [1], "protocols": ["2"]},
    ],
)
def test_profile_selection_rejects_invalid_or_incompatible_capabilities(peer) -> None:
    with pytest.raises(ValueError):
        codec.select_profile(peer)


def test_frames_preserve_the_two_wire_versions() -> None:
    payload = b"payload" * 100
    v1 = codec._frames(payload, codec.CodecProfile(version=codec.LEGACY_CODEC_VERSION))
    v2 = codec._frames(payload, codec.CodecProfile(version=codec.CODEC_VERSION))

    assert v1
    assert all(frame.count(":") == 2 and not frame.startswith("GL") for frame in v1)
    assert v2
    assert all(frame.startswith("GL2|zlib|") for frame in v2)
    assert all(len(frame) <= 140 for frame in v2)


def test_bounded_decompression_rejects_trailing_data() -> None:
    compressed = zlib.compress(b"safe")
    with pytest.raises(ValueError, match="trailing data"):
        codec._decompress_bounded(compressed + b"junk")


def test_bounded_decompression_rejects_expansion() -> None:
    compressed = zlib.compress(b"x" * 1024)
    with pytest.raises(ValueError, match="exceeds 16 bytes"):
        codec._decompress_bounded(compressed, limit=16)
