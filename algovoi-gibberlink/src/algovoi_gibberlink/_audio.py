"""Audio segmentation helpers for the gibberlink codec (no ggwave dependency)."""
from __future__ import annotations

SILENCE = b"\x00" * (4800 * 4)   # 0.1s of silence @48k float32: clean frame separation

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
