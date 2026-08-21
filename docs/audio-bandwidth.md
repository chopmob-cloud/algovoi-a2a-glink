# Audio bandwidth implementation

## Purpose

The clinic supports GibberLink as an optional transport for constrained audio
channels. HTTP remains the normal A2A and x402 transport. This document describes
the bandwidth work implemented in the clinic codec and the evidence required
before selecting a faster profile automatically.

## Current wire path

The audio path carries the same signed VAL envelope as the HTTP path:

```text
VAL envelope
  -> RFC 8785 JCS bytes
  -> zlib compression
  -> URL-safe base64
  -> versioned frame records
  -> ggwave audio
```

Version 2 frame records are textual ggwave payloads with this shape:

```text
GL2|zlib|<protocol>|<sequence>|<total>|<base64-piece>
```

The profile is self-describing so a receiver does not have to guess the
compression or protocol. The complete profile is also advertised in the agent
card when GibberLink is enabled.

The receiver validates the version, compression, protocol, sequence range,
frame count, duplicate consistency, base64, decompression, and JSON before the
envelope reaches the shared signature and replay pipeline.

## Compatibility

The decoder still accepts the original clinic frame shape:

```text
<sequence>:<total>:<base64-piece>
```

That legacy format is decoded as compressed JSON. New transmissions use version
2. A peer that cannot select version 2 must use the existing HTTP VAL endpoint;
the clinic does not silently downgrade an authenticated exchange to an
unadvertised audio format.

## Profile selection

`select_profile()` accepts the peer's public capabilities and chooses a common
version and ggwave protocol. The local configured protocol is preferred when it
is shared. Otherwise the slowest common protocol is selected. This is
deliberately conservative until benchmark results are persisted as a validated
selection table.

Environment variables:

| Variable | Default | Meaning |
| --- | ---: | --- |
| `CLINIC_GIBBERLINK_PROTOCOL` | `2` | Preferred ggwave protocol ID |
| `CLINIC_GIBBERLINK_FRAME_DATA` | `100` | Target base64 characters per frame |
| `CLINIC_GIBBERLINK_SILENCE_MS` | `100` | Acoustic gap between frames |

The frame builder reduces the piece size when the versioned prefix would exceed
ggwave's practical payload limit. The hard audio and frame limits remain in
force before decode and reassembly.

## Fallback

If an authenticated request produces a signed reply that cannot fit the chosen
audio profile, the clinic returns a signed JSON fallback envelope with:

```json
{
  "status": "fallback",
  "reason": "audio-reply-too-large",
  "fallback": {
    "transport": "http-val",
    "endpoint": "/clinic",
    "action": "retry-signed-envelope"
  }
}
```

An oversized or malformed unauthenticated audio body cannot receive a
request-specific signed response, so it is rejected before decode or signature
work. The agent card provides the HTTP VAL fallback for capability and size
negotiation.

## Security boundary

The codec is a transport encoding, not an identity mechanism:

- compression does not authenticate data;
- the public key carried by an envelope is not trusted merely because audio
  delivered it;
- the receiver must resolve the sender key from an anchored registry or prior
  trusted relationship;
- signature, freshness, replay, session, rate, and schema checks remain in the
  shared clinic transport layer;
- codec version and profile selection must not weaken the signed VAL checks.

The transport bytes may be compacted, but the signed envelope semantics and
verification preimage are not changed by this optimisation.

## Benchmarking

Run the deterministic offline benchmark from the repository root:

```powershell
python clinic/clinic_audio_benchmark.py --output artifacts/bandwidth-v1.json
```

Useful options:

```powershell
python clinic/clinic_audio_benchmark.py --sizes 64,256,1024 --protocols 0,1,2
python clinic/clinic_audio_benchmark.py --frame-data 80 --silence-ms 50
python clinic/clinic_audio_benchmark.py --drop-every 5
```

The report records logical bytes, compressed bytes, audio bytes, duration,
effective payload bytes per second, CPU time, and complete-exchange success.
WAV size is not treated as useful bandwidth. A mode is eligible for automatic
selection only after it reaches the 99% complete-exchange target across the
reviewed matrix.

## Known limitations

- The initial benchmark uses loopback waveforms and deterministic impairment;
  it is not a substitute for speaker/microphone or phone-call testing.
- Base64 remains in the first version because the current Python ggwave path
  uses textual frame payloads. Its overhead is measured explicitly.
- The current selection policy is conservative and not yet adaptive to a
  channel-specific reliability history.
- The current Python wrapper retains completed-frame state, so the decoder uses
  one bounded ggwave instance per separated frame. A streaming reuse optimisation
  requires an explicit reset API from the wrapper and is not enabled.
- Audio is intentionally unsuitable for large replies, continuous streams, or
  ordinary internet-connected agent traffic. HTTP should be selected instead.
