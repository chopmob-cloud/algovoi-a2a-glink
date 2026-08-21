# AlgoVoi A2A GibberLink

Verifiable agent-to-agent communication: RFC 9421-signed messages carried over
either ordinary HTTP or a native audio ("gibberlink") channel, with a live
signing clinic that any agent can send a broken signed request to and get a
diagnosis back.

The security core is transport-independent by design. The same signed VAL
envelope (RFC 9421 HTTP Message Signatures over an Ed25519 key, with an RFC 9530
Content-Digest and RFC 8785 canonical JSON) verifies identically whether it
arrived as JSON over HTTPS or as data-over-sound.

## Why

- **HTTP** is the primary transport for ordinary agent communication.
- **GibberLink** is an audio-only channel for constrained or cross-device hops:
  two agents that recognise each other drop to an efficient data-over-sound
  protocol (via [ggwave](https://github.com/ggerganov/ggwave)).
- **Signed envelopes** provide identity and integrity independently of the
  transport, so switching channels never weakens the trust model.

Audio is not free: a ~700-byte envelope is on the order of megabytes of waveform
and seconds of CPU to encode and decode. The transport is therefore bounded hard
(max audio bytes, frame caps, per-peer rate limits, a global daily ceiling) and
is intended for a low request rate. See
[docs/audio-bandwidth.md](docs/audio-bandwidth.md) for the wire format,
compression, and benchmark acceptance criteria.

## Layout

```
clinic/        the RFC 9421 signing clinic and its native gibberlink transport
ambassador/    the outbound side: speak native gibberlink to a peer clinic
a2a-gateway/   an A2A JSON-RPC front door (/a2a message/send) + agent card
docs/          wire format, design notes, and validation records
```

Key modules in `clinic/`:

- `clinic_gibberlink.py` — the native ggwave audio codec (versioned frame
  format, RFC 8785 canonical JSON, zlib compression, bounded decoder lifecycle).
- `negotiation_gibberlink_demo.py` — VAL envelope sign / verify helpers, the
  single source of truth reused by the ambassador.
- `clinic_listener.py`, `clinic_responder.py`, `clinic_transport.py` — the
  clinic itself: signed VAL over `/clinic`, native gibberlink over
  `/clinic/gibberlink`, and an open plain-JSON explain path over
  `/clinic/explain`. The sealed control layer (schema and size bounds, signature
  check against an anchored key, replay cache, rate and cost caps, an audit
  chain) is transport-agnostic and fail-closed.
- `secured_gibberlink_{demo,showcase,anchored}.py` — end-to-end signed audio
  exchanges, including anchored (out-of-band pinned key) trust.
- `verifier_tool.py` — an offline RFC 9421 verifier.
- `*_test.py`, `*_e2e.py`, `redteam_clinic.py`, `validate_negotiation.py` —
  self-test, end-to-end, and injection red-team suites.

## Quickstart

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# fast checks (no audio device needed; ggwave is a pure codec)
python clinic/clinic_transport_test.py            # sealed control layer
python clinic/validate_negotiation.py             # envelope signing / verification
python clinic/clinic_gibberlink_test.py           # versioned codec profile
python clinic/clinic_audio_benchmark.py           # machine-readable bandwidth benchmark
```

Runtime dependencies (installed, not vendored): `ggwave`, `PyNaCl`, `rfc8785`,
`pqcrypto`, and the `algovoi-rfc9421-verifier` / `algovoi-rfc9421-keyid`
packages. Exact pins are in [requirements.txt](requirements.txt).

## Security boundary

Audio transport is not an identity system. Counterparty keys must be anchored
out of band before signed messages from them are accepted; the audio channel
only carries the envelope, it never establishes trust. Every message retains
freshness, replay protection, session binding, and an explicit transport
representation. Anchoring a key from a network source requires HTTPS. The
listener binds to loopback by default; opening it to a network is a deliberate,
separate step.

## Live services

The signing tools referenced here run publicly and are free to use:

- Offline verifier: `POST https://verify.algovoi.co.uk/rfc9421` returns the
  verdict (`valid`, `signature_valid`, `content_digest_valid`) to any client.
- The clinic front door speaks A2A at `https://agents.algovoi.co.uk/a2a`.

## Status

This is an open reference implementation. No production adoption is claimed; it
is offered for the agent ecosystem to study, verify against, and build on.

Every suite and the bandwidth benchmark were run in a fresh `python:3.11-slim`
container with dependencies from `requirements.txt` only; results are in
[docs/validation-report.md](docs/validation-report.md) and
[benchmarks/gibberlink-bandwidth.json](benchmarks/gibberlink-bandwidth.json).

## License

Apache License 2.0. See [LICENSE](LICENSE). Attribution and third-party
acknowledgements (ggwave, the RFCs, PyNaCl, and others) are in [NOTICE](NOTICE).
Reuse with credit is welcome.
