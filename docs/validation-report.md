# Validation report

An independent clean-room run of the test, end-to-end, and benchmark suites at
commit `e816f81`.

## Environment

- A fresh `python:3.11-slim` Docker container with no pre-existing local state.
- Dependencies installed only from the pinned [requirements.txt](../requirements.txt)
  (public PyPI): `algovoi-rfc9421-verifier==0.4.4`, `algovoi-rfc9421-keyid==0.1.0`,
  `ggwave==0.4.3`, `PyNaCl==1.6.2`, `rfc8785==0.1.4`, `pqcrypto==0.4.0`.
  `ggwave` was compiled from source with `g++`.

That a clean container installs the dependencies and runs the suites confirms
`requirements.txt` is complete and the tree is self-contained.

## Test and end-to-end suites

| Suite | What it checks | Result |
| --- | --- | --- |
| `clinic_transport_test.py` | sealed control layer (auth, size/schema, replay, rate/cost, audit) | **PASS 12/12** |
| `validate_negotiation.py` | envelope signing / verification, negative controls | **PASS 19/19** |
| `clinic_gibberlink_test.py` | versioned codec profile selection and framing | **PASS 8/8** |
| `clinic_legacy_compat_test.py` | v1 and v2 gibberlink on one endpoint | **PASS 9/9** |
| `clinic_benchmark.py` | router coverage + fail-closed safety gate | **PASS 12/12** |
| `clinic_listener_e2e.py` | a real running HTTP listener end to end | **PASS** |
| `clinic_gibberlink_e2e.py` | native ggwave audio, signed and sealed, end to end | **PASS** |

`clinic_selftest.py` is a live-integration self-test that requires runtime keys
(`VISITOR_SK_HEX`, `CLINIC_PUB_HEX`) to point at an already-running clinic. It is
not a standalone unit test and is not run in clean CI.

## Bandwidth benchmark

Machine-readable results: [benchmarks/gibberlink-bandwidth.json](../benchmarks/gibberlink-bandwidth.json)
(schema `algovoi.gibberlink.bandwidth.v1`). Nine runs across ggwave protocols
0/1/2 and three payload sizes; every run decoded successfully.

Protocol 2 is the fastest profile. Representative figures:

| Logical payload | Protocol | Audio | Encode | Decode | Effective throughput |
| --- | --- | --- | --- | --- | --- |
| 194 B | 2 | 1.37 MB / 7.16 s | 13.2 ms | 61.0 ms | 27.1 B/s |
| 386 B | 2 | 1.40 MB / 7.29 s | 13.1 ms | 60.6 ms | 53.0 B/s |
| 1154 B | 2 | 1.45 MB / 7.55 s | 14.1 ms | 75.4 ms | 152.9 B/s |

This is the inherent cost of data-over-sound: even the fastest profile is about
1.4 MB of audio for a ~1 KB payload. That is why the transport is bounded hard
(max audio bytes, frame caps, per-peer rate limit, global daily ceiling) and
intended for a low request rate. See [docs/audio-bandwidth.md](audio-bandwidth.md)
for the wire format and acceptance criteria.

## Reproduce

From the repository root:

```bash
docker run --rm -v "$PWD":/work -w /work python:3.11-slim bash -lc '
  apt-get update && apt-get install -y --no-install-recommends g++
  pip install -r requirements.txt
  cd clinic
  python clinic_audio_benchmark.py
  for t in clinic_transport_test validate_negotiation clinic_gibberlink_test \
           clinic_legacy_compat_test clinic_benchmark clinic_listener_e2e \
           clinic_gibberlink_e2e; do
    echo "== $t =="; python "$t.py"
  done'
```
