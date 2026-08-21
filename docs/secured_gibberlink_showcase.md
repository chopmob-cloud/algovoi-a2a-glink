# Secured Gibberlink Showcase

A local, adversarially tested build that takes the secured gibberlink testbed and closes
its one deliberate security gap, then proves the fix under a full attack battery. Nothing
is sent to anyone. Only the verifier can be run live, against our own endpoint.

Files:
* `secured_gibberlink_showcase.py` (this build, new file, imports the base testbed unchanged)
* `secured_gibberlink_demo.py` (base testbed, transport plus signer, not modified)

Reproduce the security core exactly with `pip install "algovoi-rfc9421-verifier==0.4.4" ggwave pynacl`.

## What it demonstrates

Two AI agents exchange a signed payment authorization over a sound channel (gibberlink /
ggwave), and the receiver proves who said what using AlgoVoi's published RFC 9421 verifier.
The showcase runs the honest path and then eight distinct attacks, each executed in real
code, and prints a PASS/FAIL table plus a transport reliability count.

## The gap, and the fix (keyid anchoring)

The base testbed ends on a real, deliberate wound. The verifier proves "signed by THIS
key", not "signed by agent B", because the sender's public key rides INSIDE the envelope
over the untrusted channel. An attacker who intercepts the audio can strip B's key, insert
their own key, rewrite the body, re-sign with their own key, and the envelope verifies
against the attacker's inline key. Cryptographically valid, semantically a forgery.

We confirmed this is not hypothetical. The pre-fix, inline-key verification path accepts an
attacker re-signed envelope whose amount has been changed from 12.50 to 999.00:

```
4a. Key-swap re-sign under B's keyid   PRE-FIX base(inline) accepted=True (amount 999.00)
```

### The fix

Agent A never trusts the key that arrived over the wire. A maintains a trusted keyid to
pinned public key registry (`KeyAnchorRegistry`), which stands in for an out of band trust
source (a directory, or a prior handshake). On every message A:

1. resolves the sender's keyid from the SIGNED `Signature-Input` parameters (not the
   unsigned top level `keyid` field, which is attacker mutable metadata),
2. REJECTS if that keyid is unknown to the registry,
3. REJECTS if the public key carried in the envelope does not equal the anchored pin,
   all BEFORE any signature is trusted,
4. then verifies the signature against the ANCHORED key, never the envelope's inline key.

### Before and after, on the same key-swap attack

* Before (inline key trust): the attacker's re-signed, body-altered envelope is ACCEPTED.
* After (anchored): the same envelope is REJECTED at the anchor gate.
  * If the attacker keeps B's keyid but swaps the key, the anchor gate fails on key
    mismatch (inline key does not equal the pin).
  * If the attacker uses their own keyid, the anchor gate fails on unanchored keyid
    (unknown to the trust registry).

The forgery never even reaches the signature check. The channel still cannot tell A which
key is really B's. Anchoring supplies that from out of band, which is the whole secure
usage rule for agent to agent gibberlink.

## Adversarial results table

Every row below was executed. Local run, anchored secure policy.

```
#  case                                       expect   observed  stage   result
1. Happy path (anchored, via sound)           ACCEPT   accept    verify  PASS
2. Body tamper (amount 12.50->92.50)          REJECT   reject    verify  PASS
3. Replay past expiry (now=t0+4000s)          REJECT   reject    verify  PASS
4a. Key-swap re-sign under B's keyid          REJECT   reject    anchor  PASS
4b. Key-swap re-sign under attacker keyid     REJECT   reject    anchor  PASS
5. Small-order Ed25519 public key             REJECT   reject    verify  PASS
6a. Algorithm omission (no alg param)         REJECT   reject    verify  PASS
6b. Algorithm downgrade (alg not allowed)     REJECT   reject    verify  PASS
7. Content-Digest present but not covered     REJECT   reject    verify  PASS
8. Wrong tag when required                    REJECT   reject    verify  PASS
9. Nonce replay (same nonce twice)            REJECT   reject    verify  PASS
OVERALL: ALL PASS  (11/11)
```

Notes on each, with the actual rejection reason observed:

1. Happy path. Signed by B, keyid anchored, sent through the sound hop, decoded byte exact,
   verified against the anchored key. Accepted.
2. Body tamper. Amount edited after signing. Rejected on Content-Digest (header digest does
   not match the body hash).
3. Replay past expiry. A genuine message re-presented at t0 plus 4000 seconds. Rejected on
   freshness (older than the maximum allowed age, past its expires).
4a. Key-swap under B's keyid. Attacker re-signs an altered body with their own key, keeps
    B's keyid. Rejected at the anchor gate on key mismatch. (Base inline-key path accepted
    it, which is the gap this build closes.)
4b. Key-swap under the attacker's own keyid. Rejected at the anchor gate on unanchored
    keyid. (Base inline-key path accepted it.)
5. Small-order Ed25519 key. Even with the weak key deliberately anchored (a misconfigured
   directory), the library's key gate rejects it before verification (small-order Ed25519
   point). The anchor is not the last line of defense here, the key gate is.
6a. Algorithm omission. The `alg` parameter is dropped. Rejected (missing alg is a
    downgrade by omission vector, the library refuses to default it).
6b. Algorithm downgrade. Verifier configured to allow only rsa-pss-sha512, the message
    presents ed25519. Rejected (alg not in the allowed set). This exercises the allow-list
    pin in both directions.
7. Content-Digest present but not covered. A genuinely signed envelope whose signature does
   not cover content-digest. Rejected (Content-Digest required but not a covered component).
   Matching the digest to the body is necessary but not sufficient, it must also be signed.
8. Wrong tag. A genuinely signed envelope carrying tag "not-the-tag" while the verifier
   requires "algovoi-val-demo". Rejected on tag mismatch.
9. Nonce replay. The same nonce presented twice through the `verify_request` nonce_seen
   callback (backed by a seen set). First accepted, second rejected (nonce already used).

Everything in the battery is expressible with the shipped library 0.4.4. Nothing had to be
faked or stubbed. The only piece outside the library is the anchor gate, which is A's
client-side trust policy and is exactly what the library cannot decide for you (which key
is really B's).

## Transport reliability

The showcase re-runs the full sign, ggwave encode, .wav write, decode, byte-exact compare
loop and counts successes. Observed:

```
sign -> ggwave -> .wav -> decode -> byte-exact match: 20/20 runs
transport is 100% reliable under the showcase.
```

The base testbed's silence-separated framing plus segment-on-silence decoding holds at 100%
under the showcase. No dropped frames, so no transport blocker.

## Live verification proof

Run with `--live`. The decoded envelope is POSTed to the deployed verifier at
`https://verify.algovoi.co.uk/rfc9421`, verifying the signature against the ANCHORED key.
Observed:

* genuine, anchored: live service returns `valid:true, signature_valid:true,
  content_digest_valid:true`.
* tampered body: live service returns `valid:false, signature_valid:true,
  content_digest_valid:false` (the signature is over the original preimage, the digest no
  longer matches the swapped body).
* key-swap forgery: BLOCKED client side by the anchor gate before any network call. The
  envelope is never sent, because anchoring is A's policy, not the wire's or the service's.

That last point matters. The live service verifies a signature against whatever public key
you hand it, so the anchor decision (which key to hand it) has to be made by A before the
POST. The showcase substitutes the anchored key as `public_key_hex` on the live request.

## The three production findings (carried from the base live loop)

These are real reachability and contract findings for agent clients hitting the live
verifier, confirmed 2026-08-17 and reused here.

1. Path mismatch. The GET descriptor advertises `POST /verify/rfc9421`, but that path 404s.
   The real endpoint is `POST /rfc9421`. Descriptor bug.
2. Cloudflare User-Agent gate. Cloudflare fronts the verifier and 403s the default
   `Python-urllib` User-Agent. A normal User-Agent passes. Agent clients using stock urllib
   will be blocked until they set a UA.
3. Lowercase header keys. The service's input schema wants lowercase header keys, so the
   client lowercases `Content-Digest`, `Signature-Input`, `Signature` before POSTing.

## Honest boundaries

* The sound hop is a ggwave codec written to a real .wav file and read back, a loopback
  stand-in for a real speaker to microphone acoustic hop. The codec is genuine gibberlink
  ggwave, the acoustic channel is simulated by the file.
* Only the verifier is live. Everything else (signing, transport, the anchor gate, the
  attacks) runs locally on this bench.
* No facilitator, no MCP, no chain settlement, no payment rail. The payload is a demo
  payment authorization, self-generated throwaway keys, no secrets.
* No fabricated adoption. This is a bench experiment plus one live call to our own endpoint,
  not a claim that anyone is using it.

## Verdict

Showcase ready. The in-envelope key-swap attack is genuinely closed by keyid anchoring
(both variants rejected at the anchor gate, and the pre-fix path is shown accepting the
same forgery for contrast). The full adversarial battery is 11/11 PASS, transport is 20/20
reliable, and the live verifier confirms accept on genuine and reject on tampered.
