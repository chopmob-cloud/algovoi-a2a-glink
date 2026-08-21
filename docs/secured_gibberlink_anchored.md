# Secured gibberlink, anchored: the real published resolver

## Answer first

`secured_gibberlink_anchored.py` replaces the showcase's hardcoded `KeyAnchorRegistry`
dict with a resolver backed by the real, pip-installed `algovoi-rfc9421-keyid` 0.1.0. The
layered trust anchor: `did:key` is the offline floor, a Falcon-1024 signed
directory carries named identities, `did:web` is an opt-in online fallback behind an SSRF
domain allowlist, and TOFU pins bootstrap unlisted peers. Every key that leaves the
registry passes the verifier's weak-key gate first. The self-test is 18 of 18 PASS and
transport is 12 of 12 byte-exact. Nothing cryptographic is stubbed. The one test-shaped
shortcut is that the directory root keypair is generated in-process for the self-test
instead of loaded from cold storage. The Falcon signature over that key is produced and
verified for real.

## What is real

- **did:key offline resolution.** Agent B's keyid is a genuine `did:key:z...` produced by
  `encode_did_key(B.public_key)`. `resolve_keyid` decodes it with no network (source
  `inline`) back to B's exact public key. The self-test asserts the decode matches B and
  that the source is `inline`.
- **The weak-key gate.** `check_ed25519_public_key` runs on every key the registry returns,
  pinned or cached or resolved, before it is trusted. A small-order key listed in the
  verified directory is rejected at resolve time (returns `None`), so it never reaches the
  verifier. Case 12 proves this on the resolver cache path with a clear message.
- **The SSRF domain allowlist.** `did:web` resolution is opt-in. When enabled, the host is
  checked against a domain allowlist before any DNS or connect. The self-test injects a DNS
  resolver that raises if it is ever called, and confirms an out-of-allowlist host is
  rejected with zero network egress (case 11). This is the single most important hardening
  the design called for on top of the resolver's own private-IP blocklist.
- **The Falcon-1024 signed directory, both sides.** The signer produces a real Falcon-1024
  signature over the JCS-canonical payload bytes (`rfc8785.dumps`), the same shape as
  a JCS-canonical signed-registry pattern (kid is `sha256(pubkey)[:16]`, a `valid_until` auto-expiry).
  The loader verifies that signature with the real `pqcrypto` verify path, checks the root
  key against a trusted root supplied out of band, checks the kid, and checks freshness, and
  only then populates the resolver cache. A tampered directory (case 16) and a stale
  directory (case 15) both fail closed at load.
- **TOFU pinning.** A small JSON pin file maps keyid to key hex. First contact pins, a later
  different key for the same keyid is a pin mismatch and is rejected (case 14).
- **The anchor policy is reused unchanged.** `anchor_gate` and `anchored_verify` are imported
  verbatim from the showcase and fed the new registry. The keyid is read only from the SIGNED
  `Signature-Input`, never a mutable top-level field, and the inline key must equal the
  anchored key. Verification always runs against the anchored key.

## One security decision worth stating

A `did:key` is self-certifying, not self-authorizing. Anyone can mint a valid one. If the
registry accepted any resolvable `did:key`, an attacker who signs with their own key under
their own `did:key` would be accepted, which would silently break the showcase's core "reject
unknown keyid" property. So the registry treats an inline `did:key` as trusted only when a
pin or the verified directory vouches for it. Case 4b proves this: an attacker's own
well-formed `did:key` decodes offline but `registry.resolve` returns `None`, so it is
rejected. This is stronger than the base showcase, which relied on the attacker choosing a
malformed keyid string. The behavior is behind an explicit `accept_any_did_key=False` default.

## What is stubbed or shortcut, stated honestly

- **Nothing cryptographic is stubbed.** Falcon signing and verification, JCS canonicalization,
  Ed25519 signing and verification, the weak-key gate, and the SSRF guard all run for real.
- **The directory root keypair is ephemeral in the self-test.** `generate_keypair()` mints it
  in-process. In production this is a cold-storage Falcon root key held offline.
  The signature over it is genuine either way, so this is a test fixture, not a crypto stub.
- **No live `did:web` fetch is exercised.** By design, to avoid network egress, the SSRF test
  asserts the guard rejects the host before any fetch. The cache and guard code paths are the
  real ones; only a real remote GET is not performed.

## The trust-root boundary

The verifier proves "signed by the anchored key" and nothing more. The anchor proves "this
key belongs to this identity," and its root is out of scope for the verifier. The root sits
at one of four places depending on the tier: the private-key holder for `did:key`, the
domain's TLS plus DNS plus well-known path for `did:web`, the directory's Falcon signing root
key for the signed directory, or the party present at first contact for TOFU. Compromise of
that root is the one thing this design does not defend, by construction. The claim is bounded:
given an authentic anchored key for Agent B, A verifies B's messages over any channel with
tamper, replay, and key-swap detection, offline. The anchor is what makes the key authentic,
and its compromise, not the verifier's correctness, is the residual risk. The anchor does not
remove trust, it relocates trust from the wire to a named, auditable root and states plainly
where that root sits.

## Run it

```
cd clinic
python secured_gibberlink_anchored.py
```

Expected: an 18 row PASS table, the trust-anchor diagnostics all True, and 12 of 12 transport
reliability.
