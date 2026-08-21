#!/usr/bin/env python3
"""validate_negotiation.py -- independent, adversarial validation of the two-way
negotiation bench. Does NOT trust the demo's printed booleans; it re-exercises the
shipped verifier directly and includes NEGATIVE CONTROLS (things that MUST pass when
they should, and MUST fail when they should), so a hollow/no-op check is caught.

Exit code 0 only if every assertion holds.
"""
from __future__ import annotations
import base64, json, time, sys

from nacl.signing import SigningKey
from negotiation_gibberlink_demo import (
    sign_envelope, verify_envelope, check_transcript, envelope_hash, over_sound, TAG, TTL,
    compute_transcript_hash, check_transcript_commitment,
)

t0 = int(time.time())
results = []
def check(name, cond):
    results.append((name, bool(cond)))
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")

key_a = SigningKey.generate()
key_b = SigningKey.generate()
keyid_a = "did:key:z-agentA-test"
keyid_b = "did:key:z-agentB-test"
a_knows = {keyid_b: key_b.verify_key.encode().hex()}          # A trusts B
b_knows = {keyid_a: key_a.verify_key.encode().hex()}          # B trusts A
session = "testsession01"

def body(seq, prev, **kw):
    return json.dumps({"session_id": session, "seq": seq, "prev_hash": prev, **kw},
                      separators=(",", ":")).encode()

print("1. Signature is REAL (positive + negative control)")
env = sign_envelope(key_a, keyid_a, authority="agent-a.local",
                    body=body(0, "", role="buyer", intent="offer", amount="8.00"), created=t0)
ok, reason, b = verify_envelope(env, anchored_peers=b_knows, expected_keyid=keyid_a, now=t0 + 1)
check("genuine message verifies against A's anchored key", ok)
# NEGATIVE CONTROL: same keyid but WRONG anchored public key -> must fail (proves verify is not a no-op)
wrong = {keyid_a: key_b.verify_key.encode().hex()}
okw, rw, _ = verify_envelope(env, anchored_peers=wrong, expected_keyid=keyid_a, now=t0 + 1)
check("same message against the WRONG anchored key is rejected", (not okw))

print("2. Body binding (Content-Digest)")
tampered = json.loads(json.dumps(env))
tb = json.loads(base64.b64decode(tampered["body_b64"])); tb["amount"] = "9999.00"
tampered["body_b64"] = base64.b64encode(json.dumps(tb, separators=(",", ":")).encode()).decode()
okt, rt, _ = verify_envelope(tampered, anchored_peers=b_knows, expected_keyid=keyid_a, now=t0 + 1)
check("tampered amount is rejected on digest", (not okt) and ("igest" in rt))

print("3. Key anchoring (the negotiation trust rule)")
attacker = SigningKey.generate()
forged = sign_envelope(attacker, "did:key:z-unknown", authority="agent-a.local",
                       body=body(0, "", role="buyer", intent="offer", amount="1.00"), created=t0)
okf, rf, _ = verify_envelope(forged, anchored_peers=b_knows, expected_keyid=keyid_a, now=t0 + 1)
check("message with an UNANCHORED keyid is refused", (not okf) and ("anchor" in rf.lower()))
# attacker uses the RIGHT keyid but their own key -> must still fail (swap-both-key attack)
forged2 = sign_envelope(attacker, keyid_a, authority="agent-a.local",
                        body=body(0, "", role="buyer", intent="offer", amount="1.00"), created=t0)
okf2, rf2, _ = verify_envelope(forged2, anchored_peers=b_knows, expected_keyid=keyid_a, now=t0 + 1)
check("attacker key under A's keyid still fails signature", (not okf2))

print("4. Freshness / replay window")
old = sign_envelope(key_a, keyid_a, authority="agent-a.local",
                    body=body(0, "", role="buyer", intent="offer", amount="8.00"), created=t0 - (TTL + 50))
oko, ro, _ = verify_envelope(old, anchored_peers=b_knows, expected_keyid=keyid_a, now=t0)
check("stale message past the freshness window is rejected", (not oko))

print("5. Transcript chaining (ordering / session)")
okc, _ = check_transcript({"session_id": session, "seq": 3, "prev_hash": "abc"},
                          session_id=session, expected_seq=3, expected_prev="abc")
check("correct seq + session + prev_hash accepted", okc)
bad1, _ = check_transcript({"session_id": session, "seq": 0, "prev_hash": "abc"},
                           session_id=session, expected_seq=3, expected_prev="abc")
check("wrong seq (reorder/replay) rejected", (not bad1))
bad2, _ = check_transcript({"session_id": "other", "seq": 3, "prev_hash": "abc"},
                           session_id=session, expected_seq=3, expected_prev="abc")
check("wrong session_id (cross-session splice) rejected", (not bad2))
bad3, _ = check_transcript({"session_id": session, "seq": 3, "prev_hash": "WRONG"},
                           session_id=session, expected_seq=3, expected_prev="abc")
check("broken prev_hash (transcript tamper) rejected", (not bad3))

print("6. The ggwave SOUND hop actually round-trips the envelope")
got, frames = over_sound(env, "validate_roundtrip")
check(f"decoded envelope identical after the sound hop ({frames} samples)", got == env)
okr, _, _ = verify_envelope(got, anchored_peers=b_knows, expected_keyid=keyid_a, now=t0 + 1)
check("the sound-decoded envelope still verifies", okr)

print("7. Acceptance commitment: intent, format, non-empty, and recompute all enforced")
e1 = sign_envelope(key_a, keyid_a, authority="agent-a.local",
                   body=body(0, "", role="buyer", intent="offer", amount="8.00"), created=t0)
e2 = sign_envelope(key_b, keyid_b, authority="agent-b.local",
                   body=body(1, "", role="seller", intent="counter", amount="12.00"), created=t0 + 1)
seen = [e1, e2]
good_commit = {"intent": "accept", "agreed_transcript_sha256": compute_transcript_hash(seen)}
okc, _ = check_transcript_commitment(good_commit, seen)
check("correct commitment (well-formed, right transcript, accept intent) is accepted", okc)
# wrong transcript hash (well-formed value, but not the transcript)
bad_commit = {"intent": "accept", "agreed_transcript_sha256": "0" * 64}
okb, _ = check_transcript_commitment(bad_commit, seen)
check("well-formed commitment to a WRONG transcript is rejected", (not okb))
# negative control: same commitment, but receiver saw a different transcript -> reject
okd, _ = check_transcript_commitment(good_commit, [e1])
check("correct-looking commitment against a different seen transcript is rejected", (not okd))
# NEW (from review): missing commitment
okm, _ = check_transcript_commitment({"intent": "accept"}, seen)
check("missing transcript commitment is rejected", (not okm))
# NEW: empty seen transcript with the hash-of-nothing
oke, _ = check_transcript_commitment(
    {"intent": "accept", "agreed_transcript_sha256": compute_transcript_hash([])}, [])
check("empty-transcript commitment (hash of nothing) is rejected", (not oke))
# NEW: malformed commitment (not 64 hex)
okf, _ = check_transcript_commitment({"intent": "accept", "agreed_transcript_sha256": "NOTHEX"}, seen)
check("malformed (non-hex/short) commitment is rejected", (not okf))
# NEW: wrong intent (a non-acceptance message must not pass as a deal)
okg, _ = check_transcript_commitment(
    {"intent": "offer", "agreed_transcript_sha256": compute_transcript_hash(seen)}, seen)
check("a non-acceptance message (wrong intent) is rejected", (not okg))

print()
passed = sum(1 for _, ok in results if ok)
total = len(results)
print(f"VALIDATION: {passed}/{total} checks passed")
if passed != total:
    print("FAILED:", [n for n, ok in results if not ok])
    sys.exit(1)
print("ALL CHECKS PASSED")
