#!/usr/bin/env python3
"""Offline unit tests for the sealed-transport control layer (no crypto deps: signature is stubbed).

Exercises every fail-closed control: oversized frame, malformed json, missing schema fields, unenrolled
peer, bad signature, per-peer rate limit, global daily cap, replay, the happy path, and audit-chain tamper
detection. Exit 0 iff all pass."""
from __future__ import annotations
import json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clinic_transport as t

ENROLLED = {"agent-1", "agent-2"}


def frame(keyid="agent-1", q="how do I build the signing base?", nonce="n1", sig_ok=True, drop=None,
          headers_ok=True, bloat=0) -> bytes:
    env = {"method": "POST", "authority": "visiting-agent", "path": "/clinic", "scheme": "https",
           "headers": {"Content-Digest": "sha-256=:x:", "Signature-Input": "sig1=(...)",
                       "Signature": "sig1=:x:"},
           "body_b64": "", "public_key_hex": "deadbeef", "keyid": keyid,
           "_q": q, "_nonce": nonce, "_sig_ok": sig_ok}
    if not headers_ok:
        env["headers"].pop("Signature", None)
    if drop:
        env.pop(drop, None)
    if bloat:
        env["_pad"] = "A" * bloat
    return json.dumps(env).encode()


def stub_verify(env, now):
    keyid = env.get("keyid")
    if keyid not in ENROLLED:
        return False, "unenrolled-peer", keyid, None, None
    if not env.get("_sig_ok", True):
        return False, "bad-signature", keyid, None, None
    return True, "ok", keyid, env.get("_nonce"), {"q": env.get("_q", "")}


def stub_responder(body):
    q = (body.get("q") or "")
    return {"topic": "signing-base", "answer": f"answer to: {q[:30]}", "links": []}


def run():
    results = []

    def kit():
        return dict(replay=t.ReplayCache(), limiter=t.RateLimiter(), audit=t.AuditLog(),
                    verify_fn=stub_verify, responder_fn=stub_responder)

    def check(name, status, want_status, want_reason_sub=None, payload=None):
        ok = (status == want_status)
        if ok and want_reason_sub is not None:
            ok = want_reason_sub in (payload or {}).get("error", "")
        results.append((name, ok, status, (payload or {}).get("error", "")))

    # 1. oversized
    st, pl = t.handle_frame(frame(bloat=t.MAX_FRAME_BYTES + 100), now=1000, **kit())
    check("oversized-frame", st, "rejected", "too large", pl)
    # 2. malformed json
    st, pl = t.handle_frame(b"{not valid json", now=1000, **kit())
    check("malformed-json", st, "rejected", "malformed json", pl)
    # 3. missing top-level field
    st, pl = t.handle_frame(frame(drop="keyid"), now=1000, **kit())
    check("missing-field", st, "rejected", "missing field", pl)
    # 4. missing header
    st, pl = t.handle_frame(frame(headers_ok=False), now=1000, **kit())
    check("missing-header", st, "rejected", "missing header", pl)
    # 5. unenrolled peer
    st, pl = t.handle_frame(frame(keyid="stranger"), now=1000, **kit())
    check("unenrolled-peer", st, "rejected", "unenrolled", pl)
    # 6. bad signature
    st, pl = t.handle_frame(frame(sig_ok=False), now=1000, **kit())
    check("bad-signature", st, "rejected", "bad-signature", pl)
    # 7. happy path
    k = kit()
    st, pl = t.handle_frame(frame(nonce="h1"), now=1000, **k)
    ok = (st == "served" and pl.get("topic") == "signing-base" and k["audit"].records[-1]["event"] == "served")
    results.append(("happy-path", ok, st, ""))
    # 8. per-peer rate limit (default 6/window); 7th same peer, distinct nonces, fixed now
    k = kit()
    last = None
    for i in range(7):
        last = t.handle_frame(frame(nonce=f"r{i}"), now=2000, **k)
    check("peer-rate-limit", last[0], "rejected", "peer-rate", last[1])
    # 9. global daily cap
    k = dict(replay=t.ReplayCache(), limiter=t.RateLimiter(per_peer=100, global_day=3),
             audit=t.AuditLog(), verify_fn=stub_verify, responder_fn=stub_responder)
    last = None
    for i in range(4):
        last = t.handle_frame(frame(nonce=f"g{i}"), now=3000, **k)
    check("global-daily-cap", last[0], "rejected", "global-daily-cap", last[1])
    # 10. replay (same nonce twice, fresh kit so rate is fine)
    k = kit()
    t.handle_frame(frame(nonce="dup"), now=4000, **k)
    st, pl = t.handle_frame(frame(nonce="dup"), now=4001, **k)
    check("replay", st, "rejected", "replay", pl)
    # 11. audit chain integrity + tamper detection
    k = kit()
    for i in range(3):
        t.handle_frame(frame(nonce=f"a{i}"), now=5000, **k)
    intact = k["audit"].verify_chain()
    k["audit"].records[0]["reason"] = "tampered"
    broken = not k["audit"].verify_chain()
    results.append(("audit-chain-intact", intact, "verify_chain", ""))
    results.append(("audit-tamper-detected", broken, "verify_chain", ""))

    print("=== SEALED-TRANSPORT CONTROL TESTS ===")
    allok = True
    for name, ok, status, err in results:
        allok &= ok
        print(f"  {'PASS' if ok else 'FAIL'} {name:<22} ({status}{(' :: '+err) if err else ''})")
    print(f"\nRESULT: {'ALL PASS' if allok else 'FAILURES'}  ({sum(o for _,o,_,_ in results)}/{len(results)})")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(run())
