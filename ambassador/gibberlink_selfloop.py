#!/usr/bin/env python3
"""gibberlink_selfloop.py -- prove the AMBASSADOR speaks NATIVE gibberlink, end to end.

Dogfood: the ambassador (its real Ed25519 identity) acts as a visiting agent and holds a full
native gibberlink conversation with a clinic -- enroll, then send a concrete /explain request as
REAL ggwave audio and verify the clinic's SIGNED audio reply. Uses the ambassador's own
gibberlink_client.py against a clinic listener.

Default: spins up a LOCAL clinic listener (no public traffic) and loops against it -- proves the
outbound client works without touching the live endpoint. Pass a base URL to point it at a real
clinic (e.g. https://agents.algovoi.co.uk) plus --peer-pubkey to verify that clinic's signature.
"""
from __future__ import annotations
import argparse, base64, json, sys, threading, time
from pathlib import Path
from tempfile import NamedTemporaryFile

DIR = Path(__file__).resolve().parent
# The clinic/ codec tree ships alongside this file.
GIBBERLINK_DIR = DIR.parent / "clinic"
sys.path.insert(0, str(DIR))
sys.path.insert(0, str(GIBBERLINK_DIR))

from nacl.signing import SigningKey
import gibberlink_client as glc


def _selfasserted_verify(reply_env):
    """When we have no out-of-band clinic key (e.g. the live endpoint), verify the reply against
    its OWN asserted key. Proves the audio reply is a validly-signed VAL envelope (cryptographic
    integrity + freshness), though NOT identity-anchored. Returns (ok, honest_label)."""
    if not isinstance(reply_env, dict):
        return False, "clinic audio reply signature: no envelope to verify"
    from negotiation_gibberlink_demo import verify_envelope
    kid, pub = reply_env.get("keyid"), reply_env.get("public_key_hex")
    if not (kid and pub):
        return False, "clinic audio reply missing keyid/public_key_hex"
    ok, why, _ = verify_envelope(reply_env, anchored_peers={kid: pub}, expected_keyid=kid,
                                 now=int(time.time()))
    return ok, (f"clinic audio reply signature valid (self-asserted key {kid}={pub[:12]}..., "
                f"NOT anchored out-of-band)" if ok else f"clinic reply signature INVALID: {why}")


def _broken_request() -> dict:
    from clinic_responder import _load_explain
    _explain, sign_demo, _err = _load_explain()
    good = sign_demo({"method": "POST", "authority": "api.example.com", "path": "/v1/pay",
                      "body_b64": base64.b64encode(b'{"amount":10,"to":"acct_9"}').decode(),
                      "covered_components": ["@method", "@authority", "@path", "content-digest"],
                      "keyid": "builder-key"})
    sr = good["signed_request"]; pub = good["ephemeral_key"]["public_key_hex"]
    tampered = base64.b64encode(b'{"amount":9999,"to":"acct_9"}').decode()   # altered after signing
    return {"method": sr["method"], "authority": sr["authority"], "path": sr["path"],
            "scheme": sr["scheme"], "headers": sr["headers"], "body_b64": tampered, "public_key_hex": pub}


def _start_local_clinic(port: int):
    """Start a local clinic listener with native gibberlink enabled. Returns (server, pubkey_hex)."""
    import clinic_listener as cl
    from http.server import ThreadingHTTPServer
    from nacl.signing import SigningKey
    clinic_sk = SigningKey.generate()
    store = NamedTemporaryFile(prefix="amb_gl_enroll_", suffix=".jsonl", delete=False).name
    clinic = cl.Clinic(clinic_sk, {}, open_explain=True, gibberlink_enabled=True, enroll_store=store)
    srv = ThreadingHTTPServer(("127.0.0.1", port), cl.make_handler(clinic))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    return srv, clinic_sk.verify_key.encode().hex()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default=None, help="clinic base URL (default: spin up a local one)")
    ap.add_argument("--peer-pubkey", default=None, help="peer clinic public key hex (to verify its reply)")
    ap.add_argument("--anchor-from-card", action="store_true",
                    help="fetch the clinic's signing pubkey from its agent-card (TLS) and anchor it")
    ap.add_argument("--port", type=int, default=8817)
    a = ap.parse_args()

    srv = None
    base, peer_pub = a.base, a.peer_pubkey
    if a.anchor_from_card and base:
        got = glc.fetch_clinic_pubkey(base)
        if got and got.get("anchorable"):
            peer_pub = got["public_key_hex"]
            print(f"anchored clinic key from card (anchorable): {got['keyid']}={peer_pub[:16]}...")
        elif got:
            print(f"card publishes a key but anchorable=false (ephemeral): {got['keyid']}="
                  f"{got['public_key_hex'][:16]}...; staying self-asserted (do NOT pin a rotating key)")
        else:
            print("clinic card has no published signing key; staying self-asserted")
    if not base:
        srv, peer_pub = _start_local_clinic(a.port)
        base = f"http://127.0.0.1:{a.port}"
        print(f"local clinic up at {base} (gibberlink enabled)")

    # Ephemeral Ed25519 identity for the self-loop (self-enrollment proves key control; no stored secret needed).
    # Derive the keyid FROM the public key so each ephemeral run gets a unique keyid -- a fixed keyid
    # would collide with the clinic's first-write-wins enroll store on any second run against one clinic.
    amb_sk = SigningKey.generate()
    akid = "selfloop-" + amb_sk.verify_key.encode().hex()[:16]
    print(f"ambassador identity: {akid} pub={amb_sk.verify_key.encode().hex()[:16]}...")

    passes = []
    # 1. enroll over the peer's HTTP door (proof-of-key-control)
    er = glc.enroll(base, amb_sk, akid)
    enrolled_ok = bool(er.get("enrolled"))
    passes.append(("ambassador self-enrolled with the clinic", enrolled_ok))
    print(f"1. enroll: {er.get('status')} enrolled={er.get('enrolled')}")

    # 2. native gibberlink exchange: concrete /explain over REAL ggwave audio, verified reply
    inner = {"intent": "clinic_explain", "request": _broken_request()}
    res = glc.exchange(base, amb_sk, akid, inner, peer_pubkey_hex=peer_pub)
    ex = ((res.get("answer") or {}).get("explain") or {}) if res.get("ok") else {}
    served_ok = (res.get("ok") and res.get("status") == "served" and ex.get("valid") is False
                 and (ex.get("content_digest") or {}).get("match") is False)
    # signature: anchored when we hold the peer key (local loop), else self-asserted (live endpoint)
    if peer_pub:
        sig_ok, sig_label = (res.get("sig_verified") is True), "clinic audio reply signature verified (anchored key)"
    else:
        sig_ok, sig_label = _selfasserted_verify(res.get("reply_envelope"))
    passes.append(("native gibberlink /explain served + correct diagnosis", served_ok))
    passes.append((sig_label, sig_ok))
    rep = res.get("reply_envelope") or {}
    if rep.get("public_key_hex"):
        print(f"   clinic asserted key: {rep.get('keyid')}={rep['public_key_hex']}  "
              f"(anchor this out-of-band to upgrade to verified trust)")
    print(f"2. gibberlink /explain: ok={res.get('ok')} audio_in={res.get('audio_in')}B "
          f"audio_out={res.get('audio_out')}B rtt={(res.get('rtt') or 0):.1f}s "
          f"status={res.get('status')} sig_verified={res.get('sig_verified')} "
          f"explain.valid={ex.get('valid')} digest_match={(ex.get('content_digest') or {}).get('match')}")
    if not res.get("ok"):
        print("   detail:", res.get("error") or res.get("peer_json"))
    elif res.get("status") != "served":
        print("   clinic reply (not served):", json.dumps(res.get("answer"))[:300])

    if srv:
        srv.shutdown()
    allok = all(p for _, p in passes)
    print("\n=== AMBASSADOR NATIVE GIBBERLINK SELF-LOOP ===")
    for name, p in passes:
        print(f"  {'PASS' if p else 'FAIL'} {name}")
    print(f"\n{'ALL PASS -- the ambassador speaks native gibberlink (real ggwave, signed, verified)' if allok else 'FAILURES'}")
    return 0 if allok else 1


if __name__ == "__main__":
    sys.exit(main())
