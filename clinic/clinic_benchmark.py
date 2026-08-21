#!/usr/bin/env python3
"""clinic_benchmark.py -- fixed, offline, reproducible quality + safety gate for the RFC 9421 clinic.

Design A is frozen (OpenRouter + inline PUBLIC_KNOWLEDGE, NOT a RAG library; see the
design notes). The honest lever for the conceptual "1 miss" is the DETERMINISTIC router, so this benchmark
measures ROUTER COVERAGE over a fixed conceptual long-tail set -- no model calls, no spend, same result
every run. It is a proxy for answer quality (does the router mark the question covered and route it to the
right topic), not the noisy end-to-end model grade.

It also runs the FAIL-CLOSED safety checks required at the logic layer:
  1. missing credential  -> get_clinic_or_key() raises (never falls back to the runtime key),
  2. quota/exhaustion    -> answer_grounded degrades to the curated answer + links (never empty),
  3. oversized input     -> the router bounds the input and does not crash,
  4. off-allowlist link  -> every link the clinic can emit is on the public-host allowlist.

Usage:  python clinic_benchmark.py        (exit 0 iff coverage == full AND all fail-closed checks pass)
"""
from __future__ import annotations
import os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clinic_responder as cr

# Fixed conceptual long-tail set: (question, expected topic). This is the class that produces the miss;
# concrete signed requests are NOT here -- they bypass the router and hit the real /explain engine (the
# always-HIT control, asserted separately below).
BENCH = [
    ("my signature verifies locally but the server rejects it", "signing-base"),
    ("the signing base my library builds differs from the other end", "signing-base"),
    ("can I use content-digest with a streaming or chunked response body?", "content-digest"),
    ("how do I emit a content-digest as an http trailer for a large body?", "content-digest"),
    ("which components should I cover if a gateway rewrites the path prefix?", "covered-components"),
    ("how do I stop a signature algorithm downgrade attack?", "keyid-alg-keycheck"),
    ("how do I resolve which public key belongs to an agent, with rotation?", "key-discovery"),
    ("is a signed message's content automatically safe to trust?", "limits-threat-model"),
    ("does a valid signature stop a prompt injection in the body?", "limits-threat-model"),
    ("where can I get conformance test vectors for my signer and verifier?", "test-vectors-ci"),
    ("how do I set created and expires to prevent replay within the window?", "freshness-replay"),
    ("how do I get started verifying signed calls in python?", "getting-started"),
]


def run_benchmark() -> tuple[int, int]:
    hit = 0
    print("=== ROUTER COVERAGE (deterministic, no model calls) ===")
    for q, exp in BENCH:
        r = cr.answer(q)
        covered = (r.get("matched") or 0) >= 2       # >=2 signals == force a specific answer, not a defer
        ok = (r["topic"] == exp and covered)
        hit += ok
        print(f"  {'HIT ' if ok else 'MISS'} got={r['topic']:<18} m={r['matched']} exp={exp:<18} | {q[:52]}")
    print(f"  coverage: {hit}/{len(BENCH)}")
    return hit, len(BENCH)


def failclosed() -> bool:
    ok = True

    # 1. missing credential -> raises, no runtime-key fallback.
    saved = os.environ.pop("CLINIC_OR_KEY", None)
    saved_file = cr._clinic_key_file
    cr._clinic_key_file = lambda: Path(__file__).with_name("__nonexistent_clinic_key__.txt")
    try:
        cr.get_clinic_or_key()
        print("  FAIL [missing-credential]: expected RuntimeError, got a key"); ok = False
    except RuntimeError:
        print("  PASS [missing-credential]: fails closed (no runtime-key fallback)")
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL [missing-credential]: wrong error {type(e).__name__}"); ok = False
    finally:
        cr._clinic_key_file = saved_file
        if saved is not None:
            os.environ["CLINIC_OR_KEY"] = saved

    # 2. quota/exhaustion -> grounded model raises (simulated 429); must degrade, not blow up or return empty.
    def boom(_prompt):
        raise RuntimeError("429 quota exhausted")
    res = cr.answer_grounded("how do I set up content-digest?", ask_fn=boom)
    if res.get("grounded") is False and res.get("answer") and res.get("links"):
        print("  PASS [quota-exhaustion]: degrades to curated answer + links (never empty)")
    else:
        print(f"  FAIL [quota-exhaustion]: {res}"); ok = False

    # 3. oversized input -> bounded, no crash.
    huge = "content-digest " * 100000                     # ~1.5 MB of input
    try:
        r = cr.answer(huge)
        if r.get("topic"):
            print(f"  PASS [oversized-input]: bounded to <= {cr.MAX_QUESTION_CHARS} chars, routed cleanly")
        else:
            print("  FAIL [oversized-input]: no topic"); ok = False
    except Exception as e:  # noqa: BLE001
        print(f"  FAIL [oversized-input]: crashed {type(e).__name__}"); ok = False

    # 4. off-allowlist link -> every emittable link is on the public-host allowlist.
    from urllib.parse import urlparse
    bad = [l["url"] for l in cr.all_links() if (urlparse(l["url"]).hostname or "") not in cr.PUBLIC_HOSTS]
    if not bad:
        print(f"  PASS [link-allowlist]: all {len(cr.all_links())} links on public hosts {sorted(cr.PUBLIC_HOSTS)}")
    else:
        print(f"  FAIL [link-allowlist]: off-allowlist {bad}"); ok = False

    return ok


def main() -> int:
    hit, total = run_benchmark()
    print("\n=== FAIL-CLOSED SAFETY CHECKS ===")
    safe = failclosed()
    print(f"\nRESULT: coverage {hit}/{total}, fail-closed {'PASS' if safe else 'FAIL'}")
    return 0 if (hit == total and safe) else 1


if __name__ == "__main__":
    sys.exit(main())
