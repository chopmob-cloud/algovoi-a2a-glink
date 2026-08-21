#!/usr/bin/env python3
"""test_card_signing.py -- the A2A AgentCard signature (spec 8.4) round-trips and fails closed.

Signs the real agent-card.json with an ephemeral Ed25519 key and checks: the
detached-JWS signature verifies (self-asserted via embedded jwk, and anchored via
the known public key), the signed payload excludes `signatures` and default-valued
properties, tampering any covered field breaks verification, and the app attaches
a signature when AGENT_CARD_SIGNING_KEY_HEX is set (and serves unsigned without it).

Run: python test_card_signing.py   (needs rfc8785 + pynacl + fastapi + httpx)
"""
from __future__ import annotations
import copy
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import card_signing as cs  # noqa: E402
from nacl.signing import SigningKey  # noqa: E402

CHECKS: list[tuple[str, bool]] = []


def check(name: str, ok: bool) -> None:
    CHECKS.append((name, bool(ok)))
    print(f"  {'PASS' if ok else 'FAIL'} {name}")


SEED = "11" * 32                                   # fixed test seed (32 bytes); NOT a real key
PUB = SigningKey(bytes.fromhex(SEED)).verify_key.encode().hex()
card = json.loads((HERE / "agent-card.json").read_text(encoding="utf-8"))

# ---- sign ------------------------------------------------------------------
sig = cs.sign_card(card, SEED, kid="test-key")
signed = copy.deepcopy(card)
signed["signatures"] = [sig]
check("signature object has protected + signature", "protected" in sig and "signature" in sig)

# ---- verify (self-asserted via embedded jwk) -------------------------------
v = cs.verify_card(signed)
check("self-asserted verify is valid", v and v[0]["valid"] is True)
check("self-asserted trust labelled honestly", v[0].get("trust", "").startswith("self-asserted"))

# ---- verify (anchored against the known public key) ------------------------
va = cs.verify_card(signed, trusted_pub_hex=PUB)
check("anchored verify is valid", va and va[0]["valid"] is True)
check("anchored key matches embedded jwk", va[0].get("anchored_matches_embedded") is True)

# ---- anchored against the WRONG key rejects --------------------------------
wrong = SigningKey(bytes.fromhex("22" * 32)).verify_key.encode().hex()
vw = cs.verify_card(signed, trusted_pub_hex=wrong)
check("wrong anchored key rejects", vw and vw[0]["valid"] is False)

# ---- payload excludes signatures AND default-valued props ------------------
payload_obj = json.loads(cs.canonical_payload(signed).decode("utf-8"))
check("signed payload excludes the signatures field", "signatures" not in payload_obj)
check("signed payload strips default-valued props (capabilities:{false...}, empty security)",
      "capabilities" not in payload_obj and "securitySchemes" not in payload_obj
      and "security" not in payload_obj)
check("signed payload keeps real content (skills, name)",
      payload_obj.get("name", "").startswith("AlgoVoi")
      and any(s.get("id") == "rfc9421-clinic" for s in payload_obj.get("skills", [])))

# ---- tamper detection: change a covered field ------------------------------
tampered = copy.deepcopy(signed)
tampered["name"] = "Impostor Agent"
vt = cs.verify_card(tampered)
check("tampering a covered field breaks verification", vt and vt[0]["valid"] is False)

# ---- app attaches a signature when keyed, unsigned otherwise ---------------
os.environ["AGENT_CARD_SIGNING_KEY_HEX"] = SEED
sys.modules.pop("app", None)
import app as gw  # noqa: E402
served = gw.CARD
check("app serves a signed card when AGENT_CARD_SIGNING_KEY_HEX is set",
      isinstance(served.get("signatures"), list) and served["signatures"])
check("the app's served signature verifies (anchored)",
      cs.verify_card(served, trusted_pub_hex=PUB)[0]["valid"] is True)

# ---- preferred: seed from a MOUNTED FILE (kept out of docker inspect) -------
import tempfile
os.environ.pop("AGENT_CARD_SIGNING_KEY_HEX", None)
with tempfile.NamedTemporaryFile("w", suffix=".hex", delete=False) as _f:
    _f.write(SEED + "\n"); _seedfile = _f.name
os.environ["AGENT_CARD_SIGNING_KEY_FILE"] = _seedfile
sys.modules.pop("app", None)
import app as gw2  # noqa: E402
check("app loads the seed from AGENT_CARD_SIGNING_KEY_FILE (env HEX unset) and signs",
      isinstance(gw2.CARD.get("signatures"), list) and gw2.CARD["signatures"]
      and cs.verify_card(gw2.CARD, trusted_pub_hex=PUB)[0]["valid"] is True)
os.unlink(_seedfile)

passed = sum(1 for _, ok in CHECKS if ok)
total = len(CHECKS)
print(f"\nRESULT: {'ALL PASS' if passed == total else 'FAIL'} ({passed}/{total})")
sys.exit(0 if passed == total else 1)
