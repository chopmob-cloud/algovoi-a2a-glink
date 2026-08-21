#!/usr/bin/env python3
"""clinic_responder.py -- the AlgoVoi side of the gibberlink RFC 9421 clinic.

Agents bring a real signing question; we answer it CORRECTLY from AlgoVoi's own
knowledge (we built the verifier) and always attach the exact canonical link that
resolves it. Deterministic keyword routing -- our side never hallucinates; the
answers are curated and the links are real, live, published resources.

This module is transport-agnostic: the gibberlink harness calls answer(); the same
function can later back an /clinic endpoint or an A2A skill unchanged.
"""
from __future__ import annotations
import os, sys
from pathlib import Path

# --- DESIGN FROZEN: A (2026-08-18, the design notes) -----------------------------
# The clinic grounds on OpenRouter + the inline PUBLIC_KNOWLEDGE string below. It is DELIBERATELY NOT
# wired to any RAG library: concrete questions go to the real /explain engine, RAG only touches
# the conceptual long-tail with no measured correctness gain, and a retrieval corpus would re-open the
# exfil surface the security review closed ("nothing to exfil"). The lever for the conceptual miss is this
# deterministic router + the fixed benchmark (clinic_benchmark.py), NOT a knowledge base.
#
# FAIL-CLOSED dedicated key + input bounds + a public-host allowlist enforce the seal-audit gaps at the
# logic layer (the network transport enforces the rest before any open deploy).
PUBLIC_HOSTS = {"agents.algovoi.co.uk", "docs.algovoi.co.uk", "github.com", "pypi.org", "www.npmjs.com"}
MAX_QUESTION_CHARS = 2000                     # bound external input BEFORE any routing / model work
# NOT a module constant: an absolute path into the operator's secrets directory must not sit on
# the module surface where it can be reflected out (redteam_clinic probe 4 scans every constant).
# Resolved on demand instead, so the module exposes only the function.
_CLINIC_KEY_NAME = "clinic-openrouter.txt"


def _clinic_key_file() -> Path:
    return Path.home() / ".secrets" / _CLINIC_KEY_NAME


def get_clinic_or_key() -> str:
    """Return the DEDICATED clinic OpenRouter key (env CLINIC_OR_KEY or ~/.secrets/clinic-openrouter.txt).
    FAIL CLOSED if unset: never fall back to the shared runtime key, so a clinic abuse spike is capped to
    its own hard-limited key and cannot drain other services."""
    key = os.environ.get("CLINIC_OR_KEY", "").strip()
    key_file = _clinic_key_file()
    if not key and key_file.exists():
        key = key_file.read_text(encoding="utf-8").strip()
    if not key:
        raise RuntimeError(
            "CLINIC_OR_KEY is not set. The clinic uses a DEDICATED, spend-capped OpenRouter key (env "
            "CLINIC_OR_KEY or ~/.secrets/clinic-openrouter.txt), NEVER the shared runtime key. Set it "
            "before serving; failing closed so an abuse spike cannot drain other services.")
    return key


def all_links() -> list:
    """Every link the deterministic side can emit (KB + fallback + explain path) -- for the allowlist test."""
    links = [l for e in KB for l in e["links"]] + list(_FALLBACK["links"])
    links += [{"label": "explain", "url": f"{LIVE}/verify/rfc9421/explain"},
              {"label": "sign", "url": f"{LIVE}/verify/rfc9421/sign"}]
    return links


# Public-arena channels ONLY -- everything the clinic hands out is publicly published.
# Never cite local-only / commercial / Private::Do-Not-Upload assets.
LIVE = "https://agents.algovoi.co.uk"                                        # live free tools
DOCS = "https://docs.algovoi.co.uk"                                          # public docs
VERIFIER_REPO = "https://github.com/chopmob-cloud/algovoi-rfc9421-verifier"  # source (GitHub)
VECTORS_REPO = "https://github.com/chopmob-cloud/algovoi-jcs-conformance-vectors"
PYPI = "https://pypi.org/project/algovoi-rfc9421-verifier/"                  # pip install algovoi-rfc9421-verifier
NPM = "https://www.npmjs.com/package/@algovoi/rfc9421-verifier"              # npm i @algovoi/rfc9421-verifier

# Each entry: a topic, the keywords that route to it, a correct concise answer, and
# the exact canonical link(s). Answers are grounded in RFC 9421 + RFC 9530 and in the
# actual behaviour of algovoi-rfc9421-verifier 0.4.4.
KB = [
    {
        "topic": "signing-base",
        "keywords": ["signing base", "signature base", "canonical", "base string",
                     "what gets signed", "bytes signed", "mismatch", "fails but looks right",
                     "verify fails", "invalid signature", "doesn't verify", "wrong signature",
                     "server rejects", "rejects it", "rejected", "verifies locally", "works locally",
                     "one end", "other end", "my library", "different library"],
        "answer": (
            "Signing-base construction is the #1 interop bug. The base is built line-by-line: one line per "
            "covered component in the exact order from Signature-Input, each as `\"name\": value` (lowercased "
            "header name, field value trimmed of leading/trailing OWS), then a final "
            "`\"@signature-params\": (...)` line echoing the component list plus params. A single wrong byte "
            "(extra space, uppercased header, wrong order, CRLF vs LF) makes an otherwise-correct signature "
            "fail. Don't eyeball it -- diff your base against a reference."
        ),
        "links": [{"label": "Byte-level base diff (paste your request)", "url": f"{LIVE}/verify/rfc9421/explain"},
                  {"label": "Known-good signer to diff against", "url": f"{LIVE}/verify/rfc9421/sign"}],
    },
    {
        "topic": "content-digest",
        "keywords": ["content-digest", "content digest", "rfc 9530", "9530", "body hash",
                     "digest", "sha-256", "sha-512", "body integrity", "payload hash"],
        "answer": (
            "Content-Digest (RFC 9530) is `sha-256=:<base64>:` where the base64 is the raw digest of the exact "
            "body bytes, wrapped as an sfv byte-sequence (colon-delimited). Two rules that trip people up: (1) "
            "hash the body you actually send, after any encoding, not the pretty-printed JSON; (2) the "
            "`content-digest` header MUST be listed as a covered component in Signature-Input, or the body "
            "isn't protected at all -- a valid signature over an uncovered digest proves nothing about the body."
        ),
        "links": [{"label": "Recompute + check your digest", "url": f"{LIVE}/verify/rfc9421/explain"}],
    },
    {
        "topic": "covered-components",
        "keywords": ["covered component", "@method", "@authority", "@path", "@target-uri",
                     "derived component", "which components", "what to cover", "components",
                     "@query", "@scheme", "gateway", "rewrite", "rewrites", "rewriting", "proxy",
                     "load balancer", "load-balancer", "ingress", "mesh", "request-target",
                     "forwarding", "forwards", "path prefix", "strips", "reorders"],
        "answer": (
            "Cover the derived components that pin the request: `@method`, `@authority`, `@path` (and "
            "`@target-uri`/`@query` if the query matters), plus every security-relevant header -- crucially "
            "`content-digest` and any auth header. Derived components start with `@` and have defined values "
            "(e.g. `@authority` is host[:port] lowercased). Anything NOT listed is unprotected and an attacker "
            "can change it freely. The verifier reports exactly which components your signature covered."
        ),
        "links": [{"label": "See your covered components", "url": f"{LIVE}/verify/rfc9421/explain"}],
    },
    {
        "topic": "signature-params",
        "keywords": ["@signature-params", "signature-params", "signature-input", "created", "expires",
                     "keyid", "alg", "tag", "nonce", "params line", "parameters"],
        "answer": (
            "The final base line is `\"@signature-params\": (\"comp1\" \"comp2\" ...);created=...;keyid=...;"
            "alg=...` -- it MUST reproduce the inner-list and params from your Signature-Input header byte for "
            "byte, including quoting and param order. Set `alg` explicitly (don't rely on the verifier guessing), "
            "`keyid` so the verifier can resolve your key, and `created` (+ optionally `expires`) for freshness. "
            "`tag` scopes the signature to an application so a signature can't be replayed cross-context."
        ),
        "links": [{"label": "Explain your params + base", "url": f"{LIVE}/verify/rfc9421/explain"}],
    },
    {
        "topic": "freshness-replay",
        "keywords": ["freshness", "clock skew", "replay", "nonce", "expired", "stale",
                     "timestamp", "created too old", "time window", "anti-replay",
                     "prevent replay", "replay within", "created and expires", "reject expired",
                     "seen-nonce", "within the window"],
        "answer": (
            "`created`/`expires` are signed params, so they can't be forged, but the VERIFIER enforces the "
            "policy: reject if `created` is in the future beyond your skew tolerance, reject past `expires`, and "
            "keep a short-lived seen-nonce cache to stop replay inside the validity window. RFC 9421 gives you "
            "the fields; the deployment policy (skew, max-age, nonce store) is yours to set. Our verifier takes "
            "`now`, freshness bounds, and a nonce-seen hook as verify args."
        ),
        "links": [{"label": "Verifier freshness/replay args", "url": VERIFIER_REPO}],
    },
    {
        "topic": "keyid-alg-keycheck",
        "keywords": ["keyid", "algorithm", "ed25519", "rsa", "key check", "small order",
                     "malicious key", "weak key", "public key", "which alg",
                     "downgrade", "algorithm downgrade", "downgrade attack", "downgraded"],
        "answer": (
            "Pin the algorithm allow-list (for agents, ed25519) and reject anything else -- a downgrade to a "
            "weaker/None alg is a classic bypass. Beyond that, validate the PUBLIC KEY itself: our verifier "
            "rejects small-order / non-canonical Ed25519 points, which naive libraries accept and which let an "
            "attacker forge across the whole small-order subgroup. `keyid` tells the verifier WHICH key to "
            "expect; you must anchor that keyid to a trusted key out of band (see key discovery)."
        ),
        "links": [{"label": "Verifier keycheck (small-order rejection)", "url": VERIFIER_REPO}],
    },
    {
        "topic": "key-discovery",
        "keywords": ["key discovery", "resolve key", "keyid to key", "jwks", "well-known",
                     "trust the key", "which key", "rotation", "revocation", "whose signature",
                     "identity", "did:key", "did", "trust", "belongs to", "public key belongs",
                     "which public key", "agent key", "whose key", "map keyid", "find the key",
                     "fetch the key", "distribute keys", "publish keys", "know which agent"],
        "answer": (
            "Honest answer: RFC 9421 deliberately does NOT solve this -- it verifies a signature against a key "
            "you already trust, but 'which key is really this agent's, and is it still valid?' is out of scope "
            "and the genuinely-unsolved hard part. Practical path today: publish agent keys at a signed "
            "`.well-known` JWKS-style directory (or bind them to a `did:key`/`did:web`), anchor keyid->key out "
            "of band, and handle rotation by keyid + revocation via the directory. This is where AlgoVoi's "
            "agent-passport / signed-directory work is aimed; it's direction, not a finished standard -- happy "
            "to compare notes."
        ),
        "links": [{"label": "Verifier + keyid handling", "url": VERIFIER_REPO}],
    },
    {
        "topic": "limits-threat-model",
        "keywords": ["prompt injection", "what does it protect", "doesn't protect", "content trust",
                     "trust the content", "safe now", "guarantee", "threat model", "limitation",
                     "malicious content", "signed but malicious", "safe to trust", "automatically safe",
                     "signed content", "injection", "stop a prompt", "valid signature stop",
                     "content trustworthy", "safe to act on", "act on", "body safe", "safe to act"],
        "answer": (
            "Critical and often conflated: a valid signature proves the message wasn't altered in transit and "
            "came from the keyholder. It does NOT make the CONTENT trustworthy. A perfectly-signed request can "
            "still carry a prompt injection, a hostile instruction, or a lie -- signing protects integrity and "
            "origin, not intent or truthfulness. Treat signature-valid input as authenticated-but-still-"
            "untrusted, and keep your content-side defenses. Anyone selling signatures as a prompt-injection "
            "fix is over-claiming."
        ),
        "links": [{"label": "Verify integrity/origin (not content trust)", "url": f"{LIVE}/verify/rfc9421"}],
    },
    {
        "topic": "test-vectors-ci",
        "keywords": ["test vector", "conformance", "ci", "pytest", "vitest", "interop",
                     "test suite", "vectors", "malicious vectors", "negative test", "cross-language"],
        "answer": (
            "Don't hand-roll conformance tests -- reuse our open, published corpus. It ships signed RFC 9421 "
            "request/response/proxy-chain and receipt-evidence fixtures with runners in many languages "
            "(python/node/go/java/rust/ruby/php/dotnet), plus tamper/negative cases, so you can drop them into "
            "pytest/vitest/CI and prove your signer AND verifier against a reference. The negative cases are the "
            "important half -- they check you REJECT what you should, not just accept what's valid."
        ),
        "links": [{"label": "Conformance vectors (valid + malicious)", "url": VECTORS_REPO}],
    },
    {
        "topic": "getting-started",
        "keywords": ["get started", "getting started", "how do i start", "install", "pip",
                     "npm", "example", "quickstart", "first time", "new to", "integrate",
                     "signed calls", "verify signed", "verifying signed", "verify my agent"],
        "answer": (
            "Start with the shipped verifier -- Python: `pip install algovoi-rfc9421-verifier`; Node: "
            "`npm i @algovoi/rfc9421-verifier`. Call `verify_request(...)` with the request + the key you EXPECT "
            "the signer to hold (anchoring), and read the structured result. To learn the exact bytes, POST a "
            "request to the live /explain endpoint and read the signing base it shows you, then generate a "
            "known-good request from /sign and compare. That loop -- explain, then match -- gets most "
            "integrations green fast. Full docs at docs.algovoi.co.uk."
        ),
        "links": [{"label": "PyPI (pip install algovoi-rfc9421-verifier)", "url": PYPI},
                  {"label": "npm (@algovoi/rfc9421-verifier)", "url": NPM},
                  {"label": "Docs", "url": DOCS},
                  {"label": "Live explain + signer", "url": f"{LIVE}/verify/rfc9421/explain"}],
    },
]

_FALLBACK = {
    "topic": "general",
    "answer": (
        "Happy to help with RFC 9421 HTTP Message Signatures. The fastest path for almost any signing problem "
        "is to POST your raw signed request to our free /explain endpoint: it returns the exact canonical "
        "signing base, the covered components, a Content-Digest recomputation, and a byte-level diff against "
        "the reference base -- which is where nearly every 'valid signature that won't verify' bug lives. If "
        "you want a correct reference to compare against, /sign hands you a known-good signed request."
    ),
    "links": [{"label": "Explain any signed request", "url": f"{LIVE}/verify/rfc9421/explain"},
              {"label": "Known-good signer", "url": f"{LIVE}/verify/rfc9421/sign"},
              {"label": "Open verifier + vectors", "url": VERIFIER_REPO},
              {"label": "Docs", "url": DOCS}],
}


def answer(question: str) -> dict:
    """Route a free-text question to the best-matching curated answer + canonical links.

    Returns {topic, answer, links:[{label,url}], matched:int}. Deterministic: our side is
    a curated knowledge base, so the answers are correct and the links are real. Falls back
    to the universal /explain guidance when nothing scores."""
    q = (question or "")[:MAX_QUESTION_CHARS].lower()   # bound external input before any work
    best, best_score = None, 0
    for entry in KB:
        score = sum(1 for kw in entry["keywords"] if kw in q)
        if score > best_score:
            best, best_score = entry, score
    if best is None or best_score == 0:
        out = dict(_FALLBACK)
        out["matched"] = 0
        return out
    return {"topic": best["topic"], "answer": best["answer"],
            "links": best["links"], "matched": best_score}


# ---------------------------------------------------------------------------
# UPGRADE 1: the real /explain engine behind the desk (public tool, offline).
# For a CONCRETE signed request we run the actual shipped verifier and hand back
# the caller's own signing base + diagnosis -- impossible to be "too generic".
# ---------------------------------------------------------------------------
# Env override first, otherwise the a2a-gateway/ that ships ALONGSIDE this tree -- so a
# checkout resolves the /explain engine deterministically.
_SIBLING_GATEWAY = Path(__file__).resolve().parent.parent / "a2a-gateway"
_GATEWAY_DIR = Path(os.environ.get("CLINIC_GATEWAY_DIR", "")) if os.environ.get("CLINIC_GATEWAY_DIR") else _SIBLING_GATEWAY


def _load_explain():
    """Lazy-import the deployed, public /explain engine (verifier_tool)."""
    if str(_GATEWAY_DIR) not in sys.path:
        sys.path.insert(0, str(_GATEWAY_DIR))
    from verifier_tool import explain_rfc9421, sign_rfc9421_demo, VerifyToolError  # type: ignore
    return explain_rfc9421, sign_rfc9421_demo, VerifyToolError


def explain_request(request_payload: dict) -> dict:
    """Run the caller's actual signed request through the real public /explain engine.

    Returns a clinic-shaped result: verdict + the exact canonical signing base, covered
    components, Content-Digest recomputation, and concrete diagnosis -- plus the public link
    so they can re-run it themselves. This is the same engine live at agents.algovoi.co.uk."""
    explain_rfc9421, _sign, _err = _load_explain()
    r = explain_rfc9421(request_payload)
    return {
        "topic": "explain-live",
        "answer": None,                       # this path returns a real diagnosis, not prose
        "explain": {
            "valid": r.get("valid"),
            "errors": r.get("errors"),
            "signature_base": r.get("signature_base"),
            "covered_components": r.get("covered_components"),
            "content_digest": r.get("content_digest"),
            "base_diff": r.get("base_diff"),
            "diagnosis": r.get("diagnosis"),
            "verifier_version": r.get("verifier_version"),
        },
        "links": [{"label": "Re-run your request live", "url": f"{LIVE}/verify/rfc9421/explain"},
                  {"label": "Known-good signer to diff against", "url": f"{LIVE}/verify/rfc9421/sign"}],
        "matched": None,
    }


# ---------------------------------------------------------------------------
# UPGRADE 2: grounded conceptual answers -- sourced ONLY from public data.
# The clinic composes a SPECIFIC answer to the caller's scenario, but strictly from
# the public standards + AlgoVoi's public tools below. Links stay deterministic/public;
# the model may not invent URLs, features, or anything not publicly published.
# ---------------------------------------------------------------------------
PUBLIC_KNOWLEDGE = """\
AUTHORITATIVE PUBLIC SOURCES ONLY: RFC 9421 (HTTP Message Signatures), RFC 9530 (Content-Digest),
and AlgoVoi's PUBLIC tools/repos. Do not use or imply anything not publicly published.

Derived components (RFC 9421 sec 2.2):
- @method: the HTTP method, uppercase.
- @authority (2.2.3): host lowercased, with port ONLY if non-default. Covers Host, not the scheme.
- @path (2.2.6): the absolute path ONLY -- it does NOT include the query string.
- @query (2.2.7): the query string INCLUDING the leading "?" (value is "?" if empty). Signed AS-RECEIVED;
  RFC 9421 does NOT sort or canonicalize query params -- if you need order-independence, canonicalize
  the query yourself BEFORE signing so both ends agree.
- @query-param;name="x" (2.2.8): one query parameter, percent-decoded value.
- @target-uri (2.2.2): the full absolute URI (scheme + authority + path + query) in one component.
- Anything NOT listed in Signature-Input is UNPROTECTED and can be freely changed by a proxy. Headers
  like Authorization are protected ONLY if you explicitly list "authorization" as a covered component.

Content-Digest (RFC 9530): header form sha-256=:<base64>: over the RAW bytes you actually send (after
any content-encoding), not pretty-printed JSON. It protects the body ONLY if "content-digest" is itself
a covered component in Signature-Input; a valid signature over an uncovered digest proves nothing.

Streaming / large / unbuffered bodies: a Content-Digest needs the final body bytes, but streaming bodies
CAN still be signed -- never say they cannot. Options: (a) compute the digest incrementally as you stream
and emit Content-Digest as an HTTP TRAILER (RFC 9530 allows a trailer digest), covering it in the
signature that also lands in the trailer section; (b) chunk the body and carry a per-representation digest;
(c) if you truly cannot digest the body, sign the request METADATA (@method/@authority/@path/@query + the
security headers) WITHOUT covering content-digest, and accept that the body is unprotected until a trailer
digest arrives -- state that tradeoff explicitly. The constraint is only that the digest is final once you
have the bytes (buffered, chunked, or via trailer); signing itself is not blocked by streaming.

Signing base: built line-by-line, one per covered component in Signature-Input order, then a final
"@signature-params" line echoing the component list + params byte-for-byte. One wrong byte (order,
casing, whitespace, CRLF vs LF) breaks verification. AlgoVoi's public /explain returns the exact base
and a byte-level diff; /sign returns a known-good reference signed with an EPHEMERAL key.

Freshness/replay: created/expires are signed params but the VERIFIER enforces policy -- reject future
created beyond skew, reject past expires, keep a short seen-nonce cache. alg must be pinned (ed25519 for
agents); reject downgrades. Validate the public KEY too (reject small-order/non-canonical Ed25519 points).

Gateways/proxies that rewrite a SIGNED component (e.g. path prefix): verify at the edge BEFORE the
rewrite, OR preserve the original target in a signed header the gateway won't touch, OR have the trusted
gateway RE-SIGN. Never just drop @path -- that leaves routing unprotected.

Threat-model honesty: a valid signature proves integrity + origin (the bytes weren't altered, the
keyholder signed them). It does NOT make the CONTENT trustworthy -- a perfectly-signed request can still
carry a prompt injection or a lie. Treat signature-valid input as authenticated-but-still-untrusted.

Public AlgoVoi resources you may cite (and ONLY these): the live tools at agents.algovoi.co.uk
(/verify/rfc9421, /verify/rfc9421/explain, /verify/rfc9421/sign), the open verifier on PyPI
(algovoi-rfc9421-verifier) and npm (@algovoi/rfc9421-verifier), GitHub chopmob-cloud
(algovoi-rfc9421-verifier, algovoi-jcs-conformance-vectors), and docs at docs.algovoi.co.uk.
"""

_GROUNDING_BASE = (
    "You are the AlgoVoi RFC 9421 signing clinic. Answer the engineer's SPECIFIC question below using "
    "ONLY the authoritative public knowledge provided -- public standards (RFC 9421/9530) and AlgoVoi's "
    "public tools. Be concrete and address THEIR exact scenario, not the general topic. <=120 words. Be "
    "honest about what signatures do NOT protect. Do NOT invent URLs, features, or anything not in the "
    "knowledge; the official link is appended separately. Never state something is impossible unless the "
    "knowledge says so.\n"
)
# The escape hatch is gated by our DETERMINISTIC router, not the model's own judgement: it is offered
# ONLY when the router found no covered topic. Otherwise the model MUST answer from the knowledge.
_COVERED_CLAUSE = (
    "COVERAGE: this question IS covered by the knowledge below (topic: {topic}). You MUST give a specific, "
    "correct answer from it -- do NOT defer, punt, or tell them to go elsewhere. Cite the exact mechanism "
    "(components, digest/trailer handling, gateway verify-before-rewrite / re-sign / signed original target, "
    "etc.) that resolves THEIR case.\n"
)
_UNCOVERED_CLAUSE = (
    "COVERAGE: the knowledge below may not address this exact scenario. If and ONLY if it genuinely does "
    "not, reply exactly: 'That specific case isn't in our public guidance yet -- POST your signed request "
    "to the /explain endpoint and it will show you the exact signing base.' If it IS addressed, answer it.\n"
)
_KNOWLEDGE_BLOCK = "\n=== AUTHORITATIVE PUBLIC KNOWLEDGE ===\n" + PUBLIC_KNOWLEDGE + "\n=== END KNOWLEDGE ===\n"


def answer_grounded(question: str, ask_fn) -> dict:
    """Compose a SPECIFIC answer to the question, grounded strictly in PUBLIC_KNOWLEDGE, with
    deterministic public links. ask_fn(prompt)->str is the grounding model. On any failure we
    fall back to the deterministic curated answer -- never leaving the caller with nothing.

    The 'defer to /explain' escape hatch is gated by the DETERMINISTIC router (matched>0 == covered),
    not the model's self-assessment -- so it can't punt on a topic the KB actually covers."""
    routed = answer(question)                 # deterministic topic + PUBLIC links
    # >=2 keyword signals == genuinely covered (force a specific answer); a single weak hit is treated
    # as possibly-uncovered so the clinic may honestly defer rather than guess. Integrity over coverage.
    covered = (routed.get("matched") or 0) >= 2
    clause = _COVERED_CLAUSE.format(topic=routed["topic"]) if covered else _UNCOVERED_CLAUSE
    instr = _GROUNDING_BASE + clause + _KNOWLEDGE_BLOCK
    try:
        prompt = f"{instr}\nENGINEER'S QUESTION:\n{question}\n\nYour grounded answer:"
        text = (ask_fn(prompt) or "").strip()
        if not text:
            raise ValueError("empty grounded answer")
        return {"topic": routed["topic"], "answer": text, "links": routed["links"],
                "matched": routed["matched"], "grounded": True}
    except Exception as e:  # noqa: BLE001
        out = dict(routed); out["grounded"] = False; out["ground_error"] = str(e)[:80]
        return out


if __name__ == "__main__":  # quick self-test
    for probe in ["my signature verifies locally but the server rejects it",
                  "how do I know which public key belongs to an agent?",
                  "does a valid signature stop prompt injection?",
                  "how do I set up content-digest?",
                  "where are your test vectors?",
                  "totally unrelated question about the weather"]:
        r = answer(probe)
        print(f"[{r['topic']:22} m={r['matched']}] {probe}")
        for l in r["links"]:
            print(f"        -> {l['label']}: {l['url']}")
