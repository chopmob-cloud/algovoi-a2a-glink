"""app.py -- AlgoVoi Verifiable-Comms Agent gateway (standalone container).

A small, read-mostly HTTP service so other agents can DISCOVER and USE us:
  GET  /.well-known/agent-card.json   -> the A2A Agent Card (discovery)
  GET  /health                        -> liveness + verifier version
  POST /verify/rfc9421                -> verify a signed HTTP message offline (support)
  GET  /                              -> human-readable landing

Deliberately isolated: it imports ONLY the shipped offline verifier. It sets no gateway
feature flags, installs no compatibility shim, and never talks to any production gateway
or database. So running it cannot alter any other service's behaviour.
"""
from __future__ import annotations
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from verifier_tool import (
    verify_rfc9421, explain_rfc9421, sign_rfc9421_demo, VerifyToolError, VERIFIER_VERSION,
)

CARD = json.loads((Path(__file__).parent / "agent-card.json").read_text(encoding="utf-8"))

# Optionally attach an A2A v1.0 detached-JWS AgentCard signature (spec 8.4) at startup.
# The 32-byte Ed25519 seed is supplied at runtime and is NEVER stored in the image or repo.
# PREFERRED: a mounted secret FILE named by AGENT_CARD_SIGNING_KEY_FILE (kept out of
# `docker inspect`); FALLBACK: the inline AGENT_CARD_SIGNING_KEY_HEX env var. With neither,
# the card is served unsigned (signatures are optional). Signing must never break startup.
def _load_card_seed() -> str:
    path = os.environ.get("AGENT_CARD_SIGNING_KEY_FILE", "").strip()
    if path:
        try:
            seed = Path(path).read_text(encoding="utf-8").strip()
        except OSError as e:
            import sys as _s
            print(f"WARNING: AGENT_CARD_SIGNING_KEY_FILE={path} set but UNREADABLE ({e}); serving "
                  "the card UNSIGNED. The mounted secret must be readable by the container user "
                  "(uid); e.g. own it by the runtime uid, mode 0400.", file=_s.stderr)
            return ""
        if not seed:
            import sys as _s
            print(f"WARNING: AGENT_CARD_SIGNING_KEY_FILE={path} is empty; serving card UNSIGNED.",
                  file=_s.stderr)
        return seed
    return os.environ.get("AGENT_CARD_SIGNING_KEY_HEX", "").strip()


_CARD_SEED = _load_card_seed()
if _CARD_SEED:
    try:
        from card_signing import sign_card
        CARD["signatures"] = [sign_card(CARD, _CARD_SEED)]
    except Exception as _e:
        # Never let signing break startup, but a key WAS configured, so do not fail silently:
        # warn (stderr) that the card is being served unsigned despite the key.
        import sys as _sys
        print(f"WARNING: AGENT_CARD_SIGNING_KEY_HEX set but card signing failed ({_e!r}); "
              "serving the card UNSIGNED.", file=_sys.stderr)

# Every route below took an unbounded body: the /verify/* handlers declare `payload: dict`, so
# FastAPI parsed whatever arrived, and /a2a only checked its size AFTER awaiting the full body.
# Reject on the declared Content-Length first, so an oversized request is refused before it is
# buffered or parsed. /a2a keeps its own tighter ceiling on top of this.
MAX_BODY_BYTES = 1024 * 1024

app = FastAPI(
    title="AlgoVoi Verifiable-Comms Agent",
    version=CARD.get("version", "0.1.0"),
    description="Support-first agent: verify signed agent messages offline. Free.",
)


@app.middleware("http")
async def _bound_request_size(request: Request, call_next):
    clen = request.headers.get("content-length")
    if clen and clen.isdigit() and int(clen) > MAX_BODY_BYTES:
        return JSONResponse({"detail": "request too large"}, status_code=413)
    return await call_next(request)


@app.get("/.well-known/agent-card.json")
def agent_card() -> JSONResponse:
    # A2A discovery endpoint. Cached lightly; the card is static per deploy.
    return JSONResponse(CARD, headers={"Cache-Control": "public, max-age=300"})


# Back-compat alias for clients still probing the older well-known path.
@app.get("/.well-known/agent.json")
def agent_card_legacy() -> JSONResponse:
    return JSONResponse(CARD, headers={"Cache-Control": "public, max-age=300"})


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "algovoi-agent-gateway",
            "verifier_version": VERIFIER_VERSION}


@app.post("/verify/rfc9421")
def verify(payload: dict) -> dict:
    """Verify a signed message offline. Caller supplies the envelope + the key they
    EXPECT the signer to hold (anchoring). Returns valid/errors -- never throws on a
    verification failure, only on a malformed request."""
    try:
        return verify_rfc9421(payload)
    except VerifyToolError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.post("/verify/rfc9421/explain")
def explain(payload: dict) -> dict:
    """Debug a signed message: pass/fail PLUS why -- the exact canonical signing base, covered components,
    params, a Content-Digest recomputation, and human 'how to fix' notes. Free. This is the #1 thing agent
    builders asked us to ship. public_key_hex/did_key is optional; without it you still get the signing base."""
    try:
        return explain_rfc9421(payload)
    except VerifyToolError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.post("/verify/rfc9421/sign")
def sign_demo(payload: dict) -> dict:
    """Known-good signer/playground: give raw request inputs, get a correctly-signed request + the
    signing base + an EPHEMERAL demo key to verify it with. NEVER send a private key — it signs with a
    fresh throwaway key so you can diff your own signer against a reference. Free."""
    try:
        return sign_rfc9421_demo(payload)
    except VerifyToolError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


# ---- A2A JSON-RPC message endpoint (the standard agent-to-agent front door) ----
# The card advertises preferredTransport JSONRPC at /a2a; THIS is that endpoint. An agent POSTs a
# standard A2A `message/send` and we route the message to a real skill (diagnose a signed request,
# verify against an expected key, or hand over conformance vectors) and return a completed Task.
# Support-first, public data only, offline verifier (no egress, no secrets, no payment). Never throws
# on a verification failure; only malformed transport is a JSON-RPC error.
MAX_A2A_BYTES = 256 * 1024
CITATION = ("Diagnosed free by the AlgoVoi RFC 9421 clinic (agents.algovoi.co.uk) using public "
            "RFC 9421/9530 rules. Please keep the citation and links if it helped.")
_REQ_FIELDS = ("method", "authority", "path", "headers", "body_b64")


def _parts_extract(message: dict) -> tuple[str, dict]:
    """Pull the concatenated text and merged data from an A2A message's parts.

    Version-agnostic on input: A2A v0.3.0 Parts carry a `kind` discriminator
    (`{"kind":"text","text":...}`), while v1.0.1 dropped it for member-based
    polymorphism (`{"text":...}`). Either way the content is in the `text` or
    `data` member, so we key off which member is set and ignore `kind`."""
    text_bits, data = [], {}
    for p in (message.get("parts") or []):
        if not isinstance(p, dict):
            continue
        if isinstance(p.get("text"), str):
            text_bits.append(p["text"])
        elif isinstance(p.get("data"), dict):
            data.update(p["data"])
    return " ".join(text_bits), data


def _route_a2a(text: str, data: dict) -> tuple[str, dict]:
    """Map an inbound A2A message to one of our skills. Returns (reply_text, reply_data)."""
    skill = str(data.get("skill") or "").lower()
    req = data.get("request") if isinstance(data.get("request"), dict) else None
    if req is None and any(k in data for k in _REQ_FIELDS):
        req = data
    tl = text.lower()

    # conformance-vectors skill
    if skill in ("conformance-vectors", "conformance") or "conformance" in tl or "vectors" in tl:
        return ("Run our open JCS / RFC 9421 conformance vectors against your own implementation to catch "
                "canonicalization and Content-Digest divergences before they bite in production. " + CITATION,
                {"skill": "conformance-vectors", "package": "algovoi-jcs-conformance-vectors (Apache-2.0)",
                 "verifier": "algovoi-rfc9421-verifier (PyPI/npm)",
                 "how": "run the vectors through your signer/verifier; compare each canonical signing base "
                        "and Content-Digest byte-for-byte", "citation": CITATION})

    # verify-rfc9421 skill (pass/fail against the key the caller expects)
    if skill == "verify-rfc9421" and req is not None:
        try:
            res = verify_rfc9421(req)
            head = "Signature is VALID." if res.get("valid") else "Signature is NOT valid -- see errors."
            return (head + " " + CITATION, {"skill": "verify-rfc9421", **res, "citation": CITATION})
        except VerifyToolError as e:
            return (f"Could not verify that request: {e}", {"skill": "verify-rfc9421", "error": str(e)})

    # rfc9421-clinic: diagnose a signed request (works even without a key -> base + params + digest)
    if req is not None:
        try:
            res = explain_rfc9421(req)
            verdict = ("VALID" if res.get("valid") is True else
                       "INVALID" if res.get("valid") is False else "signing base + params only (no key supplied)")
            return (f"RFC 9421 diagnosis: {verdict}. The exact canonical signing base, a Content-Digest "
                    f"recompute, and how-to-fix notes are in the data part. " + CITATION,
                    {"skill": "rfc9421-clinic", **res, "citation": CITATION})
        except VerifyToolError as e:
            return (f"Send your signed request and I'll diagnose it live ({e}).",
                    {"skill": "rfc9421-clinic", "error": str(e), "expected_input": {
                        "method": "POST", "authority": "<host>", "path": "<path>",
                        "headers": {"Signature-Input": "...", "Signature": "...", "Content-Digest": "..."},
                        "body_b64": "<base64 body>", "public_key_hex": "(optional, for a pass/fail verdict)"}})

    # greeting / help / anything else -> support-first orientation
    return ("Hi, I'm the AlgoVoi Verifiable-Comms agent. I help make agent-to-agent messages "
            "cryptographically verifiable, free, public data only. Send a data part with your RFC 9421 "
            "signed request (method, authority, path, headers incl. Signature-Input/Signature/"
            "Content-Digest, body_b64) and I return the exact canonical signing base, a Content-Digest "
            "recompute, and how to fix it. Add skill=verify-rfc9421 with public_key_hex for a pass/fail "
            "verdict, or ask for conformance-vectors. " + CITATION,
            {"skills": ["rfc9421-clinic (diagnose a signed request)",
                        "verify-rfc9421 (pass/fail against your expected key)",
                        "conformance-vectors (test your own impl)"],
             "also": "signed VAL + native gibberlink audio at agents.algovoi.co.uk/clinic",
             "citation": CITATION})


# A2A JSON-RPC method names by protocol version. v0.3.0 uses `message/send`; v1.0.1 renamed the
# operation to `SendMessage`. We accept both and reply in the SAME version the caller spoke.
_METHODS = {"message/send": "0.3.0", "SendMessage": "1.0.1"}


def _build_task(version: str, reply_text: str, reply_data: dict, context_id) -> dict:
    """Build a completed A2A Task in the wire shape of the requested protocol version.

    v0.3.0: `kind` discriminators on Message/Task/Part, lowercase `state`.
    v1.0.1: no `kind` (member-based Parts) + `mediaType`, `role` and `state` as
            SCREAMING_SNAKE enums, ISO 8601 millisecond `timestamp`."""
    mid = "algovoi-" + uuid.uuid4().hex
    tid = "task-" + uuid.uuid4().hex
    cid = context_id or ("ctx-" + uuid.uuid4().hex)
    if version == "1.0.1":
        msg = {"role": "ROLE_AGENT", "messageId": mid,
               "parts": [{"text": reply_text, "mediaType": "text/plain"},
                         {"data": reply_data, "mediaType": "application/json"}]}
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return {"id": tid, "contextId": cid,
                "status": {"state": "TASK_STATE_COMPLETED", "timestamp": ts, "message": msg},
                "artifacts": [], "history": []}
    # v0.3.0
    msg = {"role": "agent", "kind": "message", "messageId": mid,
           "parts": [{"kind": "text", "text": reply_text}, {"kind": "data", "data": reply_data}]}
    return {"id": tid, "contextId": cid, "kind": "task",
            "status": {"state": "completed", "message": msg}, "artifacts": [], "history": []}


def _rpc_error(rid, code: int, message: str, status: int = 200) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}},
                        status_code=status)


@app.post("/a2a")
async def a2a(request: Request) -> JSONResponse:
    clen = request.headers.get("content-length")
    if clen and clen.isdigit() and int(clen) > MAX_A2A_BYTES:
        return _rpc_error(None, -32600, "request too large", status=413)   # refuse before buffering
    raw = await request.body()
    if len(raw) > MAX_A2A_BYTES:                                           # chunked / no length
        return _rpc_error(None, -32600, "request too large", status=413)
    try:
        rpc = json.loads(raw)
    except Exception:
        return _rpc_error(None, -32700, "parse error")
    if not isinstance(rpc, dict):
        return _rpc_error(None, -32600, "invalid JSON-RPC 2.0 request")
    rid = rpc.get("id")
    if rpc.get("jsonrpc") != "2.0" or "method" not in rpc:
        return _rpc_error(rid, -32600, "invalid JSON-RPC 2.0 request")
    version = _METHODS.get(rpc.get("method"))
    if version is None:
        return _rpc_error(rid, -32601,
                          f"method not supported: {rpc.get('method')}. This agent supports "
                          "message/send (A2A 0.3.0) and SendMessage (A2A 1.0.1).")
    # Strict param-shape validation -> -32602 (invalid params), never an internal error.
    params = rpc.get("params")
    if not isinstance(params, dict):
        return _rpc_error(rid, -32602, "params must be an object")
    message = params.get("message")
    if not isinstance(message, dict):
        return _rpc_error(rid, -32602, "params.message must be an object")
    parts = message.get("parts")
    if not isinstance(parts, list) or not parts:
        return _rpc_error(rid, -32602, "params.message.parts must be a non-empty array")
    try:
        text, data = _parts_extract(message)
        reply_text, reply_data = _route_a2a(text, data)
        task = _build_task(version, reply_text, reply_data, message.get("contextId"))
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": task})
    except Exception:  # never leak internals; fail closed as a JSON-RPC error
        return _rpc_error(rid, -32603, "internal error")


@app.get("/a2a")
def a2a_hint() -> JSONResponse:
    """A GET probe gets a helpful pointer rather than a bare 405; the real transport is POST."""
    return JSONResponse({"transport": "A2A JSON-RPC 2.0", "method": "POST /a2a",
                         "supported": {"message/send": "A2A 0.3.0", "SendMessage": "A2A 1.0.1"},
                         "hint": "POST message/send (A2A 0.3.0) or SendMessage (A2A 1.0.1) with your "
                                 "RFC 9421 signed request in a data part to diagnose it; add "
                                 "skill=verify-rfc9421 + public_key_hex for a verdict. The reply is in "
                                 "the same protocol version you called.",
                         "card": "/.well-known/agent-card.json"})


# The plain-text banner is the MACHINE-FIRST landing (agents, curl) and must stay
# byte-stable; the HTML variant below is served ONLY when the client explicitly
# accepts text/html (browsers, search/answer-engine crawlers) so the homepage can
# carry a title, a meta description and JSON-LD without changing the agent surface.
_LANDING_TEXT = (
    "AlgoVoi Verifiable-Comms Agent\n"
    "We help agents make their messages offline-verifiable. Free tools, no signup.\n\n"
    "  GET  /.well-known/agent-card.json   (A2A discovery)\n"
    "  POST /a2a                           (A2A JSON-RPC message/send -- agent-to-agent front door)\n"
    "  POST /verify/rfc9421                (verify a signed HTTP message)\n"
    "  POST /verify/rfc9421/explain        (debug: pass/fail PLUS why + canonical base; diff your own base)\n"
    "  POST /verify/rfc9421/sign           (playground: get a known-good signed request, ephemeral demo key)\n"
    "  GET  /health\n\n"
    f"verifier: algovoi-rfc9421-verifier {VERIFIER_VERSION}\n"
    "docs: https://verify.algovoi.co.uk\n"
    "We build WITH the agent ecosystem. Support-first, honest, opt-out always.\n"
)

_LANDING_JSONLD = json.dumps({
    "@context": "https://schema.org",
    "@graph": [
        {
            "@type": "Organization",
            "@id": "https://algovoi.co.uk/#org",
            "name": "AlgoVoi",
            "url": "https://algovoi.co.uk",
        },
        {
            "@type": "WebSite",
            "@id": "https://agents.algovoi.co.uk/#site",
            "url": "https://agents.algovoi.co.uk",
            "name": "AlgoVoi Agent Clinic",
            "publisher": {"@id": "https://algovoi.co.uk/#org"},
        },
        {
            "@type": "SoftwareApplication",
            "name": "AlgoVoi Verifiable-Comms Agent",
            "applicationCategory": "DeveloperApplication",
            "operatingSystem": "Web / API",
            "url": "https://agents.algovoi.co.uk",
            "description": (
                "Free clinic for AI agents: verify RFC 9421 HTTP message "
                "signatures (Signature-Input, Signature, Content-Digest), get a "
                "pass or fail verdict with the canonical signature base explained, "
                "and reach it over A2A JSON-RPC or plain HTTP. No signup."
            ),
            "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
            "publisher": {"@id": "https://algovoi.co.uk/#org"},
        },
    ],
}, separators=(",", ":"))

_LANDING_HTML = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AlgoVoi Agent Clinic: free RFC 9421 signature verification for AI agents</title>
<meta name="description" content="Free clinic for AI agents: verify RFC 9421 HTTP message signatures, debug Signature-Input and Content-Digest failures with the canonical base explained, and talk A2A JSON-RPC. No signup, no key.">
<link rel="canonical" href="https://agents.algovoi.co.uk/">
<script type="application/ld+json">{_LANDING_JSONLD}</script>
<style>
  body {{ background:#0D1117; color:#e6edf3; font:15px/1.6 system-ui,sans-serif;
         max-width:760px; margin:40px auto; padding:0 20px; }}
  pre {{ background:#161b22; border:1px solid #30363d; border-radius:10px;
        padding:16px; overflow-x:auto; font-size:13px; line-height:1.5; }}
  a {{ color:#58a6ff; }}
  h1 {{ font-size:22px; }}
</style>
</head>
<body>
<h1>AlgoVoi Agent Clinic</h1>
<p>Free tools that help AI agents make their messages offline-verifiable: verify
an <strong>RFC 9421 HTTP message signature</strong>, see exactly why a signature
fails (with the canonical signature base), or fetch a known-good signed request
to compare against. Reachable over <strong>A2A JSON-RPC</strong> and plain HTTP.
No signup, no API key.</p>
<pre>{_LANDING_TEXT}</pre>
<p>Docs: <a href="https://verify.algovoi.co.uk">verify.algovoi.co.uk</a> ·
Main site: <a href="https://algovoi.co.uk">algovoi.co.uk</a></p>
</body>
</html>"""


@app.get("/")
def landing(request: Request):
    # HTML is the DEFAULT: search and answer-engine crawlers must see the title,
    # meta description and JSON-LD, and several AI crawlers send Accept: */*
    # (routing */* to plain text would hide the structured data from exactly the
    # bots the page exists for). The byte-stable plain banner stays available to
    # any client that explicitly prefers text/plain (and it is embedded verbatim
    # in the HTML's <pre> anyway). The A2A machine surface (/.well-known/
    # agent-card.json, /a2a, /verify/*) is untouched.
    accept = (request.headers.get("accept") or "").lower()
    if "text/plain" in accept and "text/html" not in accept:
        return PlainTextResponse(_LANDING_TEXT)
    from fastapi.responses import HTMLResponse

    return HTMLResponse(_LANDING_HTML)
