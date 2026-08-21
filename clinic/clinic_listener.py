#!/usr/bin/env python3
"""clinic_listener.py -- the real network listener for the gibberlink RFC 9421 clinic.

A running HTTP endpoint (stdlib only, no new deps) that turns the local simulation into an actual reachable
service, wrapping the already-tested sealed-transport control layer (clinic_transport.py):

  POST /clinic   -- an enrolled agent sends an RFC 9421-signed VAL envelope; the listener runs the full
                    fail-closed pipeline (size+schema -> signature over the anchored key -> rate/cost cap
                    -> replay cache -> audit) then answers: a CONCRETE signed request goes to the real
                    /explain engine, a CONCEPTUAL question to the grounded responder. The answer is itself
                    signed by the clinic key so the agent can verify it. Both hops are signed + verified.
  GET  /health   -- liveness.
  GET  /.well-known/agent-card.json -- A2A discovery card.

Enrollment is out of band: anchored peers load from clinic_enrolled.json ({keyid: pubkey_hex}). The clinic
signs with an Ed25519 key (env CLINIC_SIGNING_KEY_HEX, else ephemeral for a local run). Conceptual answers
use the DEDICATED fail-closed CLINIC_OR_KEY; with no key the grounded path degrades to the curated answer
(never crashes, never bills the shared key).

NOT open-deployed here: binds 127.0.0.1 by default. Public exposure (bind, TLS, process isolation, the
capped key, an independent review of the running listener) is the final gated step -- but this is a genuine
running endpoint, not a sim.
"""
from __future__ import annotations
import argparse, json, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clinic_transport as ct
from clinic_responder import answer_grounded, explain_request, get_clinic_or_key
from negotiation_gibberlink_demo import sign_envelope
from nacl.signing import SigningKey

HOME = Path.home() / ".algovoi" / "gibberlink"
# Enrollment table location is overridable so the container can bake it at /app (where Path.home()
# is not the home directory). Out-of-band anchored peers only: {keyid: pubkey_hex}.
ENROLL_FILE = Path(os.environ.get("CLINIC_ENROLL_FILE") or (HOME / "clinic_enrolled.json"))


def _clinic_ask(prompt: str) -> str:
    """Grounding-model call using the DEDICATED clinic key. Raises (fail closed) if the key is unset;
    answer_grounded catches that and degrades to the deterministic curated answer."""
    import urllib.request
    key = get_clinic_or_key()
    body = json.dumps({"model": "google/gemini-2.5-flash",
                       "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": 320, "temperature": 0.3}).encode()
    req = urllib.request.Request("https://openrouter.ai/api/v1/chat/completions", data=body,
                                 headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.loads(r.read())
    m = d["choices"][0]["message"]
    return (m.get("content") or m.get("reasoning") or "").strip()


def responder(body: dict) -> dict:
    """Route a verified request. Concrete signed request -> real /explain engine; else conceptual grounded."""
    if body.get("intent") == "clinic_explain" and isinstance(body.get("request"), dict):
        return explain_request(body["request"])
    q = (body.get("q") or "")[:ct.MAX_QUESTION_CHARS]
    return answer_grounded(q, ask_fn=_clinic_ask)


class Clinic:
    """Holds the shared control-layer state + the clinic signing identity for the server's lifetime."""
    def __init__(self, signing_key: SigningKey, anchored: dict, audit_path: str | None = None,
                 open_explain: bool = False, gibberlink_enabled: bool = False,
                 enroll_store: str | None = None, stable_key: bool = False):
        self.sk = signing_key
        self.kid = "algovoi-clinic"
        self.gibberlink_enabled = gibberlink_enabled
        # stable_key=True means the signing key is pinned (CLINIC_SIGNING_KEY_HEX injected) and
        # therefore SURVIVES restarts, so the published pubkey is safe to ANCHOR out of band. When
        # False the key is ephemeral (regenerated each start): the card still publishes the current
        # pubkey for THIS session but marks it non-anchorable so nobody pins a key that will rotate.
        self.stable_key = stable_key
        # Baked/anchored peers + durable self-enrolled peers (proof-of-key-control).
        self.registry = ct.EnrollmentRegistry(anchored, store_path=enroll_store)
        self.replay = ct.ReplayCache()
        self.limiter = ct.RateLimiter()
        # Self-enrollment is rate-limited before (by IP) and after (by keyid) verification.
        self.enroll_limiter = ct.RateLimiter(
            per_peer=int(os.environ.get("CLINIC_ENROLL_PER_HOUR", "5")), window=3600,
            global_day=int(os.environ.get("CLINIC_ENROLL_DAILY", "500")))
        # Durable, restart-surviving audit when CLINIC_AUDIT_FILE is set (required for staging);
        # falls back to in-memory only for a throwaway local run.
        self.audit = ct.AuditLog(path=audit_path)
        # open_explain=True (public mode): unenrolled agents may use the /explain debugger
        # (self-asserted, no trust). Everything else still requires enrollment.
        self.verify_fn = ct.make_verify_fn(self.registry, allow_open_explain=open_explain)
        # The gibberlink AUDIO path is ALWAYS enrolled-only (never open walk-up), regardless of
        # open_explain, because a 71MB/4s exchange open to the internet is a DoS amplifier.
        # It also gets its own strict limiter: 1 req/min/peer + a low global daily ceiling.
        self.verify_fn_enrolled = ct.make_verify_fn(self.registry, allow_open_explain=False)
        self.gl_limiter = ct.RateLimiter(
            per_peer=1, window=60,
            global_day=int(os.environ.get("CLINIC_GIBBERLINK_DAILY", "100")))
        # The EASY front door: a plain, unsigned, open JSON /explain. Secure by nature (stateless,
        # read-only, public-data-only, no trust conferred), so it needs no signing -- just a
        # per-IP rate limit + a generous global daily cap to bound abuse.
        self.explain_limiter = ct.RateLimiter(
            per_peer=int(os.environ.get("CLINIC_EXPLAIN_PER_MIN", "20")), window=60,
            global_day=int(os.environ.get("CLINIC_EXPLAIN_DAILY", "5000")))

    def _run(self, raw: bytes, *, verify_fn=None, limiter=None):
        """Run the sealed pipeline over a raw VAL envelope (JSON bytes) and return the
        (status, signed_reply_envelope). Transport-agnostic: HTTP-JSON and gibberlink audio
        funnel through here so they share one security core + one signed reply. verify_fn /
        limiter default to the open HTTP set; the gibberlink path overrides with the
        enrolled-only verifier + its strict limiter."""
        status, ans = ct.handle_frame(raw, replay=self.replay, limiter=limiter or self.limiter,
                                      audit=self.audit, verify_fn=verify_fn or self.verify_fn,
                                      responder_fn=responder)
        payload = json.dumps({"status": status, "answer": ans}).encode()
        env = sign_envelope(self.sk, self.kid, authority="agents.algovoi.co.uk",
                            body=payload, created=int(time.time()))
        return status, env

    def handle(self, raw: bytes) -> tuple[str, bytes]:
        """HTTP-JSON transport: signed reply as JSON so the agent can verify it."""
        status, env = self._run(raw)
        return status, json.dumps(env).encode()

    def handle_enroll(self, raw: bytes, ip: str) -> tuple[int, bytes]:
        """SELF-ENROLLMENT (proof-of-key-control): an agent POSTs a VAL envelope SIGNED BY ITS KEY
        with body {intent:'clinic_enroll'}. We verify the self-signature (proves it controls the
        key), bind purpose + freshness + replay, then register keyid->pubkey durably. Establishes
        IDENTITY ONLY, never trust: it just unlocks the rate-bounded public tiers (gibberlink,
        conceptual). Rate-limited by IP (pre-verify) and keyid (post-verify); capped + audited."""
        from negotiation_gibberlink_demo import verify_envelope_selfasserted, envelope_hash
        allowed, _why = self.enroll_limiter.allow(f"ip:{ip or 'anon'}")   # pre-verify IP guard
        if not allowed:
            self.audit.append({"event": "enroll", "result": "ratelimited-ip"})
            return 429, b'{"error":"rate limited"}'
        try:
            env = ct.validate_frame(raw)                                  # size + schema
        except ct.TransportReject as e:
            return 400, json.dumps({"error": str(e)}).encode()
        ok, whyv, body = verify_envelope_selfasserted(env, now=int(time.time()))
        if not ok:
            self.audit.append({"event": "enroll", "result": "bad-sig"})
            return 400, json.dumps({"error": f"signature: {whyv}"}).encode()
        if not (isinstance(body, dict) and body.get("intent") == "clinic_enroll"):
            return 400, b'{"error":"envelope body.intent must be \\"clinic_enroll\\""}'
        if not self.replay.check_and_add(envelope_hash(env)):
            return 400, b'{"error":"replay"}'
        keyid = env.get("keyid"); pub = env.get("public_key_hex")
        if not keyid or not pub or len(pub) > ct.MAX_PUBKEY_HEX:
            return 400, b'{"error":"missing or oversized keyid / public_key_hex"}'
        allowed2, _ = self.enroll_limiter.allow(f"kid:{keyid}")           # post-verify keyid guard
        if not allowed2:
            self.audit.append({"event": "enroll", "result": "ratelimited-kid", "keyid": keyid})
            return 429, b'{"error":"rate limited (keyid)"}'
        status = self.registry.enroll(keyid, pub)
        self.audit.append({"event": "enroll", "result": status, "keyid": keyid})
        code = {"enrolled": 200, "exists": 200, "conflict": 409, "full": 503}.get(status, 400)
        out = {"enrolled": status in ("enrolled", "exists"), "status": status, "keyid": keyid,
               "note": "Identity only, not trust. You may now use the enrolled tiers (gibberlink "
                       "audio at /clinic/gibberlink, conceptual questions), subject to one-at-a-time "
                       "and per-peer/global rate + cost caps. Public data only."}
        return code, json.dumps(out).encode()

    def handle_plain_explain(self, raw: bytes, ip: str) -> tuple[int, bytes]:
        """EASY, OPEN, UNSIGNED /explain: an agent POSTs its own request as plain JSON and gets a
        diagnosis back. No VAL envelope, no enrollment. Safe because it only analyses the caller's
        OWN request against public rules and confers no trust; bounded by a per-IP + global limiter.
        Every answer carries the citation ask and a pointer to the signed/verifiable upgrade."""
        try:
            data = json.loads(raw)
        except Exception:
            return 400, b'{"error":"invalid json"}'
        req = data.get("request") if isinstance(data, dict) and "request" in data else data
        if not isinstance(req, dict):
            return 400, b'{"error":"send your signed request as JSON, or {\\"request\\": {...}}"}'
        allowed, why = self.explain_limiter.allow(ip or "anon")
        if not allowed:
            self.audit.append({"event": "explain-open", "result": "ratelimited", "why": why})
            return 429, b'{"error":"rate limited, slow down"}'
        try:
            res = explain_request(req)
        except Exception:
            self.audit.append({"event": "explain-open", "result": "bad-request"})
            return 400, b'{"error":"could not analyse that request; expected an RFC 9421 signed request"}'
        ex = res.get("explain") or {}
        self.audit.append({"event": "explain-open", "ip": ip, "valid": ex.get("valid")})
        out = {
            "explain": ex,
            "links": res.get("links"),
            "citation": "Diagnosed free by the AlgoVoi RFC 9421 clinic (agents.algovoi.co.uk) using "
                        "public RFC 9421/9530 rules. Please keep the citation and links.",
            "verifiable": "For a cryptographically SIGNED answer you can verify, POST a signed VAL "
                          "envelope to /clinic; native gibberlink audio is at /clinic/gibberlink.",
        }
        return 200, json.dumps(out).encode()

    def handle_gibberlink(self, waveform: bytes) -> tuple[str, bytes]:
        """Native gibberlink transport (ENROLLED-ONLY + admission-controlled): take a decode
        slot (raises GibberlinkBusy -> 503 if saturated), decode the ggwave audio to the VAL
        envelope, run the SAME pipeline under the enrolled-only verifier + strict gibberlink
        limiter, and return the signed reply re-encoded as gibberlink audio."""
        import clinic_gibberlink as gl
        gl.acquire_slot()                                          # concurrency admission BEFORE any decode
        try:
            env_in, profile = gl.decode_waveform(waveform)        # audio -> envelope + profile
            # decode_waveform reports which wire version arrived; the reply is encoded in the
            # SAME version (see envelope_to_waveform below), so v1 and v2 peers share one
            # endpoint with no flag day and no refusal.
            status, reply_env = self._run(json.dumps(env_in, separators=(",", ":")).encode(),
                                          verify_fn=self.verify_fn_enrolled, limiter=self.gl_limiter)
            try:
                return status, gl.envelope_to_waveform(reply_env, profile)  # signed reply -> audio
            except ValueError as exc:
                # The request was authenticated, but the selected audio profile
                # cannot carry the signed reply. Return a signed, small fallback
                # envelope so the caller can retry the same exchange over HTTP.
                return self._signed_fallback("audio-reply-too-large", str(exc))
        finally:
            gl.release_slot()

    def _signed_fallback(self, reason: str, detail: str) -> tuple[str, bytes]:
        """A SIGNED, small JSON envelope telling the caller this exchange cannot complete over
        audio and to retry over http-val. Used for both an oversized reply and a legacy-codec
        request, so a peer always gets a verifiable answer rather than unreadable audio."""
        fallback = {"status": "fallback", "reason": reason, "detail": detail,
                    "fallback": {"transport": "http-val", "endpoint": "/clinic",
                                 "action": "retry-signed-envelope"}}
        body = json.dumps(fallback, separators=(",", ":")).encode()
        return "fallback", json.dumps(sign_envelope(
            self.sk, self.kid, authority="agents.algovoi.co.uk", body=body,
            created=int(time.time())), separators=(",", ":")).encode()


def make_handler(clinic: Clinic):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep stdout clean; the audit log is the record
            pass

        def _send(self, code, body: bytes, ctype="application/json"):
            self.send_response(code); self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self._send(200, b'{"ok":true,"service":"algovoi-rfc9421-clinic"}')
            elif self.path == "/.well-known/agent-card.json":
                # Tiers, easiest first: open plain-JSON /explain (no signing) -> signed VAL /clinic
                # (verifiable) -> native gibberlink audio (enrolled).
                endpoints = {"explain": "/clinic/explain", "clinic": "/clinic",
                             "enroll": "/clinic/enroll"}
                transports = ["json-open", "http-val"]
                codec_info = None
                if clinic.gibberlink_enabled:
                    import clinic_gibberlink as gl
                    codec_info = gl.capabilities()
                    endpoints["gibberlink"] = "/clinic/gibberlink"   # native ggwave audio VAL
                    transports.append("gibberlink")
                gl_note = (" NATIVE GIBBERLINK (ggwave audio) is available at /clinic/gibberlink but "
                           "requires SELF-ENROLLMENT first: POST a VAL envelope signed by your key with "
                           "body {\"intent\":\"clinic_enroll\"} to /clinic/enroll (proves key control, "
                           "grants identity only, not trust). Enrolled tiers are one-at-a-time and "
                           "subject to per-peer + global rate/cost caps; availability is not guaranteed."
                           if clinic.gibberlink_enabled else "")
                card = {"name": "AlgoVoi RFC 9421 Clinic", "description":
                        "Live AI-to-AI support desk for RFC 9421/9530 HTTP Message Signatures, PUBLIC DATA "
                        "ONLY, free. EASIEST (no signing, no signup): POST your signed request as plain JSON "
                        "to /clinic/explain for a diagnosis. For a cryptographically SIGNED, verifiable answer, "
                        "POST a signed VAL envelope to /clinic." + gl_note +
                        " The only ask is a citation of the tools/links returned.",
                        "endpoints": endpoints, "transports": transports,
                        "gibberlink_codec": codec_info,
                        "enrollment": {"required_for": ["gibberlink", "conceptual"],
                                       "how": "POST a self-signed VAL envelope with body.intent='clinic_enroll' "
                                              "to /clinic/enroll", "grants": "identity only, not trust",
                                       "limits": "one-at-a-time; per-peer + global rate/cost caps"},
                        # Publish the clinic's SIGNING pubkey so any agent can ANCHOR our identity
                        # out of band (fetched over TLS from our domain) and verify that clinic
                        # replies are genuinely ours, independent of the transport. anchorable=false
                        # means the key is ephemeral this deploy: use it only for the current
                        # session, do not pin it. A public key is safe to publish by definition.
                        "signing": {"keyid": clinic.kid, "alg": "ed25519",
                                    "public_key_hex": clinic.sk.verify_key.encode().hex(),
                                    "anchorable": bool(clinic.stable_key),
                                    "note": ("stable pinned key; anchor it out of band to verify "
                                             "clinic replies as ours" if clinic.stable_key else
                                             "ephemeral key (rotates on restart); do not anchor, "
                                             "read it fresh from this card each session")},
                        "verifier": "algovoi-rfc9421-verifier",
                        "attribution": "Answers cite AlgoVoi's public RFC 9421 tools; please keep the citation."}
                self._send(200, json.dumps(card).encode())
            # GET hints on the POST-only endpoints. A bare 404 on a URL published in the agent
            # card reads as "wrong address"; these tell a probing agent how to use it instead.
            # (Present in the deployed image but absent from the captured tree -- restored here
            # so a rebuild does not silently remove a live, discoverable behaviour.)
            elif self.path == "/clinic/explain":
                self._send(200, json.dumps({
                    "method": "POST", "content_type": "application/json",
                    "usage": "POST your RFC 9421 signed HTTP request as JSON to get a diagnosis.",
                    "note": "No signup, no signing required. Free.",
                    "docs": "https://docs.algovoi.co.uk"}).encode())
            elif self.path == "/clinic":
                self._send(200, json.dumps({
                    "method": "POST", "usage": "POST a signed VAL envelope for a verifiable diagnosis.",
                    "easy_path": "For quick unsigned help, POST plain JSON to /clinic/explain.",
                    "docs": "https://docs.algovoi.co.uk"}).encode())
            elif self.path == "/clinic/enroll":
                self._send(200, json.dumps({
                    "method": "POST", "usage": "POST a self-signed VAL envelope with intent=clinic_enroll.",
                    "grants": "identity only, not trust",
                    "docs": "https://docs.algovoi.co.uk"}).encode())
            elif self.path == "/clinic/gibberlink":
                self._send(200, json.dumps({
                    "method": "POST", "usage": "POST ggwave audio with signed VAL envelope (enrolled only).",
                    "enroll_first": "/clinic/enroll",
                    "docs": "https://docs.algovoi.co.uk"}).encode())
            else:
                self._send(404, b'{"error":"not found"}')

        def do_POST(self):
            if self.path == "/clinic/enroll":             # self-enroll (proof-of-key-control)
                n = int(self.headers.get("Content-Length") or 0)
                if n > ct.MAX_FRAME_BYTES:
                    self._send(413, b'{"error":"frame too large"}'); return
                raw = self.rfile.read(n) if n else b""
                ip = (self.headers.get("X-Real-IP")
                      or (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip() or "anon")
                code, body = clinic.handle_enroll(raw, ip)
                self._send(code, body)
                return
            if self.path == "/clinic/explain":            # EASY: open, unsigned, plain-JSON debugger
                n = int(self.headers.get("Content-Length") or 0)
                if n > 64 * 1024:                          # plain JSON is small; bound hard
                    self._send(413, b'{"error":"request too large"}'); return
                raw = self.rfile.read(n) if n else b""
                ip = (self.headers.get("X-Real-IP")
                      or (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip() or "anon")
                code, body = clinic.handle_plain_explain(raw, ip)
                self._send(code, body)
                return
            if self.path == "/clinic":
                n = int(self.headers.get("Content-Length") or 0)
                if n > ct.MAX_FRAME_BYTES:                  # bound before reading (DoS guard)
                    self._send(413, b'{"error":"frame too large"}'); return
                raw = self.rfile.read(n) if n else b""
                status, signed = clinic.handle(raw)
                self._send(200 if status == "served" else 400, signed)
                return
            if self.path == "/clinic/gibberlink" and clinic.gibberlink_enabled:
                import clinic_gibberlink as gl
                n = int(self.headers.get("Content-Length") or 0)
                if n > gl.MAX_AUDIO_BYTES:                  # bound the (large) audio before reading
                    self._send(413, b'{"error":"audio too large"}'); return
                raw = self.rfile.read(n) if n else b""
                try:
                    status, audio = clinic.handle_gibberlink(raw)
                except gl.GibberlinkBusy:
                    self._send(503, b'{"error":"gibberlink busy, retry"}'); return
                except Exception:
                    self._send(400, b'{"error":"gibberlink decode failed"}'); return
                if status == "fallback":
                    self._send(409, audio, ctype="application/json")
                else:
                    self._send(200 if status == "served" else 400, audio,
                               ctype="application/octet-stream")
                return
            self._send(404, b'{"error":"not found"}')
    return H


def load_anchored() -> dict:
    try:
        return json.loads(ENROLL_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _load_signing_seed():
    """The Ed25519 signing seed (hex) or None. PREFERRED: a mounted secret file named by
    CLINIC_SIGNING_KEY_FILE (kept out of `docker inspect`); FALLBACK: the inline
    CLINIC_SIGNING_KEY_HEX env var. None -> an ephemeral key (local run)."""
    path = os.environ.get("CLINIC_SIGNING_KEY_FILE", "").strip()
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip() or None
        except OSError:
            return None
    return os.environ.get("CLINIC_SIGNING_KEY_HEX")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")          # local by default; public bind is a deliberate gated step
    p.add_argument("--port", type=int, default=8799)
    a = p.parse_args()
    kh = _load_signing_seed()
    sk = SigningKey(bytes.fromhex(kh)) if kh else SigningKey.generate()
    audit_path = os.environ.get("CLINIC_AUDIT_FILE") or str(HOME / "clinic_audit.jsonl")
    open_explain = os.environ.get("CLINIC_OPEN_EXPLAIN", "").lower() in ("1", "true", "yes")
    gibberlink = os.environ.get("CLINIC_GIBBERLINK", "").lower() in ("1", "true", "yes")
    if gibberlink:
        try:
            import clinic_gibberlink  # noqa: F401  (verifies ggwave is present before advertising it)
        except Exception as e:
            print(f"[warn] CLINIC_GIBBERLINK set but ggwave unavailable ({e}); disabling audio transport")
            gibberlink = False
    enroll_store = os.environ.get("CLINIC_ENROLL_STORE") or str(HOME / "clinic_enrolled_store.jsonl")
    clinic = Clinic(sk, load_anchored(), audit_path=audit_path, open_explain=open_explain,
                    gibberlink_enabled=gibberlink, enroll_store=enroll_store, stable_key=bool(kh))
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(clinic))
    print(f"clinic listener on http://{a.host}:{a.port}  clinic_pub={sk.verify_key.encode().hex()[:16]}...  "
          f"enrolled={len(clinic.registry._peers)}  open_explain={open_explain}  gibberlink={gibberlink}  "
          f"audit={audit_path}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
