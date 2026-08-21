#!/usr/bin/env python3
"""gibberlink_clinic.py -- an RFC 9421 CLINIC, AI-to-AI, over gibberlink (v2: real engine).

Other agents queue, are served one at a time over a signed sound channel, and grade the help.
Two answer paths, both sourced ONLY from public data:

  * CONCRETE signed request  -> run the REAL public /explain engine (verifier_tool), hand back the
                                caller's own canonical signing base + Content-Digest check + diagnosis.
                                Impossible to be "too generic": it debugs THEIR bytes.
  * CONCEPTUAL question       -> a grounded answer composed strictly from PUBLIC_KNOWLEDGE (RFC 9421/
                                9530 + AlgoVoi's public tools), with deterministic public links.

Security (standing rule -- always maintain high security):
  * every transport hop is an RFC 9421-signed VAL envelope, verified against an OUT-OF-BAND anchored
    key (never the key inside the envelope); a bad signature aborts the hop.
  * the clinic NEVER asks for or accepts a private key.
  * answers cite ONLY publicly-published resources -- nothing local-only or commercial.
"""
from __future__ import annotations
import base64, json, time, urllib.request
from pathlib import Path

from secured_gibberlink_demo import send_over_sound, recv_from_sound, HOME
from negotiation_gibberlink_demo import sign_envelope, verify_envelope
from nacl.signing import SigningKey

from clinic_responder import answer_grounded, explain_request, _load_explain, get_clinic_or_key

# DESIGN FROZEN: A (the design notes, 2026-08-18) -- OpenRouter + inline
# PUBLIC_KNOWLEDGE, NOT a RAG library. The key is read lazily via a DEDICATED, fail-closed clinic key
# (get_clinic_or_key), never the shared runtime key, so the module imports without a key (benchmark/tests
# run offline) and a real model call fails closed with a clear error when the dedicated key is unset.

# The clinic's grounding brain -- fast, clean, returns content. It composes ONLY from public knowledge.
GROUNDING_MODEL = "google/gemini-2.5-flash"

# Conceptual visitors: frontier models briefed as real agent builders. They queue behind the concrete
# walk-in and are served one at a time. Failures degrade gracefully (skipped).
CONCEPTUAL_VISITORS = ["x-ai/grok-4.6", "anthropic/claude-opus-5", "meta-llama/llama-4-scout",
                       "google/gemini-2.5-flash"]

ASK_PROMPT = (
    "You are an engineer integrating RFC 9421 HTTP Message Signatures into an AI agent, and you have hit ONE "
    "real, specific, concrete problem. Ask the AlgoVoi signing clinic about YOUR exact scenario (e.g. a gateway "
    "rewriting a signed path, query-string canonicalization across libraries, which components leave a header "
    "mutable, Content-Digest on streaming bodies, key discovery/rotation). Output ONLY your question, one or two "
    "sentences, <=40 words, no preamble, no chain-of-thought."
)


# --- realtime telemetry OVER GIBBERLINK: every status frame is a signed VAL envelope,
# sent over the sound channel and verified against an anchored monitor key before the
# dashboard ever sees it. Monitoring rides the same secured transport as the Q&A. ---
STATUS_PATH = HOME / "clinic_status.json"
_TELE_SK = None            # clinic telemetry signing key (set in main)
_TELE_KID = "clinic-telemetry"
_MON_KNOWS = {}            # the monitor's anchored view of the telemetry key (out of band)


def _classify(grade: str) -> str:
    g = (grade or "").lower()
    if g.startswith("(a) yes") or "correctly and specifically" in g or "yes, it correctly" in g \
       or ("yes" in g[:40] and "correct" in g):
        return "hit"
    if "partly" in g[:60] or "too generic" in g or "partial" in g[:60]:
        return "partial"
    if g[:20].startswith("(a) no") or g[:12].startswith("no,") or "does not" in g[:60]:
        return "miss"
    return "answered"


def write_status(state: dict) -> None:
    """Publish the live snapshot -- OVER GIBBERLINK. Sign the frame, send it over sound, verify it
    against the anchored monitor key, and persist ONLY the verified frame for the dashboard. Falls
    back to a direct write if telemetry keys aren't wired (e.g. offline self-test)."""
    state["updated"] = time.time()
    state["telemetry"] = "gibberlink"
    payload = json.dumps(state).encode()
    if _TELE_SK is not None:
        try:
            now = int(time.time())
            env = sign_envelope(_TELE_SK, _TELE_KID, authority="agents.algovoi.co.uk",
                                body=payload, created=now)
            wave = send_over_sound(env, HOME / "clinic_tele.wav")
            got = recv_from_sound(wave)
            ok, why, body = verify_envelope(got, anchored_peers=_MON_KNOWS,
                                            expected_keyid=_TELE_KID, now=now)
            if ok:
                state["tele_frames_verified"] = state.get("tele_frames_verified", 0) + 1
                state["tele_kb"] = len(wave) // 1000
                # persist the frame that actually came off the sound channel (re-serialize with the
                # bumped counter so the dashboard sees the verified-frame count).
                verified = json.loads(body) if isinstance(body, (bytes, bytearray, str)) else body
                verified["tele_frames_verified"] = state["tele_frames_verified"]
                verified["tele_kb"] = state["tele_kb"]
                STATUS_PATH.write_text(json.dumps(verified), encoding="utf-8")
                return
            state["tele_error"] = f"telemetry frame rejected: {why}"
        except Exception as e:  # noqa: BLE001
            state["tele_error"] = f"telemetry hop failed: {str(e)[:70]}"
    try:
        STATUS_PATH.write_text(json.dumps(state), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass


def _event(state: dict, msg: str) -> None:
    state.setdefault("events", []).append({"t": time.time(), "msg": msg})
    state["events"] = state["events"][-10:]      # keep the telemetry frame small for the sound hop
    write_status(state)


def ask_model(model: str, prompt: str, max_tokens: int = 450) -> str:
    body = json.dumps({"model": model,
                       "messages": [{"role": "user", "content": prompt}],
                       "max_tokens": max_tokens, "temperature": 0.3}).encode()
    req = urllib.request.Request("https://openrouter.ai/api/v1/chat/completions", data=body,
                                 headers={"Authorization": f"Bearer {get_clinic_or_key()}",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        d = json.loads(r.read())
    msg = d["choices"][0]["message"]
    content = (msg.get("content") or msg.get("reasoning") or "").strip()
    if not content:
        raise ValueError("empty content")
    return content


def _clip(q: str) -> str:
    """Guard against a model leaking chain-of-thought as the question."""
    q = q.strip().strip('"')
    # keep the first paragraph / first two sentences only
    q = q.split("\n\n")[0].strip()
    return q[:400]


def make_broken_request() -> dict:
    """Build a genuinely broken signed request for the concrete /explain demo: sign a body, then
    TAMPER the body so its Content-Digest no longer matches (a real 'body altered in transit' bug).
    Uses the public signer; returns the explain payload + the ephemeral public key to verify against."""
    _explain, sign_demo, _err = _load_explain()
    good = sign_demo({
        "method": "POST", "authority": "api.example.com", "path": "/v1/pay",
        "body_b64": base64.b64encode(b'{"amount":10,"to":"acct_9"}').decode(),
        "covered_components": ["@method", "@authority", "@path", "content-digest"],
        "keyid": "builder-key",
    })
    sr = good["signed_request"]
    pub = good["ephemeral_key"]["public_key_hex"]
    tampered_body = base64.b64encode(b'{"amount":9999,"to":"acct_9"}').decode()   # <-- altered after signing
    payload = {"method": sr["method"], "authority": sr["authority"], "path": sr["path"],
               "scheme": sr["scheme"], "headers": sr["headers"], "body_b64": tampered_body,
               "public_key_hex": pub}
    return payload


def _fmt_answer(ans: dict) -> str:
    if ans.get("explain") is not None:                 # concrete /explain path
        e = ans["explain"]
        cd = e.get("content_digest") or {}
        lines = [f"verdict: {'VALID' if e.get('valid') else 'INVALID'}",
                 f"errors: {e.get('errors')}",
                 f"content-digest match: {cd.get('match')} (header {cd.get('header')!r} vs recomputed {cd.get('recomputed')!r})",
                 f"covered components: {e.get('covered_components')}",
                 "signature base (the exact bytes that must be signed):",
                 (e.get('signature_base') or '(none)'),
                 "diagnosis:"] + [f"  - {d}" for d in (e.get('diagnosis') or [])]
        body = "\n".join(lines)
    else:
        body = ans.get("answer") or "(no answer)"
    links = "\n".join(f"  - {l['label']}: {l['url']}" for l in ans["links"])
    return f"{body}\n\nLinks:\n{links}"


def _serve(clinic, kid_clinic, visitor_label, mode, model, transcript, state, idx):
    """Serve one visitor end to end over signed sound. mode in {'ask','explain'}."""
    visitor = SigningKey.generate()
    kid_visitor = "visiting-agent"
    clinic_knows = {kid_visitor: visitor.verify_key.encode().hex()}
    visitor_knows = {kid_clinic: clinic.verify_key.encode().hex()}
    now = int(time.time())
    ag = state["agents"][idx]
    ag["status"] = "serving"; state["now_serving"] = visitor_label
    _event(state, f"now serving: {visitor_label}")

    # 1. Build the visitor's request (a real question, or a broken signed request).
    if mode == "explain":
        try:
            broken = make_broken_request()
        except Exception as e:  # noqa: BLE001
            print(f"  could not build concrete request: {str(e)[:90]}"); return
        inner = {"intent": "clinic_explain",
                 "note": "My signature was fine but the server says the body doesn't match. Here's my request.",
                 "request": broken}
        shown_q = "[concrete] signed request whose body was altered after signing (Content-Digest bug)"
    else:
        try:
            q = _clip(ask_model(model, ASK_PROMPT))
        except Exception as e:  # noqa: BLE001
            print(f"  visitor model error: {str(e)[:80]}"); return
        inner = {"intent": "clinic_question", "q": q}
        shown_q = q
    print(f"  Q: {shown_q}", flush=True)

    # 2. Visitor -> Clinic : signed envelope over sound.
    q_env = sign_envelope(visitor, kid_visitor, authority="visiting-agent",
                          body=json.dumps(inner).encode(), created=now)
    q_wave = send_over_sound(q_env, HOME / "clinic_q.wav")
    q_got = recv_from_sound(q_wave)
    ok, why, q_body = verify_envelope(q_got, anchored_peers=clinic_knows,
                                      expected_keyid=kid_visitor, now=now)
    if not ok:
        print(f"  [SECURITY] clinic rejected unsigned/forged envelope: {why}")
        ag["status"] = "rejected"; ag["verdict"] = "security"; _event(state, f"SECURITY reject: {why}"); return
    print(f"  clinic verified the visitor's signature over sound ({len(q_wave)//1000} KB)", flush=True)
    state["hops_verified"] = state.get("hops_verified", 0) + 1
    ag["question"] = shown_q[:160]; _event(state, "verified visitor signature over sound (hop 1/2)")

    # 3. Clinic answers -- real /explain engine, or grounded-from-public-data.
    if q_body.get("intent") == "clinic_explain":
        try:
            ans = explain_request(q_body["request"])
        except Exception as e:  # noqa: BLE001
            print(f"  explain engine error: {str(e)[:90]}"); return
        print(f"  routed -> /explain live engine (verdict valid={ans['explain']['valid']}, "
              f"digest_match={ (ans['explain']['content_digest'] or {}).get('match') })", flush=True)
    else:
        ans = answer_grounded(q_body["q"], ask_fn=lambda p: ask_model(GROUNDING_MODEL, p, max_tokens=320))
        print(f"  routed -> topic={ans['topic']} grounded={ans.get('grounded')}", flush=True)
    ag["topic"] = ans.get("topic"); ag["grounded"] = ans.get("grounded")
    ag["status"] = "answered"; _event(state, f"answered ({ag['topic']}) -> signing reply")

    # 4. Clinic -> Visitor : signed answer over sound.
    a_env = sign_envelope(clinic, kid_clinic, authority="agents.algovoi.co.uk",
                          body=json.dumps({"topic": ans.get("topic"), "answer": ans.get("answer"),
                                           "explain": ans.get("explain"), "links": ans["links"]}).encode(),
                          created=now)
    a_wave = send_over_sound(a_env, HOME / "clinic_a.wav")
    a_got = recv_from_sound(a_wave)
    ok2, why2, a_body = verify_envelope(a_got, anchored_peers=visitor_knows,
                                        expected_keyid=kid_clinic, now=now)
    if not ok2:
        print(f"  [SECURITY] visitor rejected clinic answer: {why2}")
        ag["verdict"] = "security"; _event(state, f"SECURITY reject (answer): {why2}"); return
    print("  visitor verified the clinic's signature over sound. Answer delivered.", flush=True)
    state["hops_verified"] = state.get("hops_verified", 0) + 1
    ag["status"] = "delivered"; _event(state, "visitor verified clinic signature (hop 2/2) - delivered")

    # 5. Grade honestly (the concrete walk-in is graded by the clinic brain; conceptual by the asker).
    grader = model or GROUNDING_MODEL
    grade_prompt = (
        f"You brought this to the AlgoVoi RFC 9421 clinic:\n{shown_q}\n\nThe clinic answered:\n"
        f"{_fmt_answer(a_body)}\n\nHonestly, in <=60 words: (a) did this correctly and SPECIFICALLY address "
        f"your scenario? (b) is the linked resource the right one? (c) any correction or gap?"
    )
    try:
        grade = ask_model(grader, grade_prompt, max_tokens=350).strip()
    except Exception as e:  # noqa: BLE001
        grade = f"(grade unavailable: {str(e)[:60]})"
    print(f"  GRADE: {grade}", flush=True)
    ag["verdict"] = _classify(grade); ag["status"] = "graded"; ag["grade"] = grade[:220]
    state["now_serving"] = None
    _event(state, f"graded {visitor_label}: {ag['verdict'].upper()}")

    transcript.append({"visitor": visitor_label, "mode": mode, "question": shown_q,
                       "topic": ans.get("topic"), "grounded": ans.get("grounded"),
                       "answer": a_body.get("answer"), "explain": a_body.get("explain"),
                       "links": a_body["links"], "grade": grade})


def main():
    global _TELE_SK, _MON_KNOWS
    clinic = SigningKey.generate()
    kid_clinic = "algovoi-clinic"
    # telemetry identity: the monitor anchors this key out of band, so it only accepts status
    # frames that carry a valid signature over the sound channel.
    _TELE_SK = SigningKey.generate()
    _MON_KNOWS = {_TELE_KID: _TELE_SK.verify_key.encode().hex()}
    transcript = []

    # FIFO waiting room: one concrete walk-in first, then the conceptual visitors.
    queue = [("concrete /explain walk-in", "explain", None)] + \
            [(m, "ask", m) for m in CONCEPTUAL_VISITORS]
    total = len(queue)

    # live state the dashboard polls
    state = {
        "open": True, "total": total, "hops_verified": 0, "now_serving": None,
        "grounding_model": GROUNDING_MODEL, "events": [],
        "agents": [{"label": lbl, "mode": mo, "status": "waiting", "verdict": "pending",
                    "topic": None, "grounded": None, "question": None, "grade": None}
                   for (lbl, mo, _md) in queue],
    }
    _event(state, f"clinic OPEN - {total} agents queued")
    print(f"=== AlgoVoi RFC 9421 clinic OPEN (v2: real engine). {total} agents queued. One at a time. ===",
          flush=True)

    for idx in range(total):
        label, mode, model = queue[idx]
        waiting = total - idx - 1
        print(f"\n--- now serving {idx+1}/{total}: {label}  ({waiting} still waiting) ---", flush=True)
        _serve(clinic, kid_clinic, label, mode, model, transcript, state, idx)

    state["open"] = False; state["now_serving"] = None
    _event(state, "clinic session complete")

    out = HOME / "gibberlink_clinic_v2_results.json"
    out.write_text(json.dumps(transcript, indent=2), encoding="utf-8")
    print(f"\n=== clinic served {len(transcript)}/{total} agents over gibberlink -> {out} ===")


if __name__ == "__main__":
    main()
