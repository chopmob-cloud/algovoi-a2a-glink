# A2A conformance mapping (v0.3.0 and v1.0.1)

How this deployment (the `a2a-gateway/` front door + its agent card) maps to the
[Agent2Agent (A2A) protocol](https://a2a-protocol.org). Mapped against the
committed code, the published spec `v0.3.0`, and the current spec `v1.0.1`
(released 2026-05-28; a patch on `v1.0.0`, which carries the breaking changes).

## Summary

The `/a2a` front door serves **both A2A v0.3.0 and v1.0.1** and replies in the
same version the caller spoke. `message/send` returns a v0.3.0-shaped `Task`
(kind discriminators, lowercase enums); `SendMessage` returns a v1.0.1-shaped
`Task` (member-based Parts with `mediaType`, `SCREAMING_SNAKE` enums, an ISO 8601
millisecond timestamp). The Agent Card advertises both interfaces in
`supportedInterfaces[]` and keeps the v0.3.0 top-level fields for back-compat.
The skill routing is version-agnostic; only the envelope differs.

## v0.3.0 conformance

| Area | Spec (v0.3.0) | This deployment | Status |
| --- | --- | --- | --- |
| Discovery | Agent Card at `/.well-known/agent-card.json` | served (also at `/.well-known/agent.json`) | conformant |
| `protocolVersion` | top-level string | `"0.3.0"` | conformant |
| Transport | `JSONRPC` / `GRPC` / `HTTP+JSON` | `JSONRPC`, `preferredTransport: "JSONRPC"`, one `additionalInterfaces` entry | conformant (JSON-RPC only) |
| Method | `message/send` (+ optional stream/tasks/*) | `message/send`; anything else → `-32601` | conformant subset |
| Request | JSON-RPC 2.0 `params.message.parts[]` | strict shape checks → `-32602`; size cap → `-32600`/413; parse → `-32700` | conformant |
| Part (in) | `{"kind":"text","text":…}` / `{"kind":"data","data":…}` | read in `_parts_extract` | conformant |
| Response | `Task` or `Message` | `Task` `{kind:"task", status:{state:"completed", message}}` | conformant |
| Message (out) | `{role:"agent", parts:[…]}` with `kind` parts | as specified | conformant |
| capabilities | `streaming` / `pushNotifications` / `stateTransitionHistory` | all `false` (declared honestly) | conformant |
| Errors | JSON-RPC `-32xxx` | `-32700/-32600/-32601/-32602/-32603` | conformant |

Streaming, `tasks/*`, and push-notification methods are intentionally not
implemented; the card declares `streaming:false` / `pushNotifications:false`, so
this is a conformant reduced surface, not a violation.

## v0.3.0 -> v1.0.1 deltas (all implemented)

v1.0 removed discriminator `kind` fields (member-based polymorphism), normalised
enums to `SCREAMING_SNAKE_CASE`, and restructured the Agent Card. The `/a2a`
handler emits each shape from `_build_task(version, ...)`, selected by the method
name; `_parts_extract` reads either shape on input.

| # | v0.3.0 | v1.0.1 | Status |
| --- | --- | --- | --- |
| 1 | Part `{"kind":"text","text":…}` | `{"text":…, "mediaType":"text/plain"}` (no `kind`) | done |
| 2 | Part `{"kind":"data","data":…}` | `{"data":…, "mediaType":"application/json"}` | done |
| 3 | `"role":"agent"` | `"role":"ROLE_AGENT"` (both read on input) | done |
| 4 | Message `{"kind":"message",…}` | no `kind` (member-based) | done |
| 5 | Task `{"kind":"task",…}` | no `kind` | done |
| 6 | `status.state:"completed"` | `"TASK_STATE_COMPLETED"` | done |
| 7 | Card: `url` + `preferredTransport` + `additionalInterfaces[]` | `supportedInterfaces[{url, protocolBinding, protocolVersion}]` | done (both present) |
| 8 | Card: top-level `protocolVersion:"0.3.0"` | per-interface `protocolVersion` | done (both present) |
| 9 | method `message/send` | `SendMessage` | done (both accepted) |
| 10 | (none) | `status.timestamp` ISO 8601 with ms precision | done |
| 11 | HTTP binding content-type | v1.0.1 prefers `application/a2a+json` (HTTP+JSON binding only; N/A for JSON-RPC here) | n/a |

Implemented v1.0 addition: **`signatures[]` on the card** (detached JWS per spec
8.4) -- see below. Still optional and not implemented: `google.rpc.Status` error
`details[]`, `tenant` fields, cursor pagination, `extendedAgentCard`.

Covered by [a2a-gateway/test_a2a.py](../a2a-gateway/test_a2a.py): both versions'
envelope shapes, version-agnostic routing, and fail-closed transport errors.

## Signed Agent Card (spec 8.4)

The card can carry an A2A **detached-JWS signature** so it is offline-verifiable.
Per spec 8.4 the signed payload is the card with the `signatures` field and all
default-valued properties removed, then RFC 8785 (JCS) canonicalized; the
signature covers `BASE64URL(protected) + "." + BASE64URL(payload)` and the
payload is not embedded. We sign with Ed25519 (`alg: "EdDSA"`, `typ: "JOSE"`,
`kid`) and embed the public key as an OKP `jwk` in the protected header so a
client can verify offline. As with the clinic, an embedded key proves integrity
and key-of-signing, not identity: anchor the key out of band before trusting it.

The 32-byte Ed25519 seed is supplied at runtime and is never stored in the image
or repo; with no key the card is served unsigned (signatures are optional).
**Preferred:** point `AGENT_CARD_SIGNING_KEY_FILE` at a read-only mounted secret
file holding the seed, so the seed never appears in `docker inspect` (Config.Env).
An inline `AGENT_CARD_SIGNING_KEY_HEX` env var is accepted as a fallback. The
clinic reads its own signing seed the same way (`CLINIC_SIGNING_KEY_FILE`, else
`CLINIC_SIGNING_KEY_HEX`). Signing and verification live in
[a2a-gateway/card_signing.py](../a2a-gateway/card_signing.py), covered by
[a2a-gateway/test_card_signing.py](../a2a-gateway/test_card_signing.py)
(round-trip, anchored vs self-asserted, default-stripping, tamper detection, and
the file-secret path).

## Alignment strengths

v1.0 formally adopts **RFC 8785 (JCS)** and **RFC 7515 (JWS)** for Agent Card
signatures. This stack already ships RFC 8785 canonicalisation and Ed25519
signing (the same primitives behind the clinic), so a **signed Agent Card**
(`signatures[]`, a JWS over the JCS-canonical card) is a natural, differentiating
addition rather than new machinery. The agent's whole value proposition, offline
signature verification, is squarely in the direction v1.0 took its own trust
model.

## Implementation

The dual-version front door detects the requested version from the JSON-RPC
method name (`message/send` -> 0.3.0, `SendMessage` -> 1.0.1) and emits the
matching Part/enum shapes via `_build_task`, serving one v0.3.0 and one v1.0.1
interface in the card's `supportedInterfaces[]`. The routing logic (`_route_a2a`)
is version-agnostic and unchanged; only the envelope (Parts, enums, card shape)
differs. The card can also carry an A2A detached-JWS signature (spec 8.4), built
from the RFC 8785 + Ed25519 primitives already in this stack -- see below.
