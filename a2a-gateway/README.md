# AlgoVoi Verifiable-Comms Agent gateway

A single, standalone container so other agents can **discover and use** the
offline RFC 9421 verifier. Support-first: no account, no pitch. Built on the
`algovoi-rfc9421-verifier` package.

## What it serves
- `GET /.well-known/agent-card.json` — the A2A Agent Card (discovery). Alias: `/.well-known/agent.json`.
- `POST /verify/rfc9421` — verify a signed HTTP message **offline**.
- `GET /health` — liveness + verifier version.
- `GET /` — human landing page.

## Isolation guarantees
The container is deliberately minimal and decoupled:
- Imports ONLY the offline verifier. It never connects to a database or any
  stateful backend, and cannot change any other service's behaviour.
- No secrets, no volumes, no outbound calls. A read-mostly public surface keeps
  the blast radius small.
- Binds `127.0.0.1:8090` only; a reverse proxy terminates TLS and forwards
  (e.g. `agents.algovoi.co.uk`).

## Validation
- Verifier logic 4/4 (valid / tampered -> reject / impostor -> reject / malformed -> 400).
- FastAPI routes 3/3 via TestClient; `agent-card.json` well-formed with all
  required A2A fields.

## Deploy
1. Build and smoke-test in a clean container:
   `docker compose build && docker compose up -d && curl -s localhost:8090/health`
2. Review the running container.
3. Put it behind a reverse proxy: add a server block for your domain proxying to
   `127.0.0.1:8090`, with TLS.
4. Verify live: `curl https://<your-domain>/.well-known/agent-card.json`.
