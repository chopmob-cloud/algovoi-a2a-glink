#!/usr/bin/env bash
# Run the clinic as a PRIVATE, isolated staging container.
# Implements the isolation spec for reviewing the running listener before any open deploy.
# This is NOT an open deploy: it publishes to 127.0.0.1 ONLY, no proxy route, no capped key.
#
#   private staging -> review the RUNNING listener -> add a spend-capped key
#   -> approve the exact public bind. Until then: private staging, not "live".
set -euo pipefail

IMAGE="${IMAGE:-algovoi-clinic:staging}"
NAME="${NAME:-algovoi-clinic-staging}"
HOST_PORT="${HOST_PORT:-127.0.0.1:8799}"        # loopback ONLY; never 0.0.0.0
AUDIT_DIR="${AUDIT_DIR:-/opt/clinic/audit}"      # host dir for the durable audit chain (only writable mount)
NET="${NET:-clinic-net}"                         # dedicated bridge, isolated from other services

mkdir -p "$AUDIT_DIR"
# The container runs --read-only as uid 10001, so $AUDIT_DIR is its ONLY writable mount. A
# root-created dir is 0755 root-owned, so the durable audit append fails EACCES on the FIRST
# audited request. GET /health does not audit, so the healthcheck still reports "healthy" while
# every real POST dies with a reset connection. Own the mount to the runtime uid.
chown 10001:10001 "$AUDIT_DIR"
docker network inspect "$NET" >/dev/null 2>&1 || docker network create --internal "$NET" >/dev/null || \
  docker network create "$NET" >/dev/null   # --internal blocks egress entirely; drop it only if the
                                            # keyless staging step must reach the /explain engine.

# CLINIC_SIGNING_KEY_HEX is injected as a runtime secret (NOT an image layer / file mount).
# CLINIC_OR_KEY is deliberately ABSENT for staging: concrete /explain works keyless; the
# conceptual OpenRouter path fails closed (never bills a shared key).
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
  --network "$NET" \
  -p "${HOST_PORT}:8799" \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount type=bind,source="$AUDIT_DIR",target=/audit \
  --user 10001:10001 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --memory 256m --memory-swap 256m \
  --cpus 0.5 \
  --restart unless-stopped \
  -e CLINIC_SIGNING_KEY_HEX="${CLINIC_SIGNING_KEY_HEX:-}" \
  "$IMAGE"

echo "clinic staging container '$NAME' started on ${HOST_PORT} (loopback only)."
echo "audit chain: $AUDIT_DIR/clinic_audit.jsonl"
echo
echo "Egress note (host-level, required before any open deploy):"
echo "  --network '$NET' is created with --internal = NO container egress at all (correct for the"
echo "  KEYLESS staging step, which makes no outbound calls). When the capped key is later added and"
echo "  the conceptual path is enabled, replace with a default-deny egress that permits HTTPS ONLY to"
echo "  openrouter.ai + the public verify endpoint (host iptables/nftables on the clinic bridge, or an"
echo "  egress proxy), denying loopback, RFC1918, 169.254.169.254 metadata, and all other outbound."
