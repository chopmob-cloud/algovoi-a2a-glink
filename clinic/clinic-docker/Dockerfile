# Isolated container for the gibberlink RFC 9421 clinic.
# Its OWN image, separate from any other service: co-locating clinic tools with a
# sensitive service would reopen the exfil boundary. Nothing here mounts a database, .env, or
# any other sensitive surface. Supports BOTH transports: HTTP-VAL (open
# walk-up) and native gibberlink ggwave audio (enrolled-only, one-at-a-time). ggwave is a pure
# codec used headlessly (no audio device).
# --- builder: compile ggwave's C++ extension here so the runtime stays slim (no g++) ---
FROM python:3.11-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends g++ && rm -rf /var/lib/apt/lists/*
# Pinned to the same versions as the repo-root requirements.txt so the image is reproducible
# and cannot drift from what the suites validate. rfc8785 is REQUIRED: clinic_gibberlink
# imports it for the GL2 canonical-JSON frame payload. Without it the listener starts but
# silently disables the audio transport (the guard misreports it as "ggwave unavailable").
RUN pip install --no-cache-dir --prefix=/install \
    "pynacl==1.6.2" "algovoi-rfc9421-verifier==0.4.4" "ggwave==0.4.3" "rfc8785==0.1.4"

# --- runtime: slim, non-root, no build tooling ---
FROM python:3.11-slim
COPY --from=builder /install /usr/local

# Non-root, no build tooling left in the final layer.
RUN adduser --disabled-password --gecos "" --uid 10001 clinic

WORKDIR /app
# Source the listener needs (no graders, no keys, no proprietary modules).
COPY clinic_listener.py clinic_transport.py clinic_responder.py \
     negotiation_gibberlink_demo.py clinic_monitor.py clinic_selftest.py \
     verifier_tool.py clinic_gibberlink.py secured_gibberlink_demo.py /app/
# Optional out-of-band enrollment table (keyid->pubkey); absent = zero peers enrolled (fail closed).
COPY clinic_enrolled.jso[n] /app/clinic_enrolled.json

# Audit is written to a dedicated mounted volume; the rest of the fs is read-only at runtime.
ENV CLINIC_AUDIT_FILE=/audit/clinic_audit.jsonl \
    CLINIC_ENROLL_FILE=/app/clinic_enrolled.json \
    CLINIC_GATEWAY_DIR=/app \
    HOME=/tmp \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
VOLUME ["/audit"]
USER clinic
EXPOSE 8799

# Bind 0.0.0.0 INSIDE the isolated container netns; the host publishes to 127.0.0.1 only
# (see run-staging.sh). Liveness is GET /health.
HEALTHCHECK --interval=30s --timeout=4s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8799/health',timeout=3).status==200 else 1)"
ENTRYPOINT ["python", "/app/clinic_listener.py", "--host", "0.0.0.0", "--port", "8799"]
