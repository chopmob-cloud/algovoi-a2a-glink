# AlgoVoi Verifiable-Comms Agent gateway -- clean, standalone container.
# Build in a clean container, deploy as its own container behind a reverse proxy.
# Isolated by design: no gateway feature flags, no compatibility shim, no gateway/DB deps.
FROM python:3.11-slim

# Non-root, no build toolchain left behind (wheels only).
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt || \
    pip install --no-cache-dir -r requirements.txt

COPY verifier_tool.py card_signing.py app.py agent-card.json ./
RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

# Liveness: the /health route (verifier import + card load must succeed).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3).status==200 else 1)"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
