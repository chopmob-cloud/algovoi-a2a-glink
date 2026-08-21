#!/usr/bin/env python3
"""test_a2a.py -- the /a2a front door speaks BOTH A2A v0.3.0 and v1.0.1.

Exercises the real FastAPI app through TestClient: the agent card advertises both
interfaces, `message/send` returns a v0.3.0-shaped Task (kind discriminators,
lowercase enums) and `SendMessage` returns a v1.0.1-shaped Task (no kind,
mediaType Parts, SCREAMING_SNAKE enums, ISO-8601 ms timestamp), the routing is
identical across versions, and malformed transport fails closed as JSON-RPC.

Run: python test_a2a.py   (needs fastapi + httpx; see requirements-dev.txt)
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fastapi.testclient import TestClient  # noqa: E402
import app as gw  # noqa: E402

client = TestClient(gw.app)
CHECKS: list[tuple[str, bool]] = []


def check(name: str, ok: bool) -> None:
    CHECKS.append((name, bool(ok)))
    print(f"  {'PASS' if ok else 'FAIL'} {name}")


def send(method: str, parts: list[dict], rid: int = 1) -> dict:
    body = {"jsonrpc": "2.0", "id": rid, "method": method,
            "params": {"message": {"role": "user", "parts": parts}}}
    return client.post("/a2a", json=body).json()


# ---- Agent Card advertises both protocol versions --------------------------
card = client.get("/.well-known/agent-card.json").json()
check("card top-level protocolVersion is 0.3.0", card.get("protocolVersion") == "0.3.0")
versions = {i.get("protocolVersion") for i in card.get("supportedInterfaces", [])}
check("card supportedInterfaces advertise 0.3.0 AND 1.0.1", {"0.3.0", "1.0.1"} <= versions)

# ---- v0.3.0: message/send -> kind discriminators, lowercase enums ----------
r = send("message/send", [{"kind": "text", "text": "hello"}])
t = r.get("result", {})
check("v0.3.0 result has kind=task", t.get("kind") == "task")
check("v0.3.0 status.state == completed", t.get("status", {}).get("state") == "completed")
m03 = t.get("status", {}).get("message", {})
check("v0.3.0 message.role == agent", m03.get("role") == "agent")
check("v0.3.0 message.kind == message", m03.get("kind") == "message")
check("v0.3.0 parts carry kind discriminators",
      all("kind" in p for p in m03.get("parts", [])) and m03.get("parts"))

# ---- v1.0.1: SendMessage -> member-based Parts, SCREAMING_SNAKE, timestamp --
r = send("SendMessage", [{"text": "hello"}])   # v1.0 member-based part (no kind)
t = r.get("result", {})
check("v1.0.1 result has NO kind field", "kind" not in t)
st = t.get("status", {})
check("v1.0.1 status.state == TASK_STATE_COMPLETED", st.get("state") == "TASK_STATE_COMPLETED")
check("v1.0.1 status.timestamp is ISO-8601 ms UTC",
      bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", st.get("timestamp", ""))))
m10 = st.get("message", {})
check("v1.0.1 message.role == ROLE_AGENT", m10.get("role") == "ROLE_AGENT")
check("v1.0.1 message has NO kind", "kind" not in m10)
parts = m10.get("parts", [])
check("v1.0.1 parts have NO kind and carry mediaType",
      bool(parts) and all("kind" not in p and "mediaType" in p for p in parts))

# ---- routing is identical across versions (member-based input read too) -----
d03 = send("message/send", [{"kind": "data", "data": {"skill": "conformance-vectors"}}])
d10 = send("SendMessage", [{"data": {"skill": "conformance-vectors"}}])
skill03 = d03["result"]["status"]["message"]["parts"][1]["data"].get("skill")
skill10 = d10["result"]["status"]["message"]["parts"][1]["data"].get("skill")
check("both versions route the conformance-vectors skill",
      skill03 == "conformance-vectors" and skill10 == "conformance-vectors")

# ---- transport errors fail closed as JSON-RPC ------------------------------
unknown = client.post("/a2a", json={"jsonrpc": "2.0", "id": 9, "method": "tasks/get"}).json()
check("unknown method -> -32601", unknown.get("error", {}).get("code") == -32601)
badparams = client.post("/a2a", json={"jsonrpc": "2.0", "id": 9, "method": "SendMessage",
                                      "params": {"message": {"parts": []}}}).json()
check("empty parts -> -32602", badparams.get("error", {}).get("code") == -32602)

# ---- GET hint lists both -----------------------------------------------------
hint = client.get("/a2a").json()
check("GET /a2a hint lists both methods",
      set(hint.get("supported", {})) == {"message/send", "SendMessage"})

passed = sum(1 for _, ok in CHECKS if ok)
total = len(CHECKS)
print(f"\nRESULT: {'ALL PASS' if passed == total else 'FAIL'} ({passed}/{total})")
sys.exit(0 if passed == total else 1)
