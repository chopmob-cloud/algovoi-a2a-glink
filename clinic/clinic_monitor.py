#!/usr/bin/env python3
"""clinic_monitor.py -- active, read-only usage monitor for the gibberlink RFC 9421 clinic.

Watches the clinic's DURABLE audit file (the hash-chained JSONL written by clinic_transport.AuditLog)
and reports live usage WITHOUT widening the attack surface: it only READS the audit file, exposes no
network port, holds no key, and never touches the listener process. This is the "active monitor to see
it being used" (tail the audit chain + counts + alerts).

Counts, continuously:
  requests (served + rejected + error), served, rejected, error, per-peer, per reject-reason,
  rate-limit hits, daily-cap hits.
Alerts (to stderr, prefixed !!) on:
  audit chain break (tamper / corruption), daily-cost-cap exhaustion, and (with --pid) listener exit.

Usage:
  python clinic_monitor.py            # follow the local clinic_audit.jsonl live
  python clinic_monitor.py --file PATH [--pid N] [--once] [--interval SECONDS]
"""
from __future__ import annotations
import argparse, json, os, sys, time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clinic_transport as ct   # reuse the SAME chain verifier the listener uses

DEFAULT_AUDIT = Path.home() / ".algovoi" / "gibberlink" / "clinic_audit.jsonl"


def _read_records(path):
    recs = []
    if not os.path.exists(path):
        return recs
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except Exception:
                recs.append({"event": "_malformed"})
    return recs


def summarize(recs):
    ev = Counter(r.get("event") for r in recs)
    peers = Counter(r.get("keyid") for r in recs if r.get("event") == "served" and r.get("keyid"))
    reasons = Counter(r.get("reason") for r in recs if r.get("event") == "rejected" and r.get("reason"))
    rate_hits = sum(1 for r in recs if r.get("event") == "rejected"
                    and str(r.get("reason", "")).startswith("rate:"))
    cap_hits = sum(1 for r in recs if "global-daily-cap" in str(r.get("reason", "")))
    return {
        "requests": ev.get("served", 0) + ev.get("rejected", 0) + ev.get("error", 0),
        "served": ev.get("served", 0), "rejected": ev.get("rejected", 0),
        "error": ev.get("error", 0), "rate_hits": rate_hits, "cap_hits": cap_hits,
        "peers": peers, "reasons": reasons,
        "last_ts": recs[-1].get("ts") if recs else None,
    }


def render(s, chain_ok):
    peers = ", ".join(f"{k[:12]}:{v}" for k, v in s["peers"].most_common(6)) or "-"
    reasons = ", ".join(f"{k}:{v}" for k, v in s["reasons"].most_common(6)) or "-"
    when = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(s["last_ts"])) if s["last_ts"] else "-"
    return (f"[clinic] req={s['requests']} served={s['served']} rejected={s['rejected']} "
            f"error={s['error']} rate={s['rate_hits']} cap={s['cap_hits']} "
            f"chain={'OK' if chain_ok else 'BROKEN'} last={when}\n"
            f"         peers[{len(s['peers'])}]: {peers}\n"
            f"         rejects: {reasons}")


def _alert(msg):
    print(f"!! {msg}", file=sys.stderr, flush=True)


def run(path, pid=None, once=False, interval=3.0):
    prev_sig = None
    warned_cap = False
    while True:
        recs = _read_records(path)
        ok, n, why = ct.verify_audit_file(path) if os.path.exists(path) else (True, 0, "empty")
        s = summarize(recs)
        sig = (s["requests"], s["served"], s["rejected"], s["error"], ok)
        if sig != prev_sig:
            print(render(s, ok), flush=True)
            prev_sig = sig
        if not ok and n:
            _alert(f"AUDIT CHAIN BROKEN in {path} ({why}) -- possible tamper/corruption")
        if s["cap_hits"] and not warned_cap:
            _alert("DAILY COST CAP hit -- clinic is refusing conceptual requests until reset")
            warned_cap = True
        if pid and not _pid_alive(pid):
            _alert(f"listener pid {pid} is NOT running")
        if once:
            return 0 if ok else 1
        time.sleep(interval)


def _pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError):
        return False


def main():
    ap = argparse.ArgumentParser(description="Read-only usage monitor for the RFC 9421 clinic")
    ap.add_argument("--file", default=str(DEFAULT_AUDIT), help="durable audit JSONL to watch")
    ap.add_argument("--pid", type=int, default=None, help="listener pid to alert on if it exits")
    ap.add_argument("--once", action="store_true", help="print one snapshot and exit (exit 1 if chain broken)")
    ap.add_argument("--interval", type=float, default=3.0, help="poll seconds")
    a = ap.parse_args()
    try:
        return run(a.file, pid=a.pid, once=a.once, interval=a.interval)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
