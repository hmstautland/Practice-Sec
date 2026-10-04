#!/usr/bin/env python3
"""A tiny detection engine over the API's JSON console log (one JSON object per line).

Usage:   dotnet run --project backend/src/SecLab.Api 2>&1 | tee /tmp/seclab.log      # terminal 1
         python3 docs/attack-scripts/12-detect.py /tmp/seclab.log                     # terminal 3 (after the attack)

It looks only at the audit events (category "SecLab.Audit") and prints findings a human or an alerting system would act on.
Thresholds are deliberately low for the lab. Real ones come from your baseline.
"""
import collections, json, sys

path = sys.argv[1] if len(sys.argv) > 1 else "/dev/stdin"
events = []
for line in open(path, errors="replace"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        e = json.loads(line)
    except ValueError:
        continue
    if e.get("Category") == "SecLab.Audit":
        state = e.get("State", {})
        events.append({"ts": e.get("Timestamp", ""), "level": e.get("LogLevel"), **{k: v for k, v in state.items() if not k.startswith("{")}})

def by(ev, key):
    c = collections.defaultdict(list)
    for e in events:
        if e.get("Event") == ev:
            c[e.get(key, "?")].append(e)
    return c

print(f"{len(events)} audit events read\n")
findings = 0

# 1. Brute force: many failures from one address
for ip, es in by("login.failed", "ClientIp").items():
    users = {e.get("Username") for e in es}
    if len(es) >= 5:
        kind = "CREDENTIAL STUFFING (many different users)" if len(users) >= 4 else "BRUTE FORCE (few users, many guesses)"
        print(f"[ALERT] {kind}: {len(es)} failed logins from {ip} against {len(users)} account(s); reasons: {dict(collections.Counter(e.get('Reason') for e in es))}")
        findings += 1

# 2. Accounts locked
for uid, es in by("login.locked", "UserId").items():
    print(f"[ALERT] account locked after repeated failures: user {uid} (source {es[0].get('ClientIp')})")
    findings += 1

# 3. Enumeration of resources / privilege probing
for uid, es in by("authz.denied", "UserId").items():
    if len(es) >= 3:
        print(f"[ALERT] user {uid} was denied {len(es)} times - probing for access? endpoints: {sorted({e.get('Endpoint') for e in es})[:4]}")
        findings += 1

# 4. Key guessing
for ip, es in by("apikey.rejected", "ClientIp").items():
    if len(es) >= 3:
        print(f"[ALERT] {len(es)} rejected API keys from {ip} - key guessing or a leaked/revoked key still in use")
        findings += 1

# 5. Flooding
for ip, es in by("ratelimit.rejected", "ClientIp").items():
    if len(es) >= 3:
        print(f"[WARN ] {ip} hit the rate limiter {len(es)} times")
        findings += 1

# 6. Always interesting: privileged and destructive changes
for ev in ("role.changed", "account.deleted"):
    for e in (x for x in events if x.get("Event") == ev):
        print(f"[AUDIT] {ev}: {json.dumps({k: v for k, v in e.items() if k != 'ts'})}")

print("\nno findings" if findings == 0 else f"\n{findings} finding(s)")
