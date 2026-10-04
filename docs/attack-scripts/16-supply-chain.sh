#!/usr/bin/env bash
# The test code and its packages are part of the supply chain too (a test dependency runs on every developer machine and in CI).
# Requires: .NET 10 on PATH, node/npm, network access. Exit code != 0 when something needs attention.
set -uo pipefail
cd "$(dirname "$0")/../.."
rc=0

echo "== 1. restore exactly what the lock files say (what CI does: RestoreLockedMode)"
out=$(dotnet restore backend/SecLab.slnx --locked-mode -v q 2>&1) && echo "   ok" || { echo "$out" | grep -E "error|NU1004|NU1403" | sort -u | head -8; rc=1; }

echo "== 2. known vulnerabilities in NuGet packages, direct AND transitive (want: none)"
out=$(dotnet list backend/SecLab.slnx package --vulnerable --include-transitive 2>&1); echo "$out" | grep -E "Severity|has the following vulnerable|no vulnerable" | sort -u
echo "$out" | grep -q "has the following vulnerable packages" && rc=1

echo "== 3. deprecated packages (want: none, except reason 'Legacy' = a successor exists: note it, plan it)"
out=$(dotnet list backend/SecLab.slnx package --deprecated --include-transitive 2>&1)
echo "$out" | grep -E "^ +> " | sort -u
echo "$out" | grep -E "^ +> " | grep -qv "Legacy" && { echo "   deprecated for a reason other than Legacy (critical bugs?): act"; rc=1; }

echo "== 4. outdated packages (information: decide, do not auto-update blindly)"
dotnet list backend/SecLab.slnx package --outdated 2>&1 | grep -E "^   >" | head -20

echo "== 5. front end: lock file present and npm audit (want: no high/critical)"
[ -f frontend/package-lock.json ] || { echo "frontend/package-lock.json is missing"; rc=1; }
out=$(cd frontend && npm audit --audit-level=high 2>&1) && echo "   $(echo "$out" | tail -1)" || { echo "$out" | tail -12; rc=1; }

echo; [ $rc -eq 0 ] && echo "supply chain: nothing to act on" || echo "supply chain: see above"
exit $rc
