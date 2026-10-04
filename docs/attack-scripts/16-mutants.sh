#!/usr/bin/env bash
# "Attacks" on your TEST SUITE: for each mutant, one security control or contract silently breaks in the test host
# (see Mutants in backend/tests/SecLab.Api.Tests/Step16Support.cs) and your suite must go RED. A mutant that leaves the suite green
# is a hole in your tests. Requires: .NET 10 on PATH, SQL Server running, .env loaded (set -a; source .env; set +a).
#
#   bash docs/attack-scripts/16-mutants.sh                 # baseline + every mutant
#   bash docs/attack-scripts/16-mutants.sh admin-open      # only the named mutant(s)
set -uo pipefail
cd "$(dirname "$0")/../.."
[ -n "${ConnectionStrings__Default:-}" ] || { echo "load .env first:  set -a; source .env; set +a"; exit 2; }
PROJECT=backend/tests/SecLab.Api.Tests
FILTER='Step=16&Kind!=Meta'          # your own tests; the meta checks (Kind=Meta) do not run application code
ALL=(admin-open ownership-skip fallback-off phantom-route password-leak error-shape strip-headers no-rate-limit)
MUTANTS=("${@:-${ALL[@]}}")

dotnet build "$PROJECT" -v q --nologo 2>&1 | grep -E "error|Build succeeded" | head -5

run() { # $1 = mutant name or empty; prints the summary line, returns the test exit code
  local out; out=$(SECLAB_MUTANT="${1:-}" dotnet test "$PROJECT" --no-build --filter "$FILTER" 2>&1); local rc=$?
  echo "$out" | grep -E "^(Passed|Failed)!" | sed 's/ - SecLab.*//' ; echo "$out" | grep -qE "(Passed|Failed)!.*Total: +[1-9]" || { echo "   (no tests ran - is there a Learner/ suite?)"; return 99; }
  return $rc
}

echo "== baseline: your suite on the unmodified application (want: all green)"
if ! run ""; then echo "BASELINE IS NOT GREEN - fix that first"; exit 1; fi

survivors=()
for m in "${MUTANTS[@]}"; do
  echo "== mutant '$m' (want: red)"
  if run "$m"; then echo "   SURVIVED: your tests did not notice"; survivors+=("$m"); else echo "   killed"; fi
done

echo
if [ ${#survivors[@]} -eq 0 ]; then echo "all ${#MUTANTS[@]} mutants killed"; else echo "survivors: ${survivors[*]}"; exit 1; fi
