#!/usr/bin/env bash
# Mutation testing of the security-critical helpers with Stryker.NET: the tool changes the code (flips a comparison, drops a
# statement, empties a string ...) and runs YOUR unit tests (Kind=Unit) against every change. A change that no test notices = "survivor".
# The mutation score must stay above the 'break' threshold in backend/tests/SecLab.Api.Tests/stryker-config.json.
# Requires: .NET 10 on PATH; no database (unit tests only), jq.
set -uo pipefail
cd "$(dirname "$0")/../.."
dotnet tool restore >/dev/null
cd backend/tests/SecLab.Api.Tests
rm -rf StrykerOutput
dotnet stryker > "${TMPDIR:-/tmp}/stryker.log" 2>&1; rc=$?       # configuration (targets, Kind=Unit filter, thresholds): stryker-config.json
grep -E "Killed|Survived|Timeout|NoCoverage|mutation score|threshold|ERR|Unrecognized" "${TMPDIR:-/tmp}/stryker.log"

report=$(ls -t StrykerOutput/*/reports/mutation-report.json 2>/dev/null | head -1)
if [ -n "$report" ]; then
  echo; echo "== survivors (each one is a test you have not written yet - or an equivalent mutant: write down why)"
  jq -r '.files | to_entries[] | .key as $f | .value.mutants[] | select(.status=="Survived" or .status=="NoCoverage")
         | "\(.status | .[0:8])  \($f | split("/") | last):\(.location.start.line)  \(.mutatorName)  -> \((.replacement // "") | gsub("\n";" ") | .[0:60])"' "$report"
  echo "html report: backend/tests/SecLab.Api.Tests/$(dirname "$report")/mutation-report.html"
fi
exit $rc
