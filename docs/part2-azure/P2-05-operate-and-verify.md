# P2-05 – Operate and verify

> Prerequisites: P2-01–P2-04, a deployed `dev` (and ideally `test`) environment. Time: ~1 h.

## Goal
Prove, repeatably and from the outside, that the deployed system behaves like the hardened Part 1 app – and be ready for the day something goes wrong.

Acceptance criteria:

1. A **smoke-test script** (`bash`, `curl`) that takes a base URL and checks: HTTPS-only, redirect, HSTS, TLS version floor, security headers from Part 1, authentication required (401), no verbose error (Part 1 step 11), rate limiting engaged (429) and WAF block, origin not directly reachable, health endpoint OK. It exits non-zero on any failure and runs as the last step of each deploy job.
2. An **OWASP ZAP baseline scan** against the deployed `dev`/`test` URL, run from GitHub Actions on a schedule and on demand, with a rules file that records accepted findings with a reason; results are uploaded as an artifact. (Passive baseline only; a full active scan is done only against environments you own and never against `prod`.)
3. A **security review checklist** you complete before the first `prod` deployment and every quarter.
4. An **incident and secret-rotation runbook**: who is called, how to contain, how to rotate each secret class (CI identity, Key Vault secrets, Entra app credentials if any, SQL admin group membership, API keys), how to investigate with KQL, and how to record the outcome.
5. You have **rehearsed** one scenario end to end (suggested: a leaked API key of Part 1 step 06).

## Threat / why
Hardened configuration erodes: someone opens a firewall rule "for a demo", a policy is exempted, a new endpoint skips the authorization policy. Without a repeatable external check you find out from an attacker. And when an incident happens, an unrehearsed team improvises: rotates the wrong secret, deletes the evidence (a deleted revision, a purged log), or forgets that the old key still works.

Demonstrate the drift: on `dev`, temporarily set SQL `publicNetworkAccess` to `Enabled`, wait for the Policy/Defender signal, and see how long it takes you to notice without the checks of this step.

## Concepts
- **Smoke test vs security test.** Smoke: is it up. Security smoke: are the controls still on. Keep it fast, deterministic, no destructive calls, and free of real credentials (use a test identity from the `test` environment held in the environment's secrets/Key Vault).
- **Scan types.** ZAP *baseline* = spider + passive rules, safe. *Full/active scan* = attacks; only against disposable environments. ZAP needs an OpenAPI definition (Part 1 step 08 versioning) or a URL list to cover an API well; authenticated scanning needs a token setup. GitHub Action `zaproxy/action-baseline` (check the current version) and the `.zap/rules.tsv` format (rule id, `IGNORE`/`WARN`/`FAIL`, comment).
- **Security review.** Map the deployment to the OWASP Top 10 / API Top 10 (Part 1 step 13), the OWASP CI/CD Top 10, and Defender for Cloud secure-score recommendations.
- **Incident response basics** (NIST 800-61 phases): prepare, detect & analyse, contain/eradicate/recover, post-incident review. Cloud specifics: revoke tokens/sessions, disable identity, snapshot evidence (activity log export, Log Analytics retention), rotate, redeploy from known-good IaC and a known image digest.
- **Rotation classes.** *Eliminated* (managed identity, OIDC – nothing to rotate), *versioned* (Key Vault secrets – add version, restart/reload, disable old), *overlapping* (API keys with two active keys), *root* (Entra tenant admin, break-glass accounts – stored offline, tested).
- **KQL** tables to know: `AzureDiagnostics`/resource-specific tables for Key Vault (`AzureDiagnostics` category `AuditEvent`), `ContainerAppConsoleLogs_CL`, `AppRequests`, `AzureActivity`, Front Door/WAF logs, SQL audit logs.

## Your turn
Tasks:
1. Write `smoke.sh` and call it from the deploy workflow after each environment deployment.
2. Add the ZAP baseline workflow (scheduled + manual) and an initial rules file; triage the first findings.
3. Write the review checklist and fill it in for `dev`.
4. Write the runbook (one page per scenario: leaked GitHub-to-Azure access, leaked API key, compromised container image, SQL data exposure suspicion) with exact commands for your names.
5. Rehearse one scenario; write down the time each step took and what surprised you.

<details><summary>Hint 1 – where to look</summary>

`docs/attack-scripts/01-https-check.sh` and the other Part 1 attack scripts – most checks in `smoke.sh` are their deployed-URL versions. ZAP docs: "Baseline Scan", "Automation Framework". Microsoft Learn: "Incident response playbooks" (compromised identity, app consent).
</details>

<details><summary>Hint 2 – which features</summary>

`curl -sS -o /dev/null -w '%{http_code}' --max-time`, `-I`, `--tls-max`, `--resolve`; loops sending N requests to trigger 429; `zaproxy/action-baseline` inputs (`target`, `rules_file_name`, `fail_action`, `allow_issue_writing`), `actions/upload-artifact`; `schedule:` cron trigger; `az monitor log-analytics query`; `az keyvault secret set` (new version) / `set-attributes --enabled false`; `az containerapp revision list/deactivate`; `az acr repository` and `az acr manifest` commands; `az ad app credential reset` (only if secrets still exist).
</details>

<details><summary>Hint 3 – shape of the solution</summary>

`smoke.sh`: a tiny `check name command expected` helper that prints PASS/FAIL and counts failures; deploy job step passes the URL from a deployment output through `env:`. ZAP workflow: read-only permissions, one job, no Azure login, target from an environment variable, report artifact. Runbook: per scenario the sections Detect, Contain (first 15 minutes), Investigate (queries), Eradicate/Rotate, Recover, Review.
</details>

## Verify
```bash
bash smoke.sh https://<dev-host>            # all PASS, exit code 0
echo $?
# make it fail on purpose: point at an HTTP-only or wrong host, or temporarily disable HSTS in dev, confirm FAIL and non-zero exit
actionlint .github/workflows/zap.yml
gh workflow run zap.yml -f target=https://<dev-host> && gh run watch
gh run download --name zap-report            # open report_html.html
az monitor log-analytics query -w <workspace-id> --analytics-query "AzureActivity | where TimeGenerated > ago(1h) | take 5"
```
Checklist:
- [ ] `smoke.sh` passes on `dev`/`test`, fails when a control is removed, and is wired into deploy jobs
- [ ] ZAP baseline ran; every remaining alert is fixed or listed in the rules file with a reason
- [ ] Review checklist completed for `dev`; open items have owners and dates
- [ ] Runbook covers the four scenarios with real resource names; contact list is current
- [ ] One rehearsal done; the leaked key is unusable afterwards (`curl` with the old key returns 401)
- [ ] Log retention lets you investigate at least 30 days back (check your workspace setting)

## Pitfalls
- A smoke test that logs in with a real user's credentials or prints tokens is itself a leak.
- ZAP against `prod` with active rules can delete data and trigger your own alerts and your provider's abuse detection.
- WAF/rate limiting will block your scanner; allow-list the runner deliberately for the test (and remove it), rather than switching protection off.
- "Rotate" without "revoke": the old key/secret version must be disabled and its use in logs checked.
- Rotating a Key Vault secret does not restart the app: know which of your consumers reload it.
- Deleting a compromised Container App destroys evidence; export logs and revision details first.
- Runbooks rot. Put a review date in them and rehearse after each architecture change.

## Further reading
- ZAP baseline scan and GitHub Action – https://www.zaproxy.org/docs/docker/baseline-scan/
- Microsoft security incident response playbooks – https://learn.microsoft.com/security/operations/incident-response-playbooks
- Microsoft Defender for Cloud recommendations – https://learn.microsoft.com/azure/defender-for-cloud/
- NIST SP 800-61 (Incident Handling Guide); OWASP Web Security Testing Guide; OWASP Top 10 CI/CD Security Risks; OWASP Logging Cheat Sheet

Stuck or done? Compare with the solution: [`docs/solutions/p2-05-operate-and-verify.md`](../solutions/p2-05-operate-and-verify.md).
