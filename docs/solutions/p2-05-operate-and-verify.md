# Solution – P2-05 Operate and verify

> Spoiler. Try the step yourself first: [`../part2-azure/P2-05-operate-and-verify.md`](../part2-azure/P2-05-operate-and-verify.md). Reference files: [`solutions/p2-05-operate/smoke.sh`](../../solutions/p2-05-operate/smoke.sh), [`solutions/p2-05-operate/zap.yml`](../../solutions/p2-05-operate/zap.yml).
>
> **Verified:** `smoke.sh` passes `bash -n` (syntax); `zap.yml` parses as YAML. **Not verified:** either against a real deployment; endpoint paths (`/health`, `/api/v1/...`, `/api/debug/crash`) come from the Part 1 layout and may differ in your solution; `zaproxy/action-baseline` inputs are from memory (check the current version).

## 1. Smoke test
Copy to `scripts/smoke.sh` (called by `deploy-env.yml`). It checks HTTPS redirect, health, 401 on protected routes, HSTS >= 180 days, no server banner, `nosniff`, TLS 1.1 refused / 1.2 accepted, no stack trace, injection probe not served, CORS not reflecting a foreign origin, a small burst for 429 (warning only), and – if `ORIGIN_URL` is set – that the container app's own hostname is not directly usable.
```bash
bash scripts/smoke.sh https://<edge-host>
ORIGIN_URL=https://ca-seclab-api-dev.<env>.<region>.azurecontainerapps.io bash scripts/smoke.sh https://<edge-host>
```
Negative test: run it against `http://` (fails immediately), or against a host without HSTS, or remove a control in dev and watch the corresponding FAIL. Some TLS 1.1 checks depend on your local `curl`/OpenSSL build: a `000` can also mean "client cannot speak 1.1"; verify with `openssl s_client -tls1_1 -connect host:443` or `nmap --script ssl-enum-ciphers -p 443 host`.

## 2. ZAP baseline
Copy `zap.yml` to `.github/workflows/zap.yml`, create `.zap/rules.tsv` (tab-separated: `rule-id<TAB>IGNORE|WARN|FAIL<TAB>reason`), and set the `ZAP_TARGET` variable on the `dev` environment. Run:
```bash
gh workflow run zap-baseline -f target=https://<dev-edge-host>
gh run watch; gh run download --name zap-report
```
Triage every alert: fix (missing header -> app/edge config), or add a rule line with a reason. Typical first findings: CSP details, cache-control on API responses, cookies without `SameSite`. Provide the OpenAPI document from Part 1 step 08 for API coverage (ZAP also ships an `api-scan` script; check the current docs). Expect the WAF to block parts of the scan; allow-list the runner *temporarily* or scan the origin from inside the network, never turn the WAF off.

## 3. Security review checklist (copy per environment)
Identity and secrets
- [ ] No client secrets exist on any app registration; all federated credentials use `environment:` subjects
- [ ] Key Vault: RBAC, soft delete, purge protection, public access off; secret expiry set where possible
- [ ] Workload identity roles = planned list; no Owner/Contributor for the app
- [ ] Admin roles in Entra are PIM-eligible, MFA/passkey enforced, break-glass account tested
Network and edge
- [ ] Only Front Door is publicly reachable for the API; origin lock verified; WAF in Prevention
- [ ] SQL/Storage/Key Vault public network access disabled (`az resource list` + property check)
- [ ] TLS 1.2+ everywhere; custom domain cert valid > 30 days; HSTS present
Data
- [ ] TDE on, backups configured, PITR restore tried this quarter
- [ ] SQL auditing to Log Analytics, Defender for SQL on; app user has no db_owner
Pipeline
- [ ] Actions pinned to SHAs, Dependabot on, CodeQL/dependency review required on `main`
- [ ] Default token read-only; prod environment reviewers current; no repo secrets that could be eliminated
- [ ] Last image scan clean; base image age < 30 days
Monitoring
- [ ] Alerts fired in the last drill; action group recipients current; log retention >= 30 days
- [ ] Defender for Cloud secure score reviewed, High recommendations owned
- [ ] Policy compliance page reviewed
Application (Part 1)
- [ ] `smoke.sh` and ZAP baseline green; OWASP Top 10 / API Top 10 mapping (step 13) still true

## 4. Incident and rotation runbook (skeleton to fill with your names)
Contacts: on-call, security lead, Azure subscription owner, GitHub org owner. Severity guide: S1 = confirmed data exposure or attacker code execution; S2 = credential exposure without evidence of use; S3 = suspicious event.

**A. Leaked API key (Part 1 step 06)** – Detect: Key Vault/app logs show unusual key use, secret-scanning alert. Contain (15 min): revoke the key in the app's key store (or disable the vault secret version), confirm `curl` with the old key returns 401, add a WAF custom rule for the abusing IPs if needed. Investigate: KQL on `AppRequests`/console logs by key id, first-seen/last-seen, endpoints touched, data volume. Eradicate: issue new key, hand over securely, check for the key in git history (`git log -S`), CI logs, tickets. Recover/Review: timeline, root cause, add detection.

**B. Compromised GitHub -> Azure access** – Contain: disable the affected environment (delete the federated credential: `az ad app federated-credential delete --id <app> --federated-credential-id <id>`), cancel runs (`gh run cancel`), lock `main` (branch protection), rotate anything the identity could read. Investigate: `AzureActivity` for the identity's operations (`| where Caller == "<app id>"`), list role assignments and deployments changed, compare deployed image digests with ACR history (`az acr repository show-manifests`). Eradicate: audit workflows, actions and Dependabot PRs, re-create credentials with narrower subjects, review who has admin on the repo.

**C. Compromised container image / dependency** – Contain: deactivate the revision (`az containerapp revision deactivate`), redeploy last known-good digest via the pipeline, block the tag in ACR (`az acr repository update --write-enabled false`). Investigate with Trivy on the digest, `dotnet list package --vulnerable`, build logs. Eradicate: patch/pin, rebuild, rotate every secret the app identity could read (assume read of all Key Vault secrets it has access to).

**D. Suspected SQL data exposure** – Contain: remove the principal from the DB role or disable the login path (`ALTER ROLE ... DROP MEMBER`), tighten network rules. Investigate: audit logs (`AzureDiagnostics | where Category == "SQLSecurityAuditEvents"`), Defender alerts, failed/successful Entra sign-ins. Preserve evidence before changes (export logs, snapshot via PITR restore to a scratch DB). Notify: legal/DPO for personal data (breach notification deadlines apply – check your jurisdiction).

**Rotation table**
| Secret class | How | Verify | Cadence |
|--------------|-----|--------|---------|
| CI to Azure | nothing to rotate (OIDC); review federated credentials | list subjects | quarterly review |
| Key Vault secrets | new version -> reload/restart -> disable old | app healthy, old version unused in `AuditEvent` logs | 90 days or on suspicion |
| Data Protection keys | key ring auto-rotates (90 days); rotate the KEK key version in Key Vault | app decrypts old and new | yearly |
| API keys | issue second key, migrate clients, revoke old | 401 for old | per policy |
| Entra app credentials | avoid; if present, add second credential -> switch -> remove old | sign-in logs | <= 180 days |
| Break-glass | offline, tested | test sign-in | yearly |

Useful KQL
```kusto
AzureDiagnostics | where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent" | summarize count() by OperationName, CallerIPAddress, httpStatusCode_d
AzureActivity | where TimeGenerated > ago(24h) and OperationNameValue has_any ("roleAssignments/write","firewallRules/write","publicNetworkAccess")
AzureDiagnostics | where Category == "FrontDoorWebApplicationFirewallLog" | summarize count() by ruleName_s, action_s, clientIP_s
```
(Table and column names depend on whether diagnostics use the AzureDiagnostics or resource-specific mode; adapt.)

## 5. Rehearsal record
Write down for scenario A: time to detect, time to contain, time to full rotation, what was unclear. Fix the runbook, repeat next quarter.
