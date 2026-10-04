# Solution – P2-04 Host security

> Spoiler. Try the step yourself first: [`../part2-azure/P2-04-host-security.md`](../part2-azure/P2-04-host-security.md). Reference files: [`solutions/p2-04-host/`](../../solutions/p2-04-host/) (`main.bicep`, `shared.bicep`, `acr-pull.bicep`, `README.md`).
>
> **Not verified:** `main.bicep` was written without the Bicep CLI or an Azure subscription. It has not been compiled, linted, what-if'd or deployed; API versions, some property names and role-definition GUIDs may need correction. Treat it as a worked design to compile-and-fix, not as tested code.

## 1. How the template maps to the criteria
| Criterion | Where in `main.bicep` |
|-----------|----------------------|
| SQL Entra-only, TLS 1.2, no public access, TDE, audit, threat detection | `sql` (`administrators.azureADOnlyAuthentication`, `minimalTlsVersion`, `publicNetworkAccess: 'Disabled'`), `tde`, `sqlAudit` + `sqlMasterDiag`, `sqlThreat` |
| Passwordless connection | `ConnectionStrings__Default` env of `api`: `Authentication=Active Directory Managed Identity;User Id=<client id>` |
| Private networking | `vnet`, `privateLinks` loop (PE + private DNS + links) for SQL, Key Vault, Blob; `acaEnv` with VNet integration |
| HTTPS/TLS | `allowInsecure: false`, storage `minimumTlsVersion`, Front Door route `httpsRedirect` + `HttpsOnly`, managed cert with `TLS12` on the optional custom domain |
| Edge + WAF | `waf` (Default Rule Set 2.1 + bot rules, prevention, rate-limit rule), `afd*`, `wafAssoc` |
| Diagnostics + alerts | `*Diag` resources -> `law`; `ag` + `alerts` loop (5xx, WAF blocks, Key Vault failures, SQL failed logins) |
| Least privilege | four role assignments to one user-assigned identity + `AcrPull` via module; no `Owner`/`Contributor` for the workload |

## 2. Steps in order
```bash
az bicep build --file main.bicep && az bicep lint --file main.bicep
az group create -n rg-seclab-shared-<r> -l <region> --tags env=shared owner=<me> costCenter=<cc>
az deployment group create -g rg-seclab-shared-<r> -f shared.bicep
# images must exist before the app resources can pull them: push a first image (P2-02 build-push), then:
az deployment group what-if -g rg-seclab-dev-<r> -f main.bicep -p env=dev acrName=<acr> acrResourceGroup=rg-seclab-shared-<r> apiImage=<ref> externalApiImage=<ref> sqlAdminGroupObjectId=<oid> sqlAdminGroupName=<name> alertEmail=<mail>
az deployment group create ...same parameters...
```
Front Door id: read the `frontDoorId` output, store it as the GitHub variable `FRONT_DOOR_ID`, redeploy. The API must then reject requests whose `X-Azure-FDID` header differs (sketch: a small middleware comparing `FrontDoor:Id`; `/health` may be exempt for probes only if you also keep it non-sensitive). Stronger: Private Link origin / internal environment – check current Container Apps + Front Door Premium Private Link support before choosing.

## 3. Database user for the managed identity (T-SQL, cannot be Bicep)
Run as a member of the SQL admin group, connected with Entra auth, in database `SecLab`:
```sql
CREATE USER [id-seclab-dev] FROM EXTERNAL PROVIDER;
ALTER ROLE db_datareader ADD MEMBER [id-seclab-dev];
ALTER ROLE db_datawriter ADD MEMBER [id-seclab-dev];
-- no db_owner, no ddl: schema changes are done by a separate migration identity/step
```
Use the rights matrix from your Part 1 step 15 solution; if you introduced stored procedures use `GRANT EXECUTE` instead of reader/writer. Migrations (`dotnet ef database update` or an idempotent SQL script from `dotnet ef migrations script --idempotent`) run as a **different** principal (for example a second identity in the admin group used only by a deploy step). The server is private, so this step needs a runner inside the VNet (self-hosted runner, a Container Apps Job in the environment, or a temporary firewall/PE path) – decide and document; GitHub-hosted runners cannot reach it. This is the largest unresolved piece of the reference design.

## 4. Subscription-level pieces (not in the RG-scoped template)
```bash
# Defender for Cloud plans (costs money; choose consciously)
az security pricing create -n SqlServers --tier Standard
az security pricing create -n KeyVaults --tier Standard
az security pricing create -n Containers --tier Standard   # check plan names with: az security pricing list
# Policy: deny public network access etc. Use built-in definitions; find ids with az policy definition list --query "[?contains(displayName,'public network access')]"
az policy assignment create -n seclab-allowed-locations --scope /subscriptions/<id>/resourceGroups/rg-seclab-dev-<r> \
   --policy <allowed-locations-definition-id> --params '{"listOfAllowedLocations":{"value":["westeurope","northeurope"]}}'
```
Suggested assignments: allowed locations (deny), require tag `env` (deny), Azure SQL public network access disabled (audit -> deny), storage/Key Vault public access disabled (audit -> deny), "Microsoft cloud security benchmark" initiative (audit). Start in *audit*, review `az policy state summarize`, then move to *deny*.

## 5. Custom domain
Add the domain to Front Door (`apiCustomDomain` parameter), create the CNAME and the `_dnsauth` TXT record shown in the portal/`az afd custom-domain show`, wait for validation and the managed certificate, then repeat the deployment. Set HSTS at the app (already from step 01); do not add `preload` until every subdomain is HTTPS.

## 6. Forwarded headers (behind Front Door)
The app sees HTTP from the ingress and the edge IP as client. Configure `ForwardedHeadersOptions` (`ForwardedHeaders.XForwardedFor | XForwardedProto | XForwardedHost`) and trust only the known proxy ranges (or the Container Apps network) before `UseHttpsRedirection`, HSTS and the rate limiter (partition by the real client IP from `X-Forwarded-For`, and rely on the WAF rate rule as a second layer).

## 7. Verification
```bash
az bicep build --file main.bicep
az bicep lint --file main.bicep
# PSRule (needs PowerShell):
pwsh -c "Install-Module PSRule.Rules.Azure -Scope CurrentUser; Assert-PSRule -Module PSRule.Rules.Azure -InputPath ./main.bicep -Format File"
```
Or run PSRule in the pipeline (`microsoft/ps-rule` action, check the current version). Post-deployment checks are listed in the step file. Alert drills: (5xx) call an endpoint that throws in dev; (WAF) `curl "https://<edge>/?q=<script>alert(1)</script>"` x 60; (Key Vault) request a missing secret with the CLI as a user without access; (SQL) attempt a login with a wrong principal using `sqlcmd -G`.

Restore drill: `az sql db restore --dest-name SecLab-restore --name SecLab -g $RG --server <sql> --time <UTC timestamp within retention>` then delete `SecLab-restore`. Suggested RPO/RTO for the course: RPO <= 1 h (PITR granularity is minutes; geo-backup asynchronous), RTO <= 4 h manual (redeploy from Bicep + restore); write your own numbers.

## Deliberate simplifications
No NSGs on subnets, no Azure Firewall/egress control, no customer-managed keys, one region, Front Door Premium in every environment (use Standard without WAF managed rules in dev if cost matters – then your dev tests no longer represent prod), auto-pause SQL in non-prod only.
