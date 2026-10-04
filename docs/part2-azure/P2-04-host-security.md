# P2-04 – Host security

> Prerequisites: P2-01–P2-03. Time: ~2.5 h. This is where money is spent: deploy `dev` only, delete it afterwards.

## Goal
Everything from P2-01's architecture exists as **reviewed code** (Bicep), is reachable only the way you intend, and tells you when something is wrong.

Acceptance criteria:

1. **Infrastructure as Code**: one Bicep template (modules optional) deploys the environment: Log Analytics, Application Insights, ACR, Key Vault, managed identity + role assignments, Container Apps environment with API and ExternalApi, Azure SQL, Storage for Data Protection, frontend hosting, edge (Front Door + WAF). `az bicep build` and the linter are clean; `what-if` is reviewed before every deployment (in the pipeline from P2-02).
2. **Azure SQL**: **Microsoft Entra-only authentication** (SQL authentication disabled), an Entra group as admin, the app connects **as its managed identity** with a contained database user holding only the rights it needs (ties to Part 1 step 15: no `sa`, no dbo), TDE on, **auditing** to Log Analytics, **Defender for SQL** on, TLS 1.2 minimum, no "Allow Azure services" blanket rule; public access disabled with a **private endpoint**, or – if you consciously accept public access in dev – a narrow firewall rule documented as such.
3. **Transport**: HTTPS only on all ingress (HTTP disabled or redirected), **TLS 1.2 minimum** on every service that has the setting, a **custom domain with a managed certificate** in front of the API and frontend; HSTS from Part 1 step 01 still emitted (behind the proxy, forwarded headers handled correctly).
4. **Edge**: Front Door with a **WAF** (managed rule set in prevention mode plus a rate-limit rule) or API Management, as the Part 1 step 14 gateway; the API is not directly usable from the internet (origin restricted, e.g. to the Front Door id or private link), CORS lists only the real frontend origin.
5. **Networking**: Container Apps environment integrated in a VNet; data services reachable through private endpoints and private DNS; no public IP on anything that does not need one.
6. **Monitoring**: diagnostic settings from Key Vault, SQL, Container Apps environment, Front Door/WAF to Log Analytics; OpenTelemetry (Part 1 step 12) exports to Application Insights; at least **four alert rules** (e.g. 5xx spike, WAF blocks spike, Key Vault access failures, SQL failed logins / Defender alert) that notify an action group.
7. **Governance**: Microsoft Defender for Cloud plans chosen and enabled; at least three **Azure Policy** assignments (for example: allowed locations, require tags, deny public network access on SQL/Storage/Key Vault, HTTPS only) in audit or deny mode.
8. **Resilience**: SQL backup retention and geo-redundancy decision, Key Vault/Storage redundancy, a written RPO/RTO and a restore you actually tried (point-in-time restore of the database).

## Threat / why
- Default Azure SQL: public endpoint + "Allow Azure services" = reachable from *any* Azure tenant; SQL logins are brute-forceable.
- Container App with external ingress and no edge: every request (scanners, SQLi against W7, floods) hits your code; the Part 1 rate limiter is per replica and sees the proxy's IP unless forwarded headers are right.
- Portal click-ops: nobody knows what changed, environments drift, and a "temporary" public storage account lives for a year.
- No logs: after an incident you cannot say what was accessed. Logs only in the container's stdout disappear with the replica.
- An engineer with `Contributor` disables TDE or auditing: nothing notices.

Check your own exposure: `az sql server show -g <rg> -n <server> --query "{pub:publicNetworkAccess,tls:minimalTlsVersion,aad:administrators.azureADOnlyAuthentication}"`, and after deployment `nmap -Pn -p 1433 <server>.database.windows.net` (from outside; expect filtered/closed when private).

## Concepts
- **Bicep.** Resources, `param`/`var`/`output`, `existing`, modules, `@secure()` parameters (and why you should have none), `uniqueString`, scopes (resource group vs subscription), decorators, API versions per resource type. Tools: `az bicep build`, `az bicep lint`, `az deployment group validate`, **`what-if`**, PSRule for Azure (rules mapped to the Well-Architected pillars), Bicep linter config (`bicepconfig.json`).
- **Azure SQL identity.** `Microsoft.Sql/servers` `administrators` with `azureADOnlyAuthentication`; creating a database user for a managed identity is a **T-SQL** step (`CREATE USER ... FROM EXTERNAL PROVIDER`, then `ALTER ROLE`), not an ARM resource – think about who runs it (a deployment script or a pipeline step with the admin group's identity) and how the migration identity differs from the runtime identity. Connection strings then use Microsoft Entra authentication (e.g. `Authentication=Active Directory Managed Identity`).
- **SQL protections:** transparent data encryption (default on; customer-managed key optional), auditing, Defender for SQL (vulnerability assessment, threat detection), ledger and Always Encrypted as further reading, dynamic data masking (not a security boundary).
- **Network:** VNet + delegated subnet for the Container Apps environment (workload profiles), private endpoints + `privatelink.*` private DNS zones, NSGs, service endpoints vs private link. Ingress: external vs internal environment.
- **Front Door:** Standard vs Premium (managed WAF rule sets and Private Link origins need Premium – check current), endpoints, origin groups, routes, custom domains with managed certificates, WAF policies (Default Rule Set, bot protection, custom rate-limit rules, detection vs prevention mode), the `X-Azure-FDID` header for origin validation, health probes. **API Management** as the alternative: policies for JWT validation, rate limiting, IP filtering.
- **TLS:** minimum TLS version settings exist per service (`minimumTlsVersion`, Front Door custom-domain TLS policy, `supportsHttpsTrafficOnly` on storage). Container Apps ingress: `allowInsecure: false`.
- **Monitoring:** diagnostic settings (categories differ per resource type), workspace-based Application Insights, KQL, scheduled query rules and metric alerts, action groups, Defender for Cloud secure score and recommendations, Activity Log alerts for policy/role changes.
- **Azure Policy:** definition, initiative, assignment, effects (`Audit`, `Deny`, `DeployIfNotExists`, `Modify`), built-in "Microsoft cloud security benchmark" initiative, exemptions. Policy also validates your Bicep at deploy time.
- **DR:** SQL automated backups and PITR, long-term retention, geo-replication/failover groups, zone redundancy, and the fact that Container Apps are stateless *because* state lives in SQL/Blob.

## Your turn
Tasks:
1. Write the Bicep (start with monitoring, registry, vault, identity; grow it resource by resource, running `az bicep build` and lint each time).
2. Configure SQL as described; script (and document who runs) the database-user creation and the migrations from Part 1 step 15.
3. Add the network layer and edge; lock the origin.
4. Add diagnostic settings and alerts; trigger each alert once deliberately.
5. Assign Azure Policy and enable Defender plans; review the recommendations list and fix or consciously accept each High.
6. Run the pipeline's `what-if` and a `dev` deployment; do the restore drill.
7. Run PSRule for Azure and the checks below.

<details><summary>Hint 1 – where to look</summary>

Azure Quickstart Templates and Azure Verified Modules (`br/public:avm/...`) for shape; the resource reference for each `Microsoft.*` type (properties named `publicNetworkAccess`, `minimalTlsVersion`, `enableRbacAuthorization`, `azureADOnlyAuthentication`). Your Part 1 `docker-compose.yml` and `appsettings.json` list what the app needs at runtime; `docs/15-*` lists the SQL rights it needs.
</details>

<details><summary>Hint 2 – which resources</summary>

`Microsoft.OperationalInsights/workspaces`, `Microsoft.Insights/components`, `Microsoft.ContainerRegistry/registries`, `Microsoft.KeyVault/vaults`, `Microsoft.ManagedIdentity/userAssignedIdentities`, `Microsoft.Authorization/roleAssignments`, `Microsoft.App/managedEnvironments` + `containerApps`, `Microsoft.Sql/servers` (+ `administrators`, `auditingSettings`, `securityAlertPolicies`, `databases`), `Microsoft.Storage/storageAccounts`, `Microsoft.Web/staticSites`, `Microsoft.Cdn/profiles` (+ afdEndpoints, originGroups, routes, securityPolicies) and `Microsoft.Network/FrontDoorWebApplicationFirewallPolicies`, `Microsoft.Insights/diagnosticSettings`, `Microsoft.Insights/scheduledQueryRules`, `Microsoft.Network/privateEndpoints`. Check the current API version of each.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

One template scoped to a resource group with an `env` parameter driving SKU/replica/retention differences and only non-secret parameters (image digests, admin group object id, domain names); role assignments named with `guid(scope, principal, role)`; every data resource with public access disabled and a diagnostic setting pointing to the workspace; the WAF policy in prevention mode referenced by a security policy on the Front Door endpoint; outputs limited to host names. Keep what you cannot express in ARM (SQL user creation) in a clearly labelled post-deployment step.
</details>

## Verify
```bash
az bicep build --file main.bicep                 # compiles, no errors
az bicep lint  --file main.bicep                 # no warnings you have not consciously suppressed
az deployment group validate -g rg-seclab-dev-<r> -f main.bicep -p @dev.bicepparam
az deployment group what-if  -g rg-seclab-dev-<r> -f main.bicep -p @dev.bicepparam   # only expected changes
# PSRule for Azure (PowerShell): Install-Module PSRule.Rules.Azure; Assert-PSRule -Module PSRule.Rules.Azure -InputPath main.bicep   # or the GitHub action
```
After deployment:
```bash
az sql server show -g <rg> -n <sql> --query "{pub:publicNetworkAccess,tls:minimalTlsVersion,aadOnly:administrators.azureADOnlyAuthentication}"
az sql db tde show ...   # or az sql db show ... ; TDE state Enabled
az monitor diagnostic-settings list --resource <resource-id> --query "[].name"
curl -sI http://<host>/         | head -1        # redirect or refused, never 200
curl -sI https://<host>/        | grep -i strict-transport-security
curl --tlsv1.1 --tls-max 1.1 -s -o /dev/null -w '%{http_code}\n' https://<host>/   # handshake failure
curl -s -o /dev/null -w '%{http_code}\n' "https://<host>/api/v1/blogs/search?q=%27%20OR%201%3D1--"   # blocked by WAF (403) or handled safely by the app
curl -s -o /dev/null -w '%{http_code}\n' https://<container-app-default-fqdn>/api/v1/health    # not reachable / rejected: origin locked
az policy state summarize --query "results.nonCompliantResources"
```
Checklist:
- [ ] `az bicep build`/`lint` clean; what-if is reviewed and attached to the PR
- [ ] PSRule reports no failed rule you have not documented an exemption for
- [ ] SQL: Entra-only, TLS 1.2, TDE, auditing, Defender on; app connects without any password
- [ ] Origin cannot be reached bypassing Front Door
- [ ] WAF in prevention mode; each of the four alerts fired once in a drill
- [ ] Policies assigned, compliance page reviewed; Defender High recommendations triaged
- [ ] PITR restore performed into a scratch database and deleted again
- [ ] RPO/RTO written down

## Pitfalls
- Setting `azureADOnlyAuthentication` before an Entra admin exists fails; ordering and `dependsOn` matter (mostly implicit in Bicep).
- Creating the DB user for a managed identity needs a session authenticated **as Entra**, not as SQL auth; from CI use the pipeline's federated identity as (or member of) the admin group.
- Private endpoints need private DNS zones **linked to the VNet**, otherwise the name still resolves to the public IP.
- Container Apps VNet integration is chosen at environment creation and is not freely changeable – plan the subnet size first.
- WAF in *detection* mode blocks nothing. Start there to find false positives, then switch – and write the date you will switch.
- Locking the origin by header alone is only as strong as the secrecy of the Front Door id in an environment where it is not secret; prefer Private Link/internal ingress where available.
- Forwarded headers: behind Front Door the client IP and scheme are in `X-Forwarded-*`; configure `ForwardedHeadersOptions` with the known proxies or rate limiting and HSTS/redirects misbehave (redirect loops).
- `what-if` is approximate (noise, unsupported resource types); it is a review aid, not a proof.
- Auditing to Log Analytics costs per GB; set retention and daily cap consciously.
- Do not use `Microsoft.Authorization/roleAssignments` with `Owner` "to make it work".

## Further reading
- Bicep documentation, linter, `what-if` – https://learn.microsoft.com/azure/azure-resource-manager/bicep/
- PSRule for Azure – https://azure.github.io/PSRule.Rules.Azure/
- Azure SQL security best practices, Entra-only authentication, managed identities – https://learn.microsoft.com/azure/azure-sql/database/security-best-practice
- Container Apps networking and ingress – https://learn.microsoft.com/azure/container-apps/
- Azure Front Door WAF – https://learn.microsoft.com/azure/web-application-firewall/afds/afds-overview
- Defender for Cloud; Azure Policy; Azure Monitor alerts – https://learn.microsoft.com/azure/
- OWASP Cloud-Native Application Security Top 10; CIS Microsoft Azure Foundations Benchmark

Stuck or done? Compare with the solution: [`docs/solutions/p2-04-host-security.md`](../solutions/p2-04-host-security.md) and `solutions/p2-04-host/`.
