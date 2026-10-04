# solutions/p2-04-host

Reference Infrastructure as Code for [`docs/part2-azure/P2-04-host-security.md`](../../docs/part2-azure/P2-04-host-security.md). Walkthrough: [`docs/solutions/p2-04-host-security.md`](../../docs/solutions/p2-04-host-security.md).

| File | Purpose |
|------|---------|
| `shared.bicep` | Container registry (admin user off, no anonymous pull) in the shared resource group. Deploy once. |
| `main.bicep` | One environment: monitoring, identity, network, Key Vault, Storage, Azure SQL (Entra-only), Container Apps, Static Web App, Front Door + WAF, diagnostics, alerts. |
| `acr-pull.bicep` | Module used by `main.bicep` for `AcrPull` across resource groups. |

Copy `main.bicep` and `acr-pull.bicep` to `infra/` (the workflow in `solutions/p2-02-pipeline/` expects `infra/main.bicep`).

```bash
az bicep build --file main.bicep && az bicep lint --file main.bicep
az deployment group create -g rg-seclab-shared-<r> -f shared.bicep
az deployment group what-if -g rg-seclab-dev-<r> -f main.bicep -p env=dev acrName=<acr> acrResourceGroup=rg-seclab-shared-<r> \
   apiImage=<acr>.azurecr.io/seclab-api@sha256:<digest> externalApiImage=<acr>.azurecr.io/seclab-externalapi@sha256:<digest> \
   sqlAdminGroupObjectId=<oid> sqlAdminGroupName=<name> alertEmail=<mail>
```

## Not verified
Written without a subscription, the Bicep CLI or `az`. Not compiled, linted, what-if'd or deployed. Expect to fix: API versions and property names (especially Container Apps `appLogsConfiguration` with `azure-monitor`, Front Door WAF rule-set versions, `scheduledQueryRules`, SQL `restrictOutboundNetworkAccess`), the role-definition GUIDs, and the `/health` endpoint the probes assume. Known simplifications: no NSGs, origin lock by `X-Azure-FDID` header (app-side check) instead of Private Link, no subscription-level Defender/Policy (see the walkthrough), no `main.bicepparam`. With SQL/Key Vault/Storage closed to the public internet, `az deployment` still works (control plane) but creating DB users and running migrations needs a runner inside the VNet (see the walkthrough).
