# Solution – P2-01 Azure landing zone

> Spoiler. Try the step yourself first: [`../part2-azure/P2-01-azure-landing.md`](../part2-azure/P2-01-azure-landing.md). Verification status: **nothing here was run against a real subscription.** Commands are standard `az` usage; check flag names with `az <cmd> --help` (the CLI surface for budgets in particular changes).

## 1. Architecture (decisions)
| Component | Azure service | Identity / auth | Inbound | Outbound |
|-----------|---------------|-----------------|---------|----------|
| React frontend | Static Web Apps (Standard) | n/a (static); deployment token fetched at deploy time | internet, HTTPS | API via Front Door |
| SecLab.Api | Container Apps (external ingress, only via Front Door) | user-assigned managed identity `id-seclab-<env>` | Front Door | SQL, Key Vault, Blob, ExternalApi, App Insights |
| SecLab.ExternalApi | Container Apps (internal ingress) | same identity, own API key check (Part 1 step 06) | Api only | Key Vault |
| Database | Azure SQL Database | Entra-only; managed identity as contained user | private endpoint | none |
| Secrets/keys | Key Vault (RBAC, purge protection) | RBAC roles for the identity | private endpoint | none |
| Data Protection ring | Blob (`allowSharedKeyAccess=false`) + Key Vault key | RBAC | private endpoint | none |
| Images | ACR (shared RG) | `AcrPush` for CI build identity, `AcrPull` for apps | internet (CI) / MI pull | none |
| Logs/metrics | Log Analytics + workspace-based Application Insights | diagnostic settings, OTel exporter with MI | - | - |
| Edge | Front Door Premium + WAF | - | internet | API origin |
| CI/CD | GitHub Actions | OIDC federated credential per environment | - | ARM, ACR |

Diagram: see the ASCII sketch in the step file; the arrows in the table are the ones to keep.

## 2. Environment boundary
**Recommended:** two subscriptions – `seclab-nonprod` (dev, test, shared registry) and `seclab-prod`. If you only have one: resource group per environment, separate identity, vault and database per environment, and the CI identity for `dev` has **no** role on the `prod` group. Reason: RBAC, policy and budget scope follow the subscription; a compromised non-prod pipeline then cannot even see prod. (The registry sits in non-prod and prod pulls by digest – grant prod's identity `AcrPull` only, or replicate to a prod registry if you need the stricter split.)

## 3. Naming and tags
Pattern (CAF abbreviations): `<abbr>-seclab-<env>[-<region>]`, e.g. `rg-seclab-dev-weu`, `kv-seclab-dev-<6 hash>`. Length/charset exceptions are handled in the Bicep: Key Vault <= 24 chars, storage/ACR alphanumeric only (`stseclabdev<hash>`, `acrseclab<hash>`), with `uniqueString(resourceGroup().id)` for global uniqueness. Tags: `env`, `owner`, `costCenter`, `workload=seclab`.

## 4. Resource groups
```bash
LOC=westeurope; R=weu
for e in shared dev test prod; do
  az group create -n rg-seclab-$e-$R -l $LOC \
    --tags env=$e owner=<you@example.com> costCenter=<cc> workload=seclab
done
```

## 5. Budget
Portal: *Cost Management + Billing -> Budgets -> Add*; scope = subscription (or the resource groups), monthly, alerts at 50/80/100 % actual and 100 % forecast, recipient = a mailbox that is read. The CLI/ARM route (`Microsoft.Consumption/budgets`) works too; check the current `az consumption budget` / `az costmanagement` support before scripting.

## 6. Cloud threat model (extract)
| # | Threat | Asset | Control | Step |
|---|--------|-------|---------|------|
| 1 | Stolen CI credential | subscription | OIDC federation, per-env identity, scoped RBAC, environment reviewers | P2-02 |
| 2 | Malicious PR / action / dependency | pipeline, supply chain | SHA pinning, dependency review, CodeQL, image scan, no secrets on fork PRs | P2-02 |
| 3 | Secret in config or image | app secrets | no secrets by design, Key Vault, MI, secret scanning | P2-03 |
| 4 | Over-privileged workload identity | data, vault | least-privilege roles, separate runtime vs migration identity | P2-03/04 |
| 5 | Public data plane (SQL, Storage, KV) | data | Entra-only, private endpoints, Policy deny public access | P2-04 |
| 6 | Direct hits on the API (bots, injection, floods) | availability, integrity | Front Door WAF, rate limit, origin lock, app-level controls of Part 1 | P2-04 |
| 7 | Undetected abuse | everything | diagnostics -> Log Analytics, alerts, Defender | P2-04/05 |
| 8 | Config drift / click-ops | all | Bicep + what-if, Policy, PSRule | P2-04 |
| 9 | Vault deletion / ransom | secrets | soft delete + purge protection, backups | P2-03/04 |
| 10 | Cost abuse | budget | budget alerts, max replicas, WAF rate limit | P2-01/04 |

## Not verified
Region/service availability, current CLI flags for budgets, and pricing. Nothing was created in Azure.
