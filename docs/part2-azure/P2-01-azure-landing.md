# P2-01 – Azure landing zone

> Prerequisites: Part 1 done, Azure subscription, `az login` works. Time: ~45 min. Nothing is deployed in this step except a budget and (optionally) resource groups.

## Goal
Decide and document where every piece of SecLab runs, and prepare the empty, well-named containers for it.

Acceptance criteria:

1. A written **target architecture** (a diagram plus a table) with: the React frontend, `SecLab.Api`, `SecLab.ExternalApi`, the database, secrets, container images, logs/metrics and the edge (TLS, WAF). Each component names its Azure service and its **identity** (who talks to whom, with what).
2. Three environments – **dev, test, prod** – that cannot reach each other's data. Decide the isolation boundary (subscription vs resource group) and justify it in two sentences.
3. A **naming and tagging convention** that encodes workload, environment and region, respects Azure length/character rules, and yields globally unique names where required (ACR, Key Vault, Storage, SQL server).
4. Resource groups created per environment plus one for shared resources (registry, monitoring if shared), tagged with `env`, `owner`, `costCenter`.
5. A **budget alert** on the subscription (or shared resource group).
6. A one-page **cloud threat model**: at least six threats, each with the control that answers it and the P2 step where you build it.

Out of scope: building the resources (P2-04), the pipeline (P2-02).

## Threat / why
A "lift and shift" that copies `docker-compose.yml` to a VM reproduces every Part 1 weakness in a bigger blast radius: the weak `sa` password, secrets in app settings, a database reachable from the internet. Typical real incidents:

- A SQL server with "Allow Azure services" and a public endpoint gets brute-forced within hours of creation (check your own server's sign-in log in P2-05).
- One subscription, one shared Key Vault: a compromised `dev` deployment reads `prod` secrets.
- A storage account made public "temporarily" leaks uploaded avatars (W6 from step 00 resurfacing).
- No budget alert: cryptominers in a hijacked Container App bill for days.

Demonstrate the exposure surface of any resource you create with `az resource list -g <rg> -o table` and, per resource, `az resource show --ids <id> --query properties.publicNetworkAccess`. In this step you are deciding what those answers should be.

## Concepts
- **Shared responsibility.** Microsoft secures the datacenter, hypervisor and (for PaaS) the runtime and patching of the platform. You own identities, data, configuration, network exposure, your container images and your code. PaaS (Container Apps, SQL, Static Web Apps) moves the line up compared to VMs; it never removes your side.
- **Landing zone.** The subscription/resource-group structure, policies, networking and identity you set up *before* workloads. Read the Cloud Adoption Framework "landing zone" and "naming and tagging" pages.
- **Environment isolation.** Stronger boundary: one subscription per environment (separate RBAC, budgets, policy, quotas). Cheaper compromise: one resource group per environment with separate identities, vaults and databases. Both need *separate managed identities and Key Vaults per environment*.
- **Services to choose from:**
  - Compute: **Azure Container Apps** (managed environment, revisions, ingress, managed identity, secrets referencing Key Vault). Alternatives: App Service, AKS – read why they were not chosen.
  - Frontend: **Static Web Apps**, or **Blob static website + Front Door**. Note where the security headers/CSP (Part 1 step 10) are set in each.
  - Data: **Azure SQL Database**. Secrets: **Key Vault**. Images: **Azure Container Registry**. Telemetry: **Log Analytics workspace** + **Application Insights** (workspace-based).
  - Edge: **Front Door + WAF** or **API Management** (P2-04).
- **Naming.** Azure resource abbreviations and rules (CAF list), e.g. Key Vault max 24 chars, storage account lowercase alphanumerics only, ACR alphanumerics only. `uniqueString(...)` in Bicep helps with global uniqueness.
- **Cloud threat model** (STRIDE per data flow is a good start): stolen CI credentials, over-privileged identities, public endpoints on data services, secret sprawl, supply-chain (base images, packages, actions), missing logging, misconfiguration drift, cost abuse.

Sketch of the shape (yours may differ):

```
 Internet
    |
 [Front Door + WAF]  -- TLS, custom domain, rate limit, managed rules
    |             \
    |              \--> [Static Web App / Blob]  (React build)
    v
 +------------------ VNet (env) -------------------+
 |  [Container Apps environment]                   |
 |    SecLab.Api  --(internal ingress)--> SecLab.ExternalApi
 |       | managed identity                        |
 +-------|-----------------------------------------+
         |            |              |
         v            v              v
   [Azure SQL]   [Key Vault]   [Blob: DataProtection keys]
   (private ep)  (RBAC, purge  
                  protection)
   [ACR] --pull (AcrPull)--> Container Apps
   [Log Analytics + App Insights] <-- diagnostics from everything
   GitHub Actions --OIDC--> Entra --> scoped RBAC on the RGs
```

## Your turn
Tasks:
1. Write the architecture table (component, service, identity, inbound, outbound, data classification) in a file of your own (for example `docs/part2-azure/my-architecture.md`, not committed if it contains ids).
2. Choose the environment boundary and the region(s); note the data-residency reason for the region.
3. Define the naming pattern and tags; apply them to resource groups for `dev`, `test`, `prod` and `shared`.
4. Create the budget alert.
5. Write the threat table (threat, asset, control, step).
6. Run the checks below.

<details><summary>Hint 1 – where to look</summary>

Cloud Adoption Framework: "Resource organization", "Define your naming convention", "Define your tagging strategy". Azure Architecture Center: "Container Apps" reference architectures. Cost Management → Budgets in the portal.
</details>

<details><summary>Hint 2 – which features</summary>

`az group create --tags ...`, `az consumption budget` / `az costmanagement`-style commands or the portal for budgets (check the current CLI surface), `az account list-locations`, Azure resource abbreviations table, `az policy definition` for a later "require tag" policy.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

Four resource groups (`shared`, `dev`, `test`, `prod`) named `rg-seclab-<env>-<region-short>`; prod isolated from non-prod at least by separate identities/vaults (subscription if you have two); every resource inherits tags; a monthly budget with 50/80/100 % notifications to an email you read; a threat table with columns matching your architecture table.
</details>

## Verify
```bash
az group list --query "[?starts_with(name,'rg-seclab-')].{n:name,l:location,t:tags}" -o table
# every group has env/owner/costCenter tags:
az group list --query "[?starts_with(name,'rg-seclab-') && (tags.env==null || tags.owner==null || tags.costCenter==null)].name" -o tsv   # must print nothing
```
Budget: the portal (Cost Management → Budgets) shows the budget with notification thresholds; or check with the current `az` budget command.

Checklist:
- [ ] Architecture table and diagram cover every component of the app, and each arrow names an identity (no "connection string" arrows)
- [ ] No two environments share a database, vault or managed identity
- [ ] Names follow the pattern and satisfy length/character rules
- [ ] Resource groups exist and carry the three tags
- [ ] Budget alert exists and goes to a mailbox someone reads
- [ ] Threat table has >= 6 rows, each pointing to a later P2 step or an accepted risk

## Pitfalls
- Key Vault, Storage, ACR and SQL server names are **global** DNS names; a taken name fails the deployment late.
- Choosing the region by price alone: check that Container Apps, Front Door features and Defender plans you need exist there.
- "We'll add environments later" – retrofitting isolation means moving data. Decide now.
- Putting environment names only in tags: tags are not a security boundary.
- Forgetting deletion: budgets alert, they do not stop spending.

## Further reading
- Cloud Adoption Framework: landing zones, naming & tagging – https://learn.microsoft.com/azure/cloud-adoption-framework/
- Shared responsibility in the cloud – https://learn.microsoft.com/azure/security/fundamentals/shared-responsibility
- Azure Well-Architected Framework: Security pillar – https://learn.microsoft.com/azure/well-architected/security/
- Microsoft cloud security benchmark – https://learn.microsoft.com/security/benchmark/azure/
- OWASP Cloud-Native Application Security Top 10; OWASP Top 10 CI/CD Security Risks

Stuck or done? Compare with the solution: [`docs/solutions/p2-01-azure-landing.md`](../solutions/p2-01-azure-landing.md).
