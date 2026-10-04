# P2-03 – Secrets and identity

> Prerequisites: P2-01, P2-02 (identities for CI exist), Part 1 steps 03 (OIDC) and 06 (API keys). Time: ~1.5 h.

## Goal
The running application holds **no secret that you could paste into a chat**: it authenticates to Azure services with a managed identity, reads the few remaining secrets from Key Vault, and users sign in through Microsoft Entra ID.

Acceptance criteria:

1. A **Key Vault per environment** with the **Azure RBAC** permission model (no access policies), **soft delete** and **purge protection** on, public network access decision documented (closed or restricted).
2. API and ExternalApi run under a **user-assigned managed identity** per environment (or system-assigned per app – justify) with only the roles they need: `Key Vault Secrets User` on the vault, `AcrPull` on the registry, a Storage data role for the Data Protection blob, and a database user with least privilege (P2-04).
3. The application code obtains credentials via **`DefaultAzureCredential`** (developer login locally, managed identity in Azure) – no client secret, no connection string with a password anywhere in app settings, IaC parameters, GitHub or the image.
4. Configuration secrets (Part 1 step 06 API-key pepper / ExternalApi keys, any OIDC client secret) are loaded from Key Vault at startup or via Container Apps **Key Vault references**; the app config contains only the vault *URI*.
5. **Microsoft Entra ID replaces Keycloak** as identity provider: app registrations for the API (with scopes and app roles) and the SPA (authorization code + PKCE, no implicit flow); the API validates issuer, audience, signature, and maps Entra roles/claims onto the Part 1 authorization policies. Tests from Part 1 step 03/05 still pass with a fake IdP locally. **Since step 17 the browser holds no tokens:** the gateway (BFF) is the OIDC client, so the second registration is a *web* application registration for the gateway (redirect URI `/bff/callback`, secret or certificate from Key Vault, ideally a federated credential) rather than a SPA registration; the API registration and its audience stay as they are.
6. **ASP.NET Core Data Protection** keys are persisted outside the container (Blob Storage) and encrypted with a Key Vault key, so scaling to several replicas and restarts do not break cookies/antiforgery tokens.
7. A documented **rotation procedure** for each remaining secret, tested once.

## Threat / why
- A password or key in an environment variable/app setting is readable by everyone with `Reader`-plus on the resource, shows up in deployment history, `az containerapp show`, crash dumps, and in the Bicep parameters file you committed.
- The `/api/debug/crash` weakness (W11) printed a connection string; even fixed, a secret that *exists* can leak. A secret that does not exist cannot.
- A shared secret across environments means a `dev` leak is a `prod` breach.
- Without purge protection, an attacker (or a mistaken script) with vault delete rights removes secrets **permanently**; with soft delete alone they can still purge.
- Without a shared Data Protection key ring, each replica issues tokens the others reject – teams "fix" it by pinning to one replica or by weakening validation.
- Keycloak in a container you operate is one more patching, backup and admin-console exposure surface.

Look at what your dev deployment leaks: `az containerapp show -n <app> -g <rg> --query "properties.template.containers[0].env"` – any value there that is a credential is a finding.

## Concepts
- **Managed identity.** An Entra service principal whose credentials Azure rotates and never shows you. *System-assigned* lives and dies with one resource; *user-assigned* is a separate resource you can pre-authorize (avoids the chicken-and-egg where the app needs access before it exists) and share deliberately. Tokens come from the local identity endpoint; SDKs hide that.
- **`DefaultAzureCredential`** tries a chain (environment, workload identity, managed identity, Visual Studio/CLI login…). Convenient for dev; in production consider `ManagedIdentityCredential` explicitly (faster failure, no surprising fallbacks). With a user-assigned identity you must pass its client id.
- **Key Vault authorization.** Legacy access policies vs **Azure RBAC**. Roles to look up: `Key Vault Secrets User` (read secrets), `Key Vault Secrets Officer`, `Key Vault Crypto Service Encryption User`/`Crypto User`, `Key Vault Administrator`. Data-plane roles are separate from `Contributor`, which does not grant secret access under RBAC.
- **Soft delete / purge protection.** Retention period (7–90 days), no purge until it elapses; purge protection cannot be turned off afterwards.
- **Getting secrets into the app:** (a) configuration provider `Azure.Extensions.AspNetCore.Configuration.Secrets` with `AddAzureKeyVault`; secret name `--` maps to `:`; reload interval. (b) Container Apps secrets that reference Key Vault via the identity, surfaced as env vars – simplest but values become environment variables, and rotation needs a new revision. Compare them.
- **Entra ID as OIDC provider.** v2.0 endpoint and issuer format, tenant id, `aud` (API app id URI or client id), scopes (`access_as_user`), **app roles** (`roles` claim), `groups` claim limits, `Microsoft.Identity.Web` vs plain `JwtBearer` with the authority. Keep Part 1's authorization *policies*; only the claim mapping changes. Conditional Access / MFA and passkeys replace Part 1 step 04 at the IdP.
- **Data Protection** (`AddDataProtection`): `PersistKeysToAzureBlobStorage`, `ProtectKeysWithAzureKeyVault`, `SetApplicationName`; packages `Azure.Extensions.AspNetCore.DataProtection.Blobs` and `.Keys`. Keys are encrypted at rest with the KEK; the blob store is private with the identity as `Storage Blob Data Contributor`.
- **Rotation.** Prefer secrets that can be dual-valid (two API keys, key-id with overlap). Key Vault versions each secret; Event Grid can notify on `NearExpiry`. Entra credentials can have expiry; better: no credentials.
- **Secret scanning.** GitHub secret scanning + push protection catch committed secrets; treat any hit as compromised, not as "remove the line".

## Your turn
Tasks:
1. Create (by hand first, IaC in P2-04) the vault with the required settings and the user-assigned identity; grant the roles.
2. Change the API's startup so all Azure access uses the credential chain and secrets come from Key Vault; keep local development working (`az login`, or user-secrets / a local file for Keycloak-free tests).
3. Create the Entra app registrations, define scopes/roles, switch the API's JWT validation and the SPA's login to Entra; keep Keycloak available for local runs behind configuration.
4. Configure Data Protection persistence and key protection.
5. Move every remaining secret into the vault; delete it from settings, Bicep parameters and GitHub secrets.
6. Write and rehearse the rotation runbook for one secret.

<details><summary>Hint 1 – where to look</summary>

`backend/src/SecLab.Api/Program.cs` (configuration builder, authentication, Data Protection), `appsettings*.json`, the Part 1 step 03 auth setup, `frontend` OIDC client config (authority, client id, scopes), the Container Apps identity and secrets settings. Microsoft Learn: "Managed identities in Azure Container Apps", "Azure Key Vault RBAC guide", "Register an application with the Microsoft identity platform".
</details>

<details><summary>Hint 2 – which features</summary>

`Azure.Identity` (`DefaultAzureCredential`, `ManagedIdentityCredential`), `Azure.Extensions.AspNetCore.Configuration.Secrets` (`AddAzureKeyVault`, `AzureKeyVaultConfigurationOptions.ReloadInterval`), `Microsoft.Identity.Web` or `AddJwtBearer` with `Authority`/`TokenValidationParameters`, app roles in the app manifest, `az keyvault create --enable-rbac-authorization --enable-purge-protection`, `az role assignment create`, `az containerapp identity assign`, Container Apps secret `keyVaultUrl` + `identity`.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

One extra configuration source guarded by "is a vault URI configured", one credential object reused for Key Vault, Blob and SQL; JWT settings read from configuration (authority + audience) so Keycloak and Entra are just different values; role claims mapped to the existing policies; `AddDataProtection` with blob + key-vault key; vault, identity and role assignments as resources you can later put in Bicep; rotation = add new version -> app reloads/new revision -> verify -> disable old.
</details>

## Verify
```bash
# vault hardening
az keyvault show -n <vault> --query "{rbac:properties.enableRbacAuthorization,softDelete:properties.enableSoftDelete,purge:properties.enablePurgeProtection,public:properties.publicNetworkAccess}"
# identity and roles of the app
az containerapp show -n <api> -g <rg> --query identity
az role assignment list --assignee <principal-id> --all -o table       # no Owner/Contributor, only the roles you planned
# no secrets in deployed config
az containerapp show -n <api> -g <rg> --query "properties.template.containers[0].env[].{n:name,v:value,s:secretRef}" -o table
gh secret list                                                          # no Azure/app credentials
# no password in git history of config files
gitleaks detect --no-banner || trufflehog git file://. --only-verified   # if installed
# tokens
curl -s -o /dev/null -w '%{http_code}\n' https://<api-host>/api/v1/users            # 401 without token
```
Also: sign in through Entra in the browser, call an admin-only endpoint as a non-admin (403) and as an admin (200); restart with `az containerapp revision restart` and confirm your session/antiforgery still works; scale to 2 replicas and repeat. With the step-17 BFF the sessions live in the gateway's memory: with 2 replicas you need a shared session store and a shared Data Protection key ring (or sticky sessions as a stop-gap) – test a request that lands on the other replica.
Part 1 tests: `dotnet test backend/SecLab.slnx --filter "Step=03"` and `"Step=05"` remain green.

Checklist:
- [ ] Vault: RBAC on, soft delete on, purge protection on
- [ ] App identity has only the planned roles
- [ ] No credential-valued env var / app setting / Bicep parameter / GitHub secret remains
- [ ] Login via Entra works; wrong audience or wrong tenant token is rejected (401)
- [ ] Two replicas share the Data Protection key ring
- [ ] Rotation of one secret done with no downtime; old version disabled

## Pitfalls
- Role assignments take minutes to propagate; a 403 right after creation is normal, a permanent one is a scope or principal-id mistake.
- `DefaultAzureCredential` with a user-assigned identity and no client id silently fails or picks another credential.
- Under RBAC, being `Owner` or `Contributor` of the vault does **not** allow reading secrets.
- Accepting tokens from *any* tenant (`common`/`organizations` authority without issuer validation) lets other tenants' users in. Pin the tenant or validate issuers.
- Access tokens vs ID tokens: the API must accept access tokens with its own audience, never ID tokens.
- `groups` claim overage: users in many groups get a link instead of the list – prefer app roles.
- Loading the whole vault at startup makes a slow or unavailable vault a startup outage; decide on caching and failure behaviour.
- Key Vault references in Container Apps resolve at revision start; rotating the secret alone does not update running replicas.
- Purge protection makes a wrongly named vault stay around; do the naming step properly.

## Further reading
- Managed identities for Azure resources – https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/
- Key Vault RBAC guide, soft delete and purge protection – https://learn.microsoft.com/azure/key-vault/
- Azure SDK authentication for .NET (`DefaultAzureCredential`) – https://learn.microsoft.com/dotnet/azure/sdk/authentication/
- ASP.NET Core Data Protection key storage providers – https://learn.microsoft.com/aspnet/core/security/data-protection/
- Microsoft identity platform: protected web API, app roles – https://learn.microsoft.com/entra/identity-platform/
- OWASP Secrets Management Cheat Sheet; OWASP Cheat Sheet on JWT

Stuck or done? Compare with the solution: [`docs/solutions/p2-03-secrets-and-identity.md`](../solutions/p2-03-secrets-and-identity.md).
