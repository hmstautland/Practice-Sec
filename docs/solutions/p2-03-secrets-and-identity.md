# Solution – P2-03 Secrets and identity

> Spoiler. Try the step yourself first: [`../part2-azure/P2-03-secrets-and-identity.md`](../part2-azure/P2-03-secrets-and-identity.md). **Not verified:** none of this was run (no Azure/Entra tenant available). C# snippets are sketches against `Azure.Identity`, `Azure.Extensions.AspNetCore.*` and `Microsoft.Identity.Web`/`JwtBearer` – check the current package versions and signatures. The Bicep for vault, identity and roles is in `solutions/p2-04-host/main.bicep`.

## 1. Vault and identity (CLI equivalent of the Bicep)
```bash
RG=rg-seclab-dev-<r>; KV=kv-seclab-dev-<hash>
az identity create -g $RG -n id-seclab-dev
az keyvault create -g $RG -n $KV --enable-rbac-authorization true \
   --enable-purge-protection true --retention-days 90 --public-network-access Disabled
PRINCIPAL=$(az identity show -g $RG -n id-seclab-dev --query principalId -o tsv)
az role assignment create --assignee-object-id $PRINCIPAL --assignee-principal-type ServicePrincipal \
   --role "Key Vault Secrets User" --scope $(az keyvault show -n $KV --query id -o tsv)
az role assignment create --assignee-object-id $PRINCIPAL --assignee-principal-type ServicePrincipal \
   --role "Key Vault Crypto User" --scope $(az keyvault show -n $KV --query id -o tsv)
# you (to add secrets/keys as a human, from a network that can reach the vault):
az role assignment create --assignee <you> --role "Key Vault Secrets Officer" --scope <vault id>
az keyvault secret set --vault-name $KV -n Seclab--ApiKeyPepper --value "$(openssl rand -base64 48)" >/dev/null
```
(`--` in a secret name becomes `:` in configuration. The value never lands in your shell history if you generate it inline as above.) Attach the identity: `az containerapp identity assign -g $RG -n <app> --user-assigned <identity id>` (Bicep does this in `main.bicep`).

## 2. Startup code (sketch)
```csharp
var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions {
    ManagedIdentityClientId = builder.Configuration["AZURE_CLIENT_ID"]   // user-assigned identity
});

var vaultUri = builder.Configuration["KeyVault:Uri"];
if (!string.IsNullOrEmpty(vaultUri))
    builder.Configuration.AddAzureKeyVault(new Uri(vaultUri), credential,
        new AzureKeyVaultConfigurationOptions { ReloadInterval = TimeSpan.FromMinutes(15) });

builder.Services.AddDataProtection()
    .SetApplicationName("seclab")
    .PersistKeysToAzureBlobStorage(new Uri(builder.Configuration["DataProtection:BlobUri"]!), credential)
    .ProtectKeysWithAzureKeyVault(new Uri(builder.Configuration["DataProtection:KeyId"]!), credential);
```
Local development: no `KeyVault:Uri` -> only appsettings / user-secrets / Keycloak, as in Part 1. In production prefer `ManagedIdentityCredential` directly to avoid the fallback chain. SQL: the connection string from Bicep uses `Authentication=Active Directory Managed Identity;User Id=<client id>` – `Microsoft.Data.SqlClient` gets the token itself; no code change beyond the string (and no password in `appsettings.json` in Production – remove the Part 1 `sa` string from the deployed configuration).

Container Apps alternative (values become env vars, resolved at revision start):
```bash
az containerapp secret set -g $RG -n <app> --secrets "pepper=keyvaultref:https://$KV.vault.azure.net/secrets/Seclab--ApiKeyPepper,identityref:<identity resource id>"
az containerapp update -g $RG -n <app> --set-env-vars "Seclab__ApiKeyPepper=secretref:pepper"
```
Rotating requires a new revision. The configuration-provider route reloads without restart – the reason it is the default here.

## 3. Entra ID instead of Keycloak
1. **API app registration** `seclab-api`: *Expose an API* -> Application ID URI `api://<api-client-id>`, scope `access_as_user`; *App roles* `Admin`, `User` (allowed member types: Users/Groups); manifest `requestedAccessTokenVersion: 2` so tokens carry the v2 issuer. Assign users/groups to roles under the enterprise application.
2. **SPA app registration** `seclab-web`: platform *Single-page application*, redirect URI `https://<static-site-host>/` (PKCE, no secret, no implicit flow); API permission `access_as_user` on `seclab-api`.
   > **Revision needed after step 17:** the browser no longer talks to the IdP; the gateway (BFF) does. Register `seclab-web` as a *Web* application (redirect URI `https://<gateway-host>/bff/callback`, a client secret in Key Vault or a certificate/federated credential, `Bff__*` settings from Key Vault references) and keep the sessions in a shared store when running more than one replica. The text below was drafted for the SPA flow and has not been revised.
3. **API config:** authority `https://login.microsoftonline.com/<tenant-id>/v2.0`, audience `api://<api-client-id>`, valid issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`. Keep it in configuration so local = Keycloak values, Azure = Entra values.
```csharp
services.AddAuthentication().AddJwtBearer(o => {
    o.Authority = cfg["Auth:Authority"];
    o.Audience  = cfg["Auth:Audience"];
    o.TokenValidationParameters.ValidateIssuer = true;       // pinned tenant, not "common"
    o.TokenValidationParameters.RoleClaimType = "roles";     // Entra app roles; Keycloak mapped separately
});
```
Part 1 policies (`RequireRole("Admin")` etc.) stay. If Part 1 used Keycloak's `realm_access.roles`, put the claim mapping behind the same configuration switch.
4. **Frontend:** authority/client id/scope from build-time variables; scope `api://<api-client-id>/access_as_user`.
5. **MFA/passkeys:** Conditional Access policy requiring phishing-resistant authentication strength for admins (this replaces Part 1 step 04 at the IdP).
6. GitHub -> Azure federation uses a *different* app registration (`gh-seclab-*`, P2-02) – never reuse an app registration between user login and CI.

Checks: a token with the wrong `aud`, a token from another tenant and an ID token must all return 401.

## 4. Rotation runbook (Key Vault secret, zero downtime)
```bash
az keyvault secret set --vault-name $KV -n Seclab--ApiKeyPepper --value "$(openssl rand -base64 48)"   # new version, old stays enabled
# wait for ReloadInterval (or restart a revision): az containerapp revision restart -g $RG -n <app> --revision <name>
# verify: requests succeed with new material; then disable the old version
az keyvault secret list-versions --vault-name $KV -n Seclab--ApiKeyPepper -o table
az keyvault secret set-attributes --vault-name $KV -n Seclab--ApiKeyPepper --version <old> --enabled false
```
For a peppered hash you cannot swap the pepper without re-hashing: use a versioned pepper id stored with each hash (two active until re-hashed). For API keys (step 06) issue the new key, let the client switch, then revoke the old.

## Not done here on purpose
Certificate-based client credentials, key-vault-backed TLS certificates, customer-managed keys for SQL TDE.
