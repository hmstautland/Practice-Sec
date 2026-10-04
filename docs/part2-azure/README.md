# Part 2 – Hosting & setting up in Azure

Part 1 (steps 01–17) hardened the application. Part 2 moves it to Azure and hardens **the place it runs**: the pipeline that builds it, the identities that run it, the secrets it needs and the network around it. Same method as Part 1: goal, threat, concepts, your turn (tiered hints), verify, pitfalls; the full walkthrough is in `docs/solutions/p2-NN-*.md`, reference files in `solutions/p2-*`.

## Steps
| Step | Topic | Time |
|------|-------|------|
| [P2-01](P2-01-azure-landing.md) | Azure landing zone: architecture, resource groups, naming, environments, cloud threat model | ~45 min |
| [P2-02](P2-02-github-actions-pipeline.md) | CI/CD with GitHub Actions: secure pipeline, OIDC to Azure, protected environments | ~2 h |
| [P2-03](P2-03-secrets-and-identity.md) | Key Vault, managed identity, Microsoft Entra ID instead of Keycloak, Data Protection keys | ~1.5 h |
| [P2-04](P2-04-host-security.md) | Host security: Azure SQL, network, Front Door + WAF, monitoring, Policy, Bicep | ~2.5 h |
| [P2-05](P2-05-operate-and-verify.md) | Operate and verify: smoke tests, ZAP baseline, review checklist, incident runbook | ~1 h |

Do them in order; each step builds on the previous one.

## Prerequisites
- Part 1 finished (or at least steps 01, 03, 12, 14, 15): the tests `dotnet test backend/SecLab.slnx` are green.
- An **Azure subscription** where you may create resource groups and assign roles (Owner, or Contributor + User Access Administrator, on a *sandbox* subscription). A Microsoft Entra tenant where you may create app registrations.
- A **GitHub repository** you administer (environments and branch protection need admin rights; on private repos some features need a paid plan – check the current GitHub plan limits).
- CLIs: `az` (with the Bicep CLI: `az bicep install`), `gh` (`gh auth login`), `git`. Recommended for local checks: `actionlint`, `yamllint`, `act` (needs Docker, only ever run locally).
- Nothing in this repository is deployed for you. The reference files were written without access to a subscription; each solution page lists what was **not** verified.

## Cost warning
Azure resources bill while they exist. The expensive ones here are **Front Door Premium** (the WAF managed rules need it; roughly a fixed monthly fee), **Defender plans**, **Azure SQL** (choose the smallest/serverless tier) and **Container Apps** with a minimum replica count above zero. Use one subscription with a **budget and alert** (P2-01), deploy `dev` first, and delete resource groups when you stop: `az group delete`. Purge protection on Key Vault means a deleted vault's *name* stays reserved for the retention period – pick names accordingly. Prices change; check the Azure pricing calculator.

## How Part 2 maps to Part 1
| Part 1 step | Becomes in Azure |
|-------------|------------------|
| 01 HTTPS | HTTPS-only ingress, TLS 1.2 minimum, managed certificate on a custom domain (P2-04) |
| 03 OAuth2/OIDC | Microsoft Entra ID replaces Keycloak (P2-03) |
| 04 WebAuthn | Passkeys / phishing-resistant MFA policy in Entra (P2-03, optional) |
| 06 API keys | Key Vault holds the key hashes' pepper and external keys (P2-03) |
| 07 Rate limiting | Front Door WAF rate-limit rule as a second layer (P2-04) |
| 11 Error handling | No stack traces from the container; ingress error pages (P2-05 checks) |
| 12 Logging/observability | OpenTelemetry to Application Insights / Log Analytics, alerts (P2-04) |
| 13 OWASP mapping | ZAP baseline scan and the OWASP CI/CD Top 10 (P2-02, P2-05) |
| 14 YARP gateway | Front Door + WAF (or API Management) in front of the API (P2-04) |
| 15 Database security | Azure SQL, Entra-only auth, managed-identity user, no `sa` (P2-04) |
| 16 Testing | CI runs the unit tests first, then the suite against a compose-started SQL Server set up by the step-15 scripts; Stryker.NET as a manual/scheduled job (P2-02) |

## Conventions
- Placeholders in angle brackets (`<subscription-id>`, `<commit-sha>`) are yours to fill in. Never commit real ids that you consider sensitive or any secret.
- "Check the current version" means: look up the latest release/API version yourself – tool and API versions move fast, and pinning is part of the lesson.
