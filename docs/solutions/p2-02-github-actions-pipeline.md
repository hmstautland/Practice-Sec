# Solution – P2-02 GitHub Actions pipeline

> Spoiler. Try the step yourself first: [`../part2-azure/P2-02-github-actions-pipeline.md`](../part2-azure/P2-02-github-actions-pipeline.md). Reference files: [`solutions/p2-02-pipeline/`](../../solutions/p2-02-pipeline/) (`ci.yml`, `deploy.yml`, `deploy-env.yml`, `Dockerfile.api`).
>
> **Verified:** the three YAML files parse (PyYAML). **Not verified:** `actionlint`, a real run on GitHub, `azure/login`, any Azure call, the Trivy/CodeQL/ZAP action inputs, the `backend` job's database set-up (`init-secrets.sh` → `docker compose up --wait` → `init-database.sh` on a hosted runner; the same scripts were run locally in step 15, not on GitHub) and the `mutation` job (Stryker itself was run locally in step 16). The weekly `schedule` trigger also re-runs every other job; restrict it with `if:` if that is too much. Every `<commit-sha>` is a placeholder you must fill in (below).

## 1. Azure side: identities with federated credentials
One app registration (or user-assigned managed identity) per purpose, **no client secret**:

```bash
SUB=<subscription-id>; TENANT=<tenant-id>; REPO=<owner>/<repo>
for name in build dev test prod; do
  APP_ID=$(az ad app create --display-name "gh-seclab-$name" --query appId -o tsv)
  az ad sp create --id "$APP_ID" >/dev/null
  az ad app federated-credential create --id "$APP_ID" --parameters "{
    \"name\": \"env-$name\",
    \"issuer\": \"https://token.actions.githubusercontent.com\",
    \"subject\": \"repo:$REPO:environment:$name\",
    \"audiences\": [\"api://AzureADTokenExchange\"] }"
  echo "$name client id: $APP_ID"
done
```
RBAC (least privilege):
```bash
# build identity: push images only
az role assignment create --assignee <build-app-id> --role AcrPush \
  --scope $(az acr show -n <acr> --query id -o tsv)
# each env identity: manage its own resource group only
az role assignment create --assignee <dev-app-id> --role Contributor \
  --scope /subscriptions/$SUB/resourceGroups/rg-seclab-dev-<r>
```
Deploying Bicep that creates role assignments needs `Role Based Access Control Administrator` (constrained to the roles you assign, via a condition) or `User Access Administrator` on that resource group in addition to `Contributor`; prefer the constrained form. The env identities also need read on the ACR (resolve) and the cross-RG `AcrPull` assignment in `acr-pull.bicep` needs rights on the registry's group – simplest: pre-create that assignment once by hand and drop the module. Also make the identities members of the SQL admin group only if you run T-SQL from CI (see P2-04).

Check: `az ad app federated-credential list --id <id> --query "[].subject"`; `az ad app credential list --id <id>` must be empty.

## 2. GitHub side
```bash
R=<owner>/<repo>
# default token read-only
gh api -X PUT repos/$R/actions/permissions/workflow -f default_workflow_permissions=read
# environments
for e in build dev test prod; do gh api -X PUT repos/$R/environments/$e >/dev/null; done
USER_ID=$(gh api user --jq .id)
gh api -X PUT repos/$R/environments/prod --input - <<JSON
{ "reviewers": [{"type":"User","id":$USER_ID}], "prevent_self_review": false,
  "deployment_branch_policy": {"protected_branches": true, "custom_branch_policies": false} }
JSON
# same for test (reviewers optional there), then variables per environment (NOT secrets):
for e in dev test prod; do
  gh variable set AZURE_CLIENT_ID -e $e --body <that env's app id>
  gh variable set AZURE_TENANT_ID -e $e --body $TENANT
  gh variable set AZURE_SUBSCRIPTION_ID -e $e --body $SUB
  gh variable set AZURE_RESOURCE_GROUP -e $e --body rg-seclab-$e-<r>
  # ACR_NAME, ACR_RESOURCE_GROUP, ALERT_EMAIL, SQL_ADMIN_GROUP_OBJECT_ID, SQL_ADMIN_GROUP_NAME ...
done
gh variable set AZURE_CLIENT_ID -e build --body <build app id>   # + AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID, ACR_NAME
```
Set `prevent_self_review` to `true` once a second person exists (a lone learner cannot approve otherwise). Branch protection for `main` (PR required, 1 approval, status checks `backend`, `frontend`, `codeql (csharp)`, `codeql (javascript-typescript)`, `dependency-review`, `images (api)`, `images (externalapi)`, no force-push):
```bash
gh api -X PUT repos/$R/branches/main/protection --input - <<'JSON'
{ "required_status_checks": {"strict": true, "contexts": ["backend","frontend","codeql (csharp)","codeql (javascript-typescript)","dependency-review","images (api)","images (externalapi)"]},
  "enforce_admins": true,
  "required_pull_request_reviews": {"required_approving_review_count": 1, "dismiss_stale_reviews": true},
  "restrictions": null, "allow_force_pushes": false, "allow_deletions": false }
JSON
```
(Repository *rulesets* are the newer alternative; the exact check names appear in the PR "Checks" list – copy them from there.) Also enable in *Settings -> Advanced Security*: dependency graph, Dependabot alerts, secret scanning + push protection, and in *Actions -> General* restrict allowed actions (GitHub-owned + the specific ones you use) and require approval for fork PR workflows.

## 3. Pinning actions
For each `uses:` find the commit of the tag you chose:
```bash
gh api repos/actions/checkout/git/ref/tags/v<x.y.z> --jq '.object | "\(.type) \(.sha)"'
# type=commit -> use the sha; type=tag (annotated) -> gh api repos/actions/checkout/git/tags/<sha> --jq .object.sha
```
Replace `<commit-sha>` and keep `# v<x.y.z>`. Dependabot (`.github/dependabot.yml`, ecosystems `github-actions`, `nuget`, `npm`, `docker`, weekly) opens PRs that bump SHA and comment together. Local check that nothing is left mutable or unfilled: `grep -RIn '<commit-sha>' .github` must print nothing before you push. (`actionlint` does not object to the SHA but will not resolve it either.)

## 4. What each file does
**`ci.yml`** – `permissions: contents: read` for the workflow; jobs:
- `backend`: build, then the **unit tests** (`--filter "Kind=Unit"`, step 16: seconds, no database), then the database exactly as on a laptop: `bash docs/init-secrets.sh` (random throw-away passwords and a pinned certificate for this run), `docker compose up -d --wait sqlserver`, `bash docs/init-database.sh` (logins and migrations). A GitHub *service container* was not used because it cannot mount the generated certificate and the tests (step 15) refuse `TrustServerCertificate=True`. The whole suite then runs in one shell step that sources `.env` (the app reads `ConnectionStrings:Default`; `CI=true` makes the restore use the lock files). Then the `dotnet list package --vulnerable --include-transitive` gate, which greps the output because the command itself exits 0. Alternative gate: `NuGetAudit` with warnings-as-errors for NU1901–NU1904 in the build.
- `mutation` (step 16): only on `workflow_dispatch` or the weekly `schedule`; `dotnet tool restore` + `dotnet stryker` in the test project (unit tests only, no database); the HTML/JSON report is uploaded as an artifact; the job fails below the `break` threshold.
- `frontend`: `npm ci --ignore-scripts` (lifecycle scripts of dependencies do not run), build, `npm audit --audit-level=high`.
- `codeql`: matrix `csharp`, `javascript-typescript`, `build-mode: none`, the only job with `security-events: write`.
- `dependency-review`: PR only.
- `images`: `docker build` for API and ExternalApi + Trivy (HIGH/CRITICAL, unfixed ignored). No login, no push, so it is safe for fork PRs.

**`deploy.yml`** – `permissions: {}` at workflow level. `build-push` (environment `build`, `id-token: write`) builds again from the merged commit, scans, logs in with OIDC, pushes `seclab-*:<sha>` and emits `registry/repo@sha256:...` references (checked with a `case`). `deploy-dev` -> `deploy-test` -> `deploy-prod` call `deploy-env.yml` with the digest references; `test` and `prod` pause for reviewers; `prod` is restricted to `main` by the environment's branch policy and by the `if:` on the first job.

**`deploy-env.yml`** – one place for the deployment logic: OIDC login (variables of *that* environment), `what-if`, `az deployment group create` (image digests are Bicep parameters, so infra and app move together), frontend build with the API URL from the deployment output, SWA token fetched at run time and masked (`::add-mask::`), then `scripts/smoke.sh` (P2-05). All inputs reach shell code through `env:` variables.

Injection rules used throughout: no `${{ }}` inside `run:` bodies; expressions only in `env:`/`with:`. If you need a PR title or branch name, pass it via `env:` and quote it.

## 5. Dockerfile
`Dockerfile.api` is a multi-stage build ending in the chiseled ASP.NET runtime image (no shell, non-root via `$APP_UID`). Build context is `backend/`; for the ExternalApi change the project. Check the current tag names for .NET 10 images.

## 6. Verification you can run
```bash
actionlint .github/workflows/*.yml
python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" .github/workflows/ci.yml   # per file
grep -RIn '<commit-sha>' .github                           # nothing left unpinned
gh api repos/$R/environments/prod --jq '.protection_rules'
gh api repos/$R/actions/permissions/workflow --jq .default_workflow_permissions
```
`act pull_request -j backend` can exercise the job locally (the compose-started database needs access to the host's Docker; expect differences from GitHub-hosted runners).

## Known gaps
- `deploy.yml` triggers on `push` to `main` and relies on branch protection for "CI was green". A stricter alternative is a `workflow_run` gate on `ci` (read its security notes first).
- The frontend is rebuilt per environment (API URL is baked in); the *container* artifacts are promoted by digest.
- Image signing / SBOM / provenance attestations (`actions/attest-build-provenance`, cosign) are further reading.
- The `azure/login` inputs, `Azure/static-web-apps-deploy` inputs and `zaproxy` inputs are from memory; check the current README of each.
