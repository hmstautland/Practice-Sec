# OWASP mapping for SecLab (fill this in – step 13)

Rules for a valid matrix (`Step13OwaspTests` reads this file):

- One row per category below; keep the **ID** column exactly as it is.
- **Status** is one of: `Mitigated`, `Partial`, `Accepted risk`, `Not applicable`.
- **Where / how in SecLab** says concretely *where the risk exists* in this app (endpoint, file, feature) – not a definition of the category.
- **Mitigation** names the step(s) / code that address it. For `Partial` and `Accepted risk` say what is left.
- **Evidence** for `Mitigated` and `Partial` must point at something runnable that exists in the repo: a test filter like `Step=05`, or a script path like `docs/attack-scripts/05-idor.sh`.
- `Accepted risk` and `Not applicable` need a justification of at least 20 characters in the *Mitigation* column (and, for accepted risks, an owner: `owner: <name/role>`).
- No `?` or `TODO` may remain.

## OWASP Top 10:2025

| ID | Title | Where / how in SecLab | Mitigation | Evidence | Status |
|----|-------|-----------------------|------------|----------|--------|
| A01 | Broken Access Control | ? | ? | ? | ? |
| A02 | Security Misconfiguration | ? | ? | ? | ? |
| A03 | Software Supply Chain Failures | ? | ? | ? | ? |
| A04 | Cryptographic Failures | ? | ? | ? | ? |
| A05 | Injection | ? | ? | ? | ? |
| A06 | Insecure Design | ? | ? | ? | ? |
| A07 | Authentication Failures | ? | ? | ? | ? |
| A08 | Software or Data Integrity Failures | ? | ? | ? | ? |
| A09 | Security Logging and Alerting Failures | ? | ? | ? | ? |
| A10 | Mishandling of Exceptional Conditions | ? | ? | ? | ? |

## OWASP API Security Top 10:2023

| ID | Title | Where / how in SecLab | Mitigation | Evidence | Status |
|----|-------|-----------------------|------------|----------|--------|
| API1 | Broken Object Level Authorization | ? | ? | ? | ? |
| API2 | Broken Authentication | ? | ? | ? | ? |
| API3 | Broken Object Property Level Authorization | ? | ? | ? | ? |
| API4 | Unrestricted Resource Consumption | ? | ? | ? | ? |
| API5 | Broken Function Level Authorization | ? | ? | ? | ? |
| API6 | Unrestricted Access to Sensitive Business Flows | ? | ? | ? | ? |
| API7 | Server Side Request Forgery | ? | ? | ? | ? |
| API8 | Security Misconfiguration | ? | ? | ? | ? |
| API9 | Improper Inventory Management | ? | ? | ? | ? |
| API10 | Unsafe Consumption of APIs | ? | ? | ? | ? |
