# 00 – Overview and threat model

## How to use this tutorial
Each step is a challenge. Read **Goal**, watch the **Threat** demo, read **Concepts**, then try the **Your turn** tasks yourself (hints are tiered – stop at the lowest tier that unblocks you). **Verify** with the shipped tests and attack script. Only then read the solution.

## What the starter does
Login (plaintext password table) → Profile, Personal, Timeline, Experience pages. There is no real session, authorization or validation.

## Baseline weaknesses (all deliberate)
| # | Weakness | Where | Fixed in |
|---|----------|-------|----------|
| W1 | Plain HTTP only | Kestrel, Vite | 01 |
| W2 | Plaintext passwords, "token" = user id, user enumeration | `POST /api/auth/login`, `Users.Password` | 02, 03 |
| W3 | Client-chosen identity (`X-User-Id`) | all endpoints | 03, 05 |
| W4 | IDOR + password leak | `GET /api/users/{id}` | 05, 10 |
| W5 | Mass assignment (role/password overwrite), no owner check | `PUT /api/users/{id}` | 05, 10 |
| W6 | Unrestricted file upload | `POST /api/users/{id}/avatar` | 09, 10 |
| W7 | SQL injection | `GET /api/blogs/search` | 15 |
| W8 | Stored XSS | blog body via `dangerouslySetInnerHTML` | 10 |
| W9 | Spoofable author | `POST /api/blogs` | 05, 10 |
| W10 | Open CORS | `Program.cs` | 09 |
| W11 | Verbose errors / dev exception page | `Program.cs`, `/api/debug/crash` | 11 |
| W12 | No rate limiting | all | 07 |
| W13 | No versioning | all routes | 08 |
| W14 | DB accessed as `sa` with a weak committed password | `appsettings.json`, `docker-compose.yml` | 15 |
| W15 | Token in `localStorage` | frontend | 03 |

## Try the baseline attacks
Scripts in `docs/attack-scripts/` (need the API running on :5080):
```
bash docs/attack-scripts/00-baseline.sh
```
Each prints what the attacker obtained. After a step, the relevant lines should fail.

## Reference
https://learn.microsoft.com/en-us/dotnet/standard/security/
