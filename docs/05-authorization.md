# 05 – Authorization

> Prerequisites: steps 01–04 done (or apply patches `01`–`04`). Time: 2–3 hours. No schema change.
> Step 03 answered *who are you?* Now answer *what may you do?* – the #1 item of the OWASP API Security Top 10 (BOLA/IDOR), plus #3 (property level) and #5 (function level).

## Goal
Make every endpoint enforce **who may do what, to which record, and see which fields** – on the server, by default.

Rules (the tests encode exactly these; roles come from `Users.Role` in the database, not from the token):

| Resource / action | Allowed |
|---|---|
| Any `/api` endpoint that says nothing about auth | authenticated users only – **default deny**, except `/api/auth/*` |
| `GET /api/users/{id}` | **Owner or Admin:** full profile (id, username, displayName, avatarUrl, bio, email, phone, address, role). **Friend:** public fields + email + phone. **Anyone else:** public fields only (id, username, displayName, avatarUrl, bio). Never password/hash/lockout data. Unknown id → `404`. |
| `GET /api/me` | the same *full* view of yourself |
| `PUT /api/users/{id}` | **Owner only** (not even Admin) → `403` otherwise. Only displayName, email, phone, address, bio are editable; `role`, `username`, `password`, `id` in the body are ignored. |
| `GET /api/users/{id}/friends`, `/likes` | Owner or Admin → `403` otherwise. |
| `POST /api/users/{id}/avatar` | Owner only. |
| `POST /api/blogs` | any user; the **author is the caller**, whatever the body says. |
| **new** `PUT /api/blogs/{id}` (`{ title, body }`) | **Author only**; `404` if missing. |
| **new** `DELETE /api/blogs/{id}` | **Author or Admin** → `204`; `403` otherwise; `404` if missing. |
| **new** `GET /api/admin/users` | Admin only – id, username, displayName, email, role. |
| **new** `PUT /api/admin/users/{id}/role` (`{ role }`) | Admin only; role must be `User` or `Admin` (`400` otherwise). |
| `GET /api/debug/crash` | Admin only. |

Also: a small **UI** improvement – authors get a Delete button on their own posts in *Experience*.

Out of scope: input validation depth and file-upload safety (step 10), rate limits (07), audit logging of denials (12).

## Threat / why
Authentication proves identity; without authorization every logged-in user is a super-user. Object IDs in URLs are guessable, and clients can send fields you never meant to accept.

```bash
bash docs/attack-scripts/05-idor.sh        # dave (an ordinary user, not alice's friend) attacks alice
```
It shows: reading alice's private data, editing her profile, promoting yourself to Admin through your own profile (mass assignment), reading her private lists, calling admin/debug routes. On the pre-step code most of these succeed – with a *valid* token.

## Concepts
- **Authentication ≠ authorization.** ASP.NET Core separates them: authentication builds a `ClaimsPrincipal`; authorization evaluates **requirements** against it (and optionally a **resource**).
- **Levels of authorization:** *function level* (may this role call this endpoint?), *object level* (may this user touch **this** record?), *property level* (may they see/set **this field**?). Each has a classic vulnerability: BFLA, BOLA/IDOR, mass assignment/excessive data exposure.
- **Declarative vs imperative.** Roles/policies attach to endpoints (`RequireAuthorization("…")`) and answer "who may call this?". Anything that depends on the record ("only the author") is **resource-based**: load the record, then ask `IAuthorizationService.AuthorizeAsync(user, resource, requirement)`. Handlers (`AuthorizationHandler<TRequirement, TResource>`) hold the logic in one place instead of `if` statements scattered over endpoints; `OperationAuthorizationRequirement` is the ready-made "verb" requirement.
- **Default deny / fallback policy.** ASP.NET Core can apply a *fallback policy* to any endpoint that has no authorization metadata. It is the safety net for the endpoint somebody adds next month and forgets to protect. `AllowAnonymous` then becomes an explicit, greppable exception.
- **Roles from where?** The IdP can put roles in the token; you can also keep them in your own database (as here). Either way, translate to claims *once per request* (an `IClaimsTransformation`) so the rest of the code just asks `IsInRole`. Be aware of staleness: a token issued yesterday still says what it said yesterday, a DB lookup doesn't.
- **DTOs are an authorization tool.** Returning entities leaks every column you add later; accepting entities lets clients write every column. Separate input and output types per audience (a fuller treatment comes in step 10).
- **403 vs 404.** `403` says "exists, not for you"; `404` hides existence. Pick per resource and be consistent; for enumerable IDs `404` is sometimes the safer answer. The tests here use `403` for existing-but-forbidden.
- **Least privilege & separation of duties:** Admins here can delete content but can't rewrite someone's profile.
- **Tests as specification:** authorization bugs are logic bugs; the matrix above must be executable.

## Your turn
Tasks:
1. Turn on default deny and add an `Admin` policy.
2. Get the local user id and role into the principal for every request.
3. Write resource handlers for users and blogs; use them in the endpoints.
4. Replace entity input/output with per-audience types; implement the new endpoints.
5. Run the tests; then the attack script; then look at the UI.

<details><summary>Hint 1 – where to look</summary>

`Program.cs` (authorization registration), `Endpoints/Api.cs` (every route), a new `Authorization/` folder, `frontend/src/BlogCard.tsx` + `pages/Experience.tsx`.
</details>

<details><summary>Hint 2 – which APIs</summary>

`AddAuthorizationBuilder().SetFallbackPolicy(...).AddPolicy(...)`; `IClaimsTransformation`; `AuthorizationHandler<OperationAuthorizationRequirement, TResource>` registered as `IAuthorizationHandler`; `IAuthorizationService.AuthorizeAsync`; `Results.Forbid()`; `ClaimsPrincipal` as an endpoint parameter; `ExecuteUpdateAsync` for the role change.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

Claims transformation: look the user up by `preferred_username`, add `local_user_id` and a role claim on a *copy* of the identity, and make it idempotent. One handler per resource type switching on the operation name. Endpoints follow "load → authorize → act" (and pick the response DTO by which operation succeeded). Three profile records (public / friend / full), one input record. Admin routes in a group with the policy.
</details>

## Verify
```bash
dotnet test backend/SecLab.slnx --filter "Step=05"      # 16 tests; each creates its own users, seeded data is untouched
bash docs/attack-scripts/05-idor.sh                     # Keycloak + API running
```
Checklist:
- [ ] `Step=05` (16) green, steps 01–04 still green
- [ ] Attack script: public fields only, `403`, role still `"User"`, `403 403`, `403 403`
- [ ] Deleting the `[Authorize]`-equivalent from one new test endpoint still yields `401` (default deny works)
- [ ] `git grep -n "Results.Ok(u)\|Results.Ok(user)"` finds no entity being returned
- [ ] UI: an author sees Delete only on their own posts; friends' profiles show email + phone but no address

## Pitfalls
- **Checking authentication where you needed authorization** ("user is logged in" is not "user owns this").
- Authorizing on a client-supplied id instead of the loaded record's owner.
- Forgetting *sibling* routes: `/users/{id}`, `/users/{id}/friends`, `/users/{id}/likes`, avatar, search results – attackers try them all.
- Returning the entity and "hiding" fields in the UI; the response is what counts.
- Binding request bodies straight to entities → `role`, `id`, `authorId` become client-controlled.
- Mutating the incoming `ClaimsIdentity` in a claims transformation (it may be cached and run several times) – clone it and be idempotent.
- Treating "admin" as "can do anything": decide per action (admins may delete a post but not edit a profile here).
- Role in the *token* vs role in the *database* going out of sync; know which you trust and how fast changes take effect.
- Only testing the happy path and the anonymous case – the dangerous cases are *authenticated but wrong user*.

## Further reading
- Authorization in ASP.NET Core – https://learn.microsoft.com/aspnet/core/security/authorization/introduction
- Resource-based authorization – https://learn.microsoft.com/aspnet/core/security/authorization/resourcebased
- Policy-based authorization and fallback policy – same section
- .NET security overview – https://learn.microsoft.com/dotnet/standard/security/
- OWASP API Security Top 10 (API1 BOLA, API3 Property level, API5 BFLA); OWASP Authorization Cheat Sheet; OWASP IDOR Prevention Cheat Sheet

Stuck or done? Compare with the solution: [`docs/solutions/05-authorization.md`](solutions/05-authorization.md) and `solutions/05-authorization.patch` (applies on top of 01–04).
