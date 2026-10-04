# Solution – 05 Authorization

> Spoiler. Try the step yourself first: [`../05-authorization.md`](../05-authorization.md). Patch: `solutions/05-authorization.patch` (after 01–04).

## What was verified
- **52 tests** (steps 01–05) pass on a fresh database.
- Live run of `05-idor.sh` against real Keycloak tokens: `403` on editing another user, role stays `User` after a mass-assignment attempt, `403 403` for someone else's friends/likes, `403 403` for admin/debug routes. (Step 1 of the script showed the *friend* view for bob→alice because they are friends in the seed data; the script now uses dave, a non-friend.)
- The frontend builds. Not click-tested in a browser.

## Building blocks
**`Program.cs`**
```csharp
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
    .AddPolicy("Admin", p => p.RequireRole("Admin"));
builder.Services.AddScoped<IClaimsTransformation, LocalUserClaims>();
builder.Services.AddScoped<IAuthorizationHandler, UserResourceHandler>();
builder.Services.AddScoped<IAuthorizationHandler, BlogResourceHandler>();
```
The `/api` group no longer says `RequireAuthorization()` – the fallback policy does the work, and only `/api/auth/*` opts out with `AllowAnonymous()`.

**`Authorization/LocalUserClaims.cs`** – an `IClaimsTransformation` that finds the user by `preferred_username`, then adds `local_user_id` and `ClaimTypes.Role` (from `Users.Role`) to a **cloned** identity; it returns early if the claim is already there (it can run more than once per request).

**`Authorization/ResourceHandlers.cs`**
- `Operations`: `ViewFull`, `ViewAsFriend`, `Edit`, `Delete` (`OperationAuthorizationRequirement`).
- `UserResourceHandler` (resource `User`): `ViewFull` = owner or Admin; `Edit` = owner only; `ViewAsFriend` = owner, Admin, or a `Friendships` row exists.
- `BlogResourceHandler` (resource `Blog`): `Edit` = author; `Delete` = author or Admin.
A handler that doesn't call `Succeed` means *denied* – there is no explicit fail path to forget.

## Endpoints
Pattern: **load → authorize → act**.
```csharp
var target = await db.Users.FindAsync(id);
if (target is null) return Results.NotFound();
if ((await authz.AuthorizeAsync(me, target, Operations.ViewFull)).Succeeded) return Results.Ok(FullProfile.From(target));
if ((await authz.AuthorizeAsync(me, target, Operations.ViewAsFriend)).Succeeded) return Results.Ok(FriendProfile.From(target));
return Results.Ok(PublicProfile.From(target));
```
- Output records `PublicProfile` / `FriendProfile` / `FullProfile` and input records `UpdateProfile`, `EditBlog`, `ChangeRole` – **entities no longer cross the API boundary**. `PUT` copies only the five editable fields, so `role`, `username`, `password`, `id` in the body are simply not part of the type.
- `POST /blogs` sets `AuthorId` from the caller. `PUT`/`DELETE /blogs/{id}` use `BlogResourceHandler`; delete also removes the blog's likes.
- `/admin` is a group with `RequireAuthorization("Admin")`; the role endpoint validates the two allowed values and uses `ExecuteUpdateAsync`.
- `/debug/crash` requires the Admin policy.

## Test-design notes
- Every test creates its own users (and friendships/blogs) through `AppDbContext`, so seed data is never modified – important because a broken solution would otherwise leave the database changed.
- The "password not changed" assertion compares against the value *before* the request: the step-02 startup sweep may legitimately hash a legacy test row whenever another test host starts.

## Deliberately left open
- File upload still trusts the client's file name and type → step 09/10.
- No input validation (lengths, formats), blog body still raw HTML → step 10.
- Denials are not logged → step 12.
- One DB query per request for the claims transformation; fine here, cache carefully if you optimise (staleness vs. speed).
