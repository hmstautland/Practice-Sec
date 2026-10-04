# Solution – 03 OAuth2 and OpenID Connect

> Spoiler. Try the step yourself first: [`../03-oauth2-oidc.md`](../03-oauth2-oidc.md). Reference patch: `solutions/03-oauth2-oidc.patch` – apply `01`, `02`, then this one (`patch -p1 < …`). After applying: `bash docs/reset-database.sh` if you switch between starter and solution trees.

## What was verified
- All **20** tests (steps 01–03) pass on a fresh database.
- Live against real Keycloak 26 tokens (password grant via `seclab-dev-cli`): no token → 401, `X-User-Id` only → 401, alice's token → `/api/me` = alice, and bob's token with a spoofed `X-User-Id: 1` returns *bob's* timeline (authors Alice, Dave) while alice's returns Bob and Carol.
- Frontend compiles and builds (`npm run build`).
- **Not verified here:** the interactive browser flow (redirect → Keycloak login → `/callback` → profile). No browser was available in the authoring environment; please try it and report problems.

## API
`Program.cs`
```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(o =>
{
    o.Authority = builder.Configuration["Auth:Authority"];          // issuer + discovery + signing keys
    o.Audience = builder.Configuration["Auth:Audience"];            // this API must be the intended audience
    o.MapInboundClaims = false;                                     // keep sub / preferred_username as issued
    o.RequireHttpsMetadata = !builder.Environment.IsDevelopment();  // HTTP only for the dev Keycloak
    o.TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(30);
});
builder.Services.AddAuthorization();
...
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
```
Signature, issuer, audience and lifetime validation are on by default once `Authority`/`Audience` are set; `alg: none` is rejected because a signature is required. Nothing here disables them.

`appsettings.json` has an **HTTPS placeholder** (`https://login.seclab.example/realms/seclab`); `appsettings.Development.json` overrides it with `http://localhost:8081/realms/seclab`. This split matters: with an HTTP authority in the base file the app throws on the first request in Production (`RequireHttpsMetadata`), which the step-01 HSTS test caught during authoring.

`Endpoints/Api.cs`
```csharp
var api  = app.MapGroup("/api").RequireAuthorization();       // authenticated by default
var auth = api.MapGroup("/auth").AllowAnonymous();            // legacy local login/registration

static async Task<int?> CurrentUserId(HttpContext ctx, AppDbContext db)
{
    var username = ctx.User.FindFirst("preferred_username")?.Value;
    if (string.IsNullOrEmpty(username)) return null;
    return await db.Users.Where(u => u.Username == username).Select(u => (int?)u.Id).FirstOrDefaultAsync();
}
```
`/api/me` projects the user to safe fields. Timeline / like / unlike call `CurrentUserId(ctx, db)`; a valid token for a user that doesn't exist locally gets `401` (no JIT provisioning – a deliberate, documented choice).

## SPA
- `src/api/auth.ts`: one `UserManager` – authority `http://localhost:8081/realms/seclab`, `client_id: seclab-spa`, `response_type: code` (PKCE is on by default in oidc-client-ts), tokens in `sessionStorage`.
- `Login.tsx`: a single button → `userManager.signinRedirect()`.
- `Callback.tsx` (route `/callback`): `signinRedirectCallback()` → `api.me()` → cache the profile for display → `/profile`.
- `client.ts`: `request()` awaits `userManager.getUser()` and sets `Authorization: Bearer <access_token>`; `X-User-Id` and the `token` in `localStorage` are gone.
- `App.tsx`: log-out calls `signoutRedirect()` so the IdP session ends too.

## Why the tests look the way they do
`TestIdp` creates an RSA key, sets `Auth__Authority` / `Auth__Audience` as **environment variables** (visible even if `Program.cs` reads configuration eagerly) and replaces the JwtBearer `ConfigurationManager` with a static one holding that key. `ConfigureTestServices(PostConfigure…)` *replaces the manager after the framework's own post-configure has created the real one*. Issuer, audience and lifetime checks are still yours.

## Known limitations left for later steps
- Any authenticated user can read/modify any other user's data (IDOR, mass assignment) → step 05, 10.
- The legacy `/api/auth/*` endpoints and the `Password` column still exist → removed or replaced in steps 04/05.
- Tokens in `sessionStorage` are exposed to XSS (W8 is still open until step 10) → step 17 (BFF).
- The password-grant client `seclab-dev-cli` and Keycloak dev mode (HTTP, admin/admin) are lab-only.
