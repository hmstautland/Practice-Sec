# Solution – 04 WebAuthn / passkeys (step-up)

> Spoiler. Try the step yourself first: [`../04-webauthn.md`](../04-webauthn.md). Patch: `solutions/04-webauthn.patch` (after 01–03). New table → `bash docs/reset-database.sh`.

## What was verified
- **36 tests** (steps 01–04) pass on a fresh database. The negative step-04 tests were additionally tightened to require exactly `400` (not just "not 2xx") and still passed, so they fail for the intended reason and not with a 500.
- The frontend builds. **Not verified:** the browser/authenticator ceremony (needs a real or virtual authenticator).
- Library: **Fido2 (Fido2NetLib) 4.1.1**, package `Fido2.AspNet`. v5 is still in preview; its API differs.

## Data
`Passkey { Id, UserId, CredentialId (byte[512], unique index), PublicKey, SignCount, UserHandle, Name, CreatedAt }`. The user handle is 16 random bytes created with the first passkey and reused for later ones.

## Program.cs
```csharp
builder.Services.AddMemoryCache();
builder.Services.AddFido2(o =>
{
    o.ServerDomain = builder.Configuration["WebAuthn:RpId"]!;
    o.ServerName   = builder.Configuration["WebAuthn:RpName"]!;
    o.Origins      = builder.Configuration.GetSection("WebAuthn:Origins").Get<HashSet<string>>()!;
});
```

## Endpoints (`Endpoints/Passkeys.cs`)
The pattern for both ceremonies:
```csharp
// options: create → cache JSON under a per-user key (5 min) → return it
// complete: TryGetValue → cache.Remove (single use, even if verification fails) → verify → persist
```
- **Registration:** `RequestNewCredential(new RequestNewCredentialParams { User, ExcludeCredentials, AuthenticatorSelection { UserVerification = Required, ResidentKey = Preferred }, AttestationPreference = None })`, then `MakeNewCredentialAsync(new MakeNewCredentialParams { AttestationResponse, OriginalOptions, IsCredentialIdUniqueToUserCallback })`. Store `Id`, `PublicKey`, `SignCount`.
- **Assertion:** options list only the caller's credentials. `complete` loads the passkey by **credential id AND user id**, then `MakeAssertionAsync(new MakeAssertionParams { AssertionResponse, OriginalOptions, StoredPublicKey, StoredSignatureCounter, IsUserHandleOwnerOfCredentialIdCallback })`. The library enforces origin, RP-id hash, challenge, signature, UV (because the options required it) and counter monotonicity; failures raise `Fido2VerificationException`, mapped to a uniform `400`.
- **Step-up token:** 32 random bytes → base64, stored in the cache as `stepup:<token> → username` for 5 minutes.
- `Passkeys.ConsumeStepUp(ctx, cache, username)` checks header presence, cache entry, **owner == caller**, then removes it (single use). `DELETE /api/me` returns `403` when it fails; otherwise removes likes, friendships, passkeys, blogs, then the user.

## Frontend
`@simplewebauthn/browser`: `startRegistration({ optionsJSON })` after `POST register/options`, and `startAuthentication({ optionsJSON })` → `assert/complete` → `DELETE /api/me` with `X-StepUp`, then `signoutRedirect()`. The API's JSON is passed straight through because it already is standard WebAuthn JSON.

## Deliberately left open
- Ceremony state and step-up tokens live in `IMemoryCache` – single instance only; production needs a distributed cache.
- No passkey management UI (rename/remove) and no recovery flow.
- Passkeys are step-up only; passwordless login belongs in the IdP (Keycloak WebAuthn Passwordless / Entra ID).
- `DELETE /api/me` removes rows one by one; a real system would soft-delete, audit (step 12) and anonymise.
- Authorisation between users is still missing → step 05.
