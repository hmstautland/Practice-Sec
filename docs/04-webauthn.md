# 04 – WebAuthn / passkeys

> Prerequisites: steps 01–03 done (or apply patches `01`–`03`). Time: 3–4 hours. New table → run `bash docs/reset-database.sh` after adding the model.
> No Keycloak needed for the tests. For the browser you need a passkey-capable authenticator (Windows Hello, Touch ID, Android, a YubiKey, or Chrome DevTools' *WebAuthn* virtual authenticator).

## Goal
Add a **phishing-resistant second proof** for dangerous actions. A stolen bearer token (or a phished password) must not be enough to do irreversible damage.

You implement the **WebAuthn relying party** in the API and use it for **step-up authentication**: a signed-in user registers a passkey, and can then earn a short-lived *step-up token* by performing a passkey assertion. The endpoint that deletes the account demands that token.

Contract (the tests depend on it):

| Route | Auth | Behaviour |
|---|---|---|
| `POST /api/passkeys/register/options` | bearer | Returns WebAuthn *creation options* JSON (`challenge`, `rp.id`, `user`, `authenticatorSelection`, `excludeCredentials`, …). RP id **`localhost`**, user verification **required**. |
| `POST /api/passkeys/register/complete` | bearer | Body is the standard `PublicKeyCredential` JSON (`id`, `rawId`, `type`, `response.attestationObject`, `response.clientDataJSON`). `200` on success, **`400`** on any verification failure. |
| `POST /api/passkeys/assert/options` | bearer | Returns *request options* (`challenge`, `allowCredentials` …). `400` if the user has no passkey. |
| `POST /api/passkeys/assert/complete` | bearer | Body: `PublicKeyCredential` JSON with `authenticatorData`, `clientDataJSON`, `signature`. `200` + `{ "stepUpToken": "…", "expiresIn": … }`, `400` on failure. |
| `DELETE /api/me` | bearer **+ `X-StepUp` header** | Deletes the current user and their data → `204`. Missing, unknown, expired, already used or *someone else's* step-up token → **`403`**. |

Requirements behind the table:

1. Configuration keys **`WebAuthn:RpId`** (`localhost`), **`WebAuthn:RpName`**, **`WebAuthn:Origins`** (`["https://localhost:5173"]`).
2. A ceremony **challenge is random, bound to the user, expires (minutes) and is single-use** – also when verification fails.
3. Registration and assertion are rejected for: a foreign **origin**, a different **RP id**, a challenge the server did not issue, a missing **user-verification** flag, a signature made with another key, and a **signature counter that does not increase**.
4. A credential can only be used by the user who registered it.
5. The step-up token is high-entropy, **short-lived, single-use, bound to the user** who earned it.
6. Only public keys and metadata are stored – never secrets. The WebAuthn *user handle* is an opaque random id, not a name or e-mail.
7. Frontend: an "Add a passkey" button and a "Delete my account" button that performs the step-up before calling the API.

Out of scope: passkeys as the *primary* login (that belongs in the IdP – see Concepts), attestation trust chains, account recovery flows.

## Threat / why
Passwords and bearer tokens are *replayable secrets*: whoever holds them is you. Phishing sites, infostealer malware, a leaked log line or an XSS bug (W8 is still open!) hand attackers exactly that.

```bash
bash docs/attack-scripts/04-stolen-token.sh
```
The attacker holds only eve's bearer token. Before this step there is no protected action; the script shows what "token = full control" would mean and that after step 04 the destructive call needs proof that the *human* is present.

WebAuthn changes the economics: the private key never leaves the authenticator, every signature covers the **origin** the browser is talking to (a look-alike domain gets nothing usable), and each ceremony has a fresh challenge (no replay).

## Concepts
- **Two ceremonies.** *Registration* (attestation): the authenticator creates a key pair for this RP and returns the public key + credential id. *Authentication* (assertion): the RP sends a challenge; the authenticator signs `authenticatorData ‖ SHA-256(clientDataJSON)`.
- **Relying-party id and origin.** The RP id (a registrable domain suffix, no scheme/port) scopes credentials; `authenticatorData` contains its SHA-256, `clientDataJSON` contains the origin. The server must check *both* against configuration, plus `type` (`webauthn.create` / `webauthn.get`) and the challenge.
- **Challenge:** ≥16 random bytes from a CSPRNG, stored server-side, used once, with a lifetime. Where you keep it (memory cache, distributed cache, DB) matters once you scale out.
- **UP vs UV.** *User present* = something touched it; *user verified* = biometric/PIN. Step-up should demand UV; asking for it in the options is not the same as checking the flag.
- **Signature counter:** a monotonically increasing value that helps detect cloned authenticators. Many synced passkeys always report 0 – know what your library does with that.
- **Attestation:** proof of *what kind* of authenticator made the key. Consumer apps normally use `none`; enterprise policy may require more. Don't ask for attestation you won't verify.
- **Discoverable credentials / resident keys** enable username-less sign-in; **backup eligible / backup state** flags tell you whether a passkey syncs between devices.
- **Don't hand-roll.** WebAuthn parsing (CBOR, COSE keys, formats) is easy to get subtly wrong. The mature .NET library is **Fido2NetLib** (NuGet package id `Fido2`, plus `Fido2.AspNet` for DI). Check which major version you install – the API changed between versions.
- **Step-up authentication:** raise the assurance level *when the action is risky*, not on every request. The result is a separate, short-lived proof rather than a new session.
- **Where should primary passkey login live?** Your API is now an OAuth resource server (step 03); it does not issue sessions. Passwordless/passkey **login** is best enabled in the IdP (Keycloak has a WebAuthn Passwordless policy, Entra ID has passkeys). Building your own RP, as here, teaches the protocol and suits step-up/transaction-signing.
- **Browser side:** `navigator.credentials.create/get` need base64url ⇄ ArrayBuffer conversions; libraries such as `@simplewebauthn/browser` do that and accept the same JSON the server returns.

## Your turn
Tasks:
1. Add a table for passkeys (credential id, public key, counter, user handle, owner, created) and the configuration.
2. Register the WebAuthn library with your RP settings; implement the four passkey endpoints and their challenge handling.
3. Implement `DELETE /api/me` behind the step-up rule.
4. Make the tests pass, then wire up the UI and try it with a real (or virtual) authenticator.

<details><summary>Hint 1 – where to look</summary>

`Models/Models.cs` + `Data/AppDbContext.cs` (new entity, unique index on credential id – mind SQL Server's index key size limit for `byte[]`), `Program.cs` (services), a new endpoints file next to `Api.cs`, `IMemoryCache` for short-lived state.
</details>

<details><summary>Hint 2 – which APIs</summary>

NuGet `Fido2.AspNet` → `AddFido2(...)` (`ServerDomain`, `ServerName`, `Origins`), then inject `IFido2`. In v4 the calls take parameter objects: `RequestNewCredential`, `MakeNewCredentialAsync`, `GetAssertionOptions`, `MakeAssertionAsync`; options objects can round-trip through `ToJson()` / `FromJson()`. Catch the library's verification exception and answer `400` without leaking details. Step-up token: `RandomNumberGenerator.GetBytes(32)`; remember `TryGetValue` + `Remove`.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

Options endpoints create options → cache their JSON under a per-user key with an expiry → return them. Complete endpoints **remove** the cached options first, then verify, then persist (register) or bump the stored counter and mint the token (assert). The credential lookup filters by *both* credential id and current user. `DELETE /api/me` reads `X-StepUp`, checks it against a cache entry that names the caller, removes it, then deletes the user's rows in a safe order.
</details>

## Verify
```bash
bash docs/reset-database.sh
dotnet test backend/SecLab.slnx --filter "Step=04"     # 16 tests, driven by a software authenticator (tests/SoftAuthenticator.cs)
bash docs/attack-scripts/04-stolen-token.sh            # after the step: 200, 403, 403
```
`SoftAuthenticator` builds real attestation objects (CBOR/COSE) and ES256 signatures, so the whole ceremony is exercised without a browser.

Manual: `npm run dev`, log in, open Chrome DevTools → *More tools → WebAuthn* → enable a virtual authenticator (CTAP2, internal, resident key, user verification on), click **Add a passkey**, then **Delete my account** with a throw-away user (e.g. register `eve`, then delete). Try deleting again from a second tab with the same step-up token in a `curl` – it must fail.

Checklist:
- [ ] `Step=04` (16) green; steps 01–03 still green
- [ ] Attack script prints `200 403 403`
- [ ] Passkey table contains public keys only; user handle is random
- [ ] Wrong origin / wrong RP id / stale challenge / replay / bad signature / non-increasing counter all give `400`
- [ ] Step-up token: works once, only for its owner, dies after minutes

## Pitfalls
- Verifying the signature but not the **origin** or **RP id** – exactly the phishing protection you wanted.
- Reusing a challenge, or keeping it only client-side.
- Checking `userVerification` in the *options* but never the **UV flag** in the response. Test what your library does; then test again after upgrading it.
- Treating counter `0` on every assertion as an attack for synced passkeys (or, the opposite, ignoring the counter completely).
- A user handle derived from the username/e-mail (it's not secret, but it is stored on devices and shown in account choosers).
- `IMemoryCache` is per-process: behind two instances a ceremony can start on one and finish on the other. Use a distributed cache/DB in real deployments.
- RP id vs dev hostnames: credentials created for `localhost` won't work on `127.0.0.1` or a LAN name.
- Returning different errors for "unknown credential" vs "bad signature" – keep them uniform.
- Forgetting to remove/rotate rows on account deletion (likes, friendships, passkeys) leaves orphans.
- No recovery path: users who lose their only passkey need a policy (second passkey, backup codes, IdP recovery).

## Further reading
- Fido2NetLib – https://github.com/passwordless-lib/fido2-net-lib
- Passkeys / WebAuthn in ASP.NET Core Identity (new in .NET 10; check current docs) – https://learn.microsoft.com/aspnet/core/security/authentication/identity
- W3C Web Authentication Level 3 – https://www.w3.org/TR/webauthn-3/ ; FIDO Alliance passkey resources
- .NET security overview – https://learn.microsoft.com/dotnet/standard/security/
- OWASP Authentication Cheat Sheet, Multifactor Authentication Cheat Sheet

Stuck or done? Compare with the solution: [`docs/solutions/04-webauthn.md`](solutions/04-webauthn.md) and `solutions/04-webauthn.patch` (applies on top of 01–03).
