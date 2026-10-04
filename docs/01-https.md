# 01 – HTTPS

> Prerequisites: the starter runs (`docs/00`), SQL Server container is up. Time: ~45 min.

## Goal
Make **all** traffic between browser, frontend and API travel over TLS, and make sure nobody can quietly downgrade it.

Acceptance criteria:

1. The API listens on **`https://localhost:5443`**. Requests to plain HTTP on `:5080` are answered with a **redirect (307/308) to the HTTPS URL**.
2. In any environment other than Development, HTTPS responses carry a `Strict-Transport-Security` header with **`max-age` of at least 180 days** (`15552000` s).
3. Kestrel accepts **TLS 1.2 and 1.3 only**.
4. The React app (`https://localhost:5173`) calls the API over HTTPS and the browser shows **no certificate warning** for either origin. All places that hard-code `http://localhost:5080` are gone.
5. No certificate or private key is committed to the repository (`certs/` is already git-ignored).

Out of scope: production certificates (Part 2), cookie flags (later steps), CORS (step 09).

## Threat / why
Everything the starter sends is readable and modifiable by anyone on the path: coffee-shop Wi-Fi, a compromised router, an ISP hop. Watch it happen:

```bash
python3 docs/attack-scripts/01-eavesdrop.py            # terminal 1: a passive observer on :5081 → :5080
curl -s -X POST http://localhost:5081/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"password123"}'  # terminal 2
```

Terminal 1 prints the username, the password and the "session token" in clear text. An active attacker can also *change* responses (inject script into the page, swap the JavaScript bundle). Later steps (OAuth2 tokens, API keys, WebAuthn) are pointless if the transport leaks them.

## Concepts
- **TLS** gives confidentiality, integrity and server authentication. The last one depends on the certificate being issued by an authority your client **trusts** and matching the host name.
- **Development certificates.** `dotnet dev-certs` creates a self-signed certificate for `localhost`. On Windows/macOS it can be trusted with one command; on **Linux there is no single trust store**, so you export the certificate and add it to the system store (and, for browsers such as Chromium/Firefox, to their own store). Read the "Trust the certificate" notes in the Microsoft Learn page linked below.
- **HTTPS redirection vs HSTS.** Redirecting `http → https` still exposes the first request. HSTS tells the browser "for the next N seconds, never even try HTTP for this host". It must only be sent over HTTPS, and ASP.NET Core deliberately skips it for `localhost`/loopback so you don't poison your dev browser.
- **ASP.NET Core building blocks:** the HTTPS redirection middleware needs to know *which* HTTPS port to redirect to (from server addresses or configuration); the HSTS middleware has its own options object (defaults are conservative).
- **Kestrel** owns the TLS handshake; protocol versions are configured on its HTTPS defaults, not in the middleware pipeline.
- **The client side:** the frontend's API base URL and the Vite dev server both matter. A page served over HTTPS that calls an HTTP API is blocked by browsers as *mixed content*.
- **TLS termination.** In production a reverse proxy / gateway (step 14, Part 2) often terminates TLS. The API then sees HTTP from the proxy and must trust `X-Forwarded-Proto` correctly — otherwise redirect loops or a false sense of security.

## Your turn
Tasks:
1. Create/trust a development certificate and make Kestrel serve it on port 5443 (keep 5080 for the redirect).
2. Add the redirect and HSTS to the request pipeline (correct order, correct environments).
3. Restrict Kestrel to TLS 1.2/1.3.
4. Serve the Vite dev server over HTTPS with the same certificate (do **not** copy the key into the repo) and point the API client at HTTPS.
5. Run the checks below until everything is green.

<details><summary>Hint 1 – where to look</summary>

`backend/src/SecLab.Api/Program.cs` (pipeline + Kestrel), `Properties/launchSettings.json` (URLs), `frontend/vite.config.ts`, `frontend/src/api/client.ts`, and search the frontend for `localhost:5080`.
</details>

<details><summary>Hint 2 – which APIs</summary>

`dotnet dev-certs https` (`--trust`, `--export-path`, `--format Pem`, `--no-password`); `UseHttpsRedirection`; `AddHsts` / `UseHsts` and `Environment.IsDevelopment()`; `WebHost.ConfigureKestrel(...).ConfigureHttpsDefaults(...)` with `SslProtocols`; Vite's `server.https` option.
</details>

<details><summary>Hint 3 – shape of the solution</summary>

Two services registrations/options (HSTS max-age, Kestrel TLS versions), two middleware calls placed before anything that serves content, one launch profile with two URLs, one exported PEM cert+key in the git-ignored `certs/` folder read by `vite.config.ts`, and one constant changed in the API client.
</details>

## Verify
Automated (red on the starter → green when done):
```bash
docker compose up -d sqlserver
dotnet test backend/SecLab.slnx --filter "Step=01"
```
Live check against the running API (start it with `dotnet run --project backend/src/SecLab.Api`):
```bash
bash docs/attack-scripts/01-https-check.sh
```
Then repeat the eavesdrop demo against the HTTPS port (`01-eavesdrop.py 5081 5443`, `curl -k https://localhost:5081/...`): the observer must see only unreadable bytes.

Checklist:
- [ ] `dotnet test --filter "Step=01"` passes (2 tests)
- [ ] `01-https-check.sh` prints only PASS (including "trusted cert" – this needs the certificate trusted by your OS/curl)
- [ ] Browser opens `https://localhost:5173`, logs in, all four pages load, DevTools shows no mixed-content or certificate errors
- [ ] `git status` shows no `.pem`/`.key` files

## Pitfalls
- ASP.NET's **default HSTS `max-age` is only 30 days** – the test will catch you if you forget to configure it.
- HSTS in Development is skipped for `localhost`; that is a feature. Test it with a non-localhost host name, as the test does.
- Middleware **order** matters: redirect/HSTS must run before static files and endpoints.
- If the redirect does nothing and the log says *"Failed to determine the https port for redirect"*, the middleware doesn't know your HTTPS port.
- Trusting the dev cert for the OS does not automatically trust it in Firefox/Chromium, and `curl` uses its own CA bundle (`--cacert`).
- Never enable `TrustServerCertificate`-style shortcuts on clients "just to make it work"; that recreates the problem.
- Do not commit the exported private key.
- `HSTS preload` and `includeSubDomains` are one-way doors for real domains – only use them when you are sure every subdomain supports HTTPS.

## Further reading
- Enforce HTTPS in ASP.NET Core – https://learn.microsoft.com/aspnet/core/security/enforcing-ssl
- Trust the ASP.NET Core HTTPS development certificate (Linux section) – same page
- Kestrel HTTPS configuration – https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel/endpoints
- .NET cryptography & TLS guidance – https://learn.microsoft.com/dotnet/standard/security/
- OWASP Transport Layer Security Cheat Sheet, OWASP HSTS Cheat Sheet

Stuck or done? Compare with the solution: [`docs/solutions/01-https.md`](solutions/01-https.md) and `solutions/01-https.patch`.
