# Solution – 01 HTTPS

> Spoiler. Try the step yourself first: [`../01-https.md`](../01-https.md). Reference patch: `solutions/01-https.patch` (`patch -p1 < solutions/01-https.patch` from the repo root). Verified: both step tests pass and `01-https-check.sh` passes with the exported certificate.

## 1. Certificate
```bash
dotnet dev-certs https                      # create (once)
mkdir -p certs
dotnet dev-certs https --export-path certs/dev.pem --format Pem --no-password   # writes dev.pem + dev.key
```
Trust it (Arch/CachyOS):
```bash
sudo trust anchor --store certs/dev.pem     # system store (curl, .NET clients)
```
Chromium/Firefox keep their own store: import `certs/dev.pem` under *Settings → Certificates → Authorities*. For a quick curl check without touching the system store use `curl --cacert certs/dev.pem`.

## 2. Backend – `Program.cs`
```csharp
// Only allow modern TLS on every HTTPS endpoint Kestrel opens.
builder.WebHost.ConfigureKestrel(k => k.ConfigureHttpsDefaults(h =>
    h.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13));

builder.Services.AddHsts(o => { o.MaxAge = TimeSpan.FromDays(365); o.IncludeSubDomains = true; });
...
if (!app.Environment.IsDevelopment()) app.UseHsts();
app.UseHttpsRedirection();
```
(place both before `UseCors`/`UseStaticFiles`). `Properties/launchSettings.json`:
```json
"applicationUrl": "https://localhost:5443;http://localhost:5080"
```
Having an HTTPS address in the server URLs is also how the redirect middleware learns port 5443; outside launch profiles use `ASPNETCORE_URLS` or `https_port`.

## 3. Frontend
`src/api/client.ts`: `export const API_BASE = 'https://localhost:5443'`. `BlogCard.tsx` had a second hard-coded copy of the URL – it now uses `API_BASE`.

`vite.config.ts` reads the exported PEM files (kept out of git):
```ts
server: { port: 5173, https: { cert: fs.readFileSync('../certs/dev.pem'), key: fs.readFileSync('../certs/dev.key') } }
```

## Why the tests look the way they do
`TestServer` has no real sockets, so the redirect test tells the middleware the HTTPS port with `UseSetting("https_port", …)`. The HSTS test runs in `Production` against `https://seclab.example`, because HSTS is skipped for loopback hosts and for plain HTTP.

## Not done here (on purpose)
Secure cookies (no cookies yet), HSTS preload, real certificates – see Part 2.
