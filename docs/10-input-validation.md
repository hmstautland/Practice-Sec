# 10 – Input validation and output encoding

> Prerequisites: steps 01–09 done (or apply patches `01`–`09`). Time: 2–3 hours. No schema change.
> Setup for the frontend tests (once): `cd frontend && npm i -D vitest jsdom @testing-library/react @testing-library/dom` and add a `"test": "vitest run"` script and a `test` section to `vite.config.ts` (`environment: 'jsdom'`, `include: ['tests/**/*.test.tsx']`).

## Goal
Treat **every byte from outside as hostile**: validate it at the boundary, reject what doesn't fit, sanitise the one field that legitimately carries markup, and encode on output – so injection, stored XSS and resource abuse have nowhere to land.

Rules (the tests encode them):

**Registration** (`POST /api/auth/register`)
- `username`: 3–32 characters, **ASCII** letters/digits/underscore only (homoglyphs like Cyrillic "а" are rejected).
- `password`: 12–128 characters. `email`: ≤ 254, one `@`, no whitespace or `<>`. `displayName`: 1–60, plain text (no `<` or `>`).

**Profile update** (`PUT /api/users/{id}`; every field optional, but if present it must be valid)
- `displayName` 1–60 plain text · `email` as above · `phone` `+`, digits, space, `()`, `-`, 6–20 chars · `address` ≤ 200 plain text · `bio` ≤ 500 plain text. A rejected update changes **nothing**.

**Blogs** (create, edit, and the partner/API-key route – *every* write path)
- `title` 1–120, plain text, whitespace-only rejected; `body` 1–10 000 characters.
- `body` is HTML, but only a **safe subset survives**: `p br b i u strong em ul ol li a code pre blockquote h1–h4`; only `href` attributes, only `http`, `https`, `mailto` links; no scripts, event handlers, styles, frames, forms, SVG/MathML, images, objects. Sanitising happens **before storing**.

**Everything else**
- A validation failure is a **`400` problem-details JSON** with `status: 400` and an `errors` object keyed by field – and it never echoes the raw input back.
- Malformed JSON, wrong JSON types and empty bodies → `400`; a non-JSON content type → `415`; never `500`.
- `GET /api/blogs/search?q=`: `q` required, 1–100 characters.
- References must exist: liking a non-existent blog → `404` (and no orphan row).

**Frontend** (`frontend/tests/BlogCard.xss.test.tsx`, 5 tests): the browser sanitises blog HTML **again** before inserting it (defence in depth); titles and author names are always rendered as text.

Out of scope: SQL injection in the search endpoint (step 15 – you'll see it survive this step), CSP and other headers (step 13), error-format polish (step 11).

## Threat / why
Injection is what happens when data is interpreted as code: HTML/JS in a blog body (**stored XSS**, W8 – with a token in `sessionStorage` an XSS is an account takeover), markup in names shown elsewhere, oversize strings that exhaust memory or storage, homoglyph usernames that impersonate other users, malformed bodies that crash handlers into leaking 500 pages. Validation is also *cheap authorization*: fewer states the rest of the code must reason about.

```bash
bash docs/attack-scripts/10-injection-inputs.sh
```

## Concepts
- **Validate at the boundary, on the server.** Client-side checks are UX, not security. Prefer **allow-lists** (`^[A-Za-z0-9_]{3,32}$`) over deny-lists; check **type, length, format, range** and business rules; **reject rather than "fix"** (silent rewriting hides attacks and causes surprises), except where the field is explicitly rich text.
- **DTOs per operation.** Input types describe exactly what you accept (step 05 already stopped binding entities). Put constraints on the type so they can't be forgotten per endpoint. **.NET 10 has built-in minimal-API validation** (`AddValidation()`) that runs `System.ComponentModel.DataAnnotations` on endpoint parameters and returns a standard `400` problem-details payload; alternatives are FluentValidation or hand-written validators. Read how opt-out works – library types may not suit DataAnnotations.
- **Canonicalise before you validate** (Unicode normalisation, trimming, case) and validate the *canonical* form; regexes need anchors and, for user-controlled patterns, timeouts (ReDoS).
- **Validation ≠ sanitising ≠ encoding.** *Validation* decides accept/reject. *Sanitising* rewrites rich content to a safe subset (HTML sanitiser with an allow-list, e.g. the `HtmlSanitizer` NuGet package). *Output encoding* makes data inert in its destination context (HTML text, attribute, URL, JS, CSS each need different encoding). JSON serialisation encodes for JSON; React text nodes encode for HTML text; `dangerouslySetInnerHTML` bypasses both.
- **Defence in depth for HTML:** sanitise on write (protect every consumer: mobile apps, exports, admin UIs), sanitise/encode again on read in the UI (protects against old data and future bugs). DOMPurify is the standard browser-side sanitiser.
- **Mass assignment & overposting** are validation problems too (fixed with DTOs in step 05).
- **Transport-level limits:** request size (Kestrel), JSON depth, content-type checks, timeouts. Minimal APIs already answer `415`/`400` for wrong types when you declare typed parameters – check what happens for your own edge cases.
- **Error responses:** field-level messages, no stack traces, no echo of hostile input (reflected XSS in JSON is rare but log-injection and confused clients are not).
- **Second-order injection:** data that passed today's validation but is later used in a query, a file name, a header or a log line. Validation doesn't replace parameterised queries (step 15) or log encoding (step 12).

## Your turn
Tasks:
1. Describe every request body/parameter as a typed contract with constraints; wire up automatic validation and problem-details errors.
2. Add an HTML sanitiser with the allow-list above; use it on **all** blog write paths.
3. Make the "like" endpoint check that the target exists.
4. Frontend: sanitise before `dangerouslySetInnerHTML`; install the test tooling and get the 5 tests green.
5. Run the backend tests, the frontend tests and the attack script. Try to break your own sanitiser with payloads from the OWASP XSS Filter Evasion cheat sheet.

<details><summary>Hint 1 – where to look</summary>

`Endpoints/Api.cs` (register, profile, blogs, search, like), `Endpoints/ApiKeys.cs` (partner route), a new `Validation/` folder, `Program.cs`, `frontend/src/BlogCard.tsx`, `frontend/package.json`, `vite.config.ts`.
</details>

<details><summary>Hint 2 – which APIs</summary>

`builder.Services.AddValidation()` (.NET 10) + attributes `[Required] [StringLength(max, MinimumLength = n)] [RegularExpression]` (on records use `[property: …]`); `[Required, StringLength(…)]` directly on query parameters; `.DisableValidation()` on routes whose body type isn't yours; NuGet `HtmlSanitizer` (`Ganss.Xss.HtmlSanitizer`: `AllowedTags`, `AllowedAttributes`, `AllowedSchemes`, `PostProcessNode`); npm `dompurify` (`ALLOWED_TAGS`, `ALLOWED_ATTR`, `ALLOWED_URI_REGEXP`).
</details>

<details><summary>Hint 3 – shape of the solution</summary>

One file with the contracts (regex constants shared), one singleton `ContentSanitizer` with a strict configuration, endpoints that take the contract types and call the sanitiser exactly where a body is stored. Run the *whole* suite afterwards: stricter validation legitimately breaks earlier tests that used sloppy sample data (e.g. `phone = "1"`) – and may break routes that take external library types.
</details>

## Verify
```bash
dotnet test backend/SecLab.slnx --filter "Step=10"        # 39 test cases incl. 12 XSS payloads × 3 write paths
cd frontend && npm test                                   # 5 tests (red until BlogCard sanitises)
bash docs/attack-scripts/10-injection-inputs.sh
```
Checklist:
- [ ] Backend `Step=10` green; the full suite still green
- [ ] `npm test` 5/5 and `npm run build` passes
- [ ] The script prints `<p>hello</p>` + a harmless link (no script/img/iframe/`javascript:`), `400 400`, `400 400 415`, field-keyed errors, `404`
- [ ] No 500 in any of the malformed cases (check the server log)
- [ ] `git grep dangerouslySetInnerHTML` shows exactly one use, fed by the sanitiser

## Pitfalls
- Sanitising on **only one** of the write paths (the API-key route and the edit route are the usual forgotten ones).
- Blocklists (`if body.Contains("<script")`) – trivially bypassed (`<ScRiPt>`, `<img onerror>`, SVG, entities). Allow-list tags, attributes **and URL schemes**.
- Validating after using the value; validating the raw form but using the normalised one.
- `RegularExpression` without anchors, or catastrophic-backtracking patterns.
- Relying on `[EmailAddress]` alone (very permissive) – decide what "valid" means for your app; the only proof an address works is sending mail to it.
- Turning the validation pipeline on and forgetting it also inspects **third-party request types** (the WebAuthn completion routes broke in the reference solution until validation was disabled for them).
- Echoing invalid input in error messages.
- Forgetting that stricter validation changes contracts: bump the API version (step 08) if clients rely on the old leniency.
- Sanitising for HTML but then putting the value into an attribute, a URL or JavaScript – context matters.
- Storing HTML "encoded twice" because both layers encode; sanitise (not escape) rich text, escape plain text once, at the output.

## Further reading
- Minimal API validation in ASP.NET Core 10 – https://learn.microsoft.com/aspnet/core/fundamentals/minimal-apis
- Model validation and DataAnnotations – https://learn.microsoft.com/aspnet/core/mvc/models/validation
- Prevent Cross-Site Scripting (XSS) in ASP.NET Core – https://learn.microsoft.com/aspnet/core/security/cross-site-scripting
- .NET security overview – https://learn.microsoft.com/dotnet/standard/security/
- OWASP Input Validation, XSS Prevention, DOM-based XSS Prevention and XSS Filter Evasion Cheat Sheets; OWASP API Security Top 10 (API3, API8)

Stuck or done? Compare with the solution: [`docs/solutions/10-input-validation.md`](solutions/10-input-validation.md) and `solutions/10-input-validation.patch` (applies on top of 01–09).
