# Solution – 10 Input validation and output encoding

> Spoiler. Try the step yourself first: [`../10-input-validation.md`](../10-input-validation.md). Patch: `solutions/10-input-validation.patch` (after 01–09). New packages: `HtmlSanitizer` 9.2.1039 (API), `dompurify`, `vitest`, `jsdom`, `@testing-library/*` (frontend).

## What was verified
- **144 backend tests** (steps 01–10) pass on a fresh database.
- **Frontend:** the 5 XSS tests pass with the solution (`npm test`) and 3 of them fail on the previous `BlogCard` (red → green); `npm run build` passes.
- Live `10-injection-inputs.sh` against real Keycloak tokens: the hostile post came back as `<p>hello</p><a rel="noopener noreferrer nofollow">click</a>` (the `javascript:` href was dropped, script/img/iframe removed); markup in title/display name → 400; oversized → 400, malformed JSON → 400, `text/plain` → 415; registration errors keyed by field without echoing input; like on a missing blog → 404.

## Contracts (`Validation/Contracts.cs`)
Records with DataAnnotations on the properties, shared regex constants:
```csharp
public record CreateBlog(
    [property: Required, StringLength(120, MinimumLength = 1), RegularExpression(Rx.PlainText)] string? Title,
    [property: Required, StringLength(10_000, MinimumLength = 1)] string? Body);
```
`RegisterRequest`, `UpdateProfile`, `CreateBlog`, `EditBlog` live here (the partner route reuses `CreateBlog`). `Program.cs` adds `builder.Services.AddValidation();` – the .NET 10 minimal-API validation pipeline validates bound parameters and answers `400` with `ValidationProblem` (`status`, `errors` keyed by field; messages contain rules, not the offending value).
- `Required` on a string also rejects whitespace-only input.
- Search: `[Required, StringLength(100, MinimumLength = 1)] string q` directly on the parameter.
- The register endpoint lost its hand-written checks from step 02.
- `Passkeys` completion routes call `.DisableValidation()`: their body types come from the Fido2 library, and DataAnnotations on them rejected valid ceremonies (all step-04 tests failed until this was added).

## Sanitiser (`Validation/ContentSanitizer.cs`)
`Ganss.Xss.HtmlSanitizer` configured from empty: tags `p br b i u strong em ul ol li a code pre blockquote h1–h4`; attributes `href` only; schemes `https http mailto`; no CSS properties; a `PostProcessNode` hook adds `rel="noopener noreferrer nofollow"` to anchors. A singleton is used from `POST /blogs`, `PUT /blogs/{id}` and `POST /partner/blogs`. Titles are trimmed. `POST`/`PUT` now return small objects instead of the entity.

## Reference check
`POST /api/blogs/{id}/like` checks `Blogs.AnyAsync` first → `404`.

## Frontend
`BlogCard.tsx`: `DOMPurify.sanitize(body, { ALLOWED_TAGS, ALLOWED_ATTR: ['href'], ALLOWED_URI_REGEXP: /^(?:https?|mailto):/i })` before `dangerouslySetInnerHTML`; title and names stay text nodes. `vite.config.ts` imports `defineConfig` from `vitest/config` and adds `test: { environment: 'jsdom', include: ['tests/**/*.test.tsx'] }`; `package.json` gets `"test": "vitest run"`.

## Things that surfaced while building it
- Stricter validation **broke two earlier tests** (their sample phone number was `"1"`). The test data was corrected; in a real API this is exactly when you would bump the API version.
- Validation runs **before** the handler, so an invalid body from a user who lacks permission gets `400` instead of `403`. That is acceptable here (nothing sensitive leaks), but be aware of it if you want "authorise first" semantics.
- Error keys are capitalised property names (`Username`), not camelCase – the tests compare case-insensitively.

## Deliberately left open
- `GET /api/blogs/search` still concatenates SQL (step 15) – validation shortens the payload but does not stop injection.
- Sanitising is allow-list based but not re-run on old rows; migrate existing data if you introduce it late.
- No image support in posts (which would need URL allow-listing and a proxy).
- No Unicode normalisation / confusable detection beyond restricting usernames to ASCII.
