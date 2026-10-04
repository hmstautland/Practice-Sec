// Step 17 – the SPA must hold no tokens. Source-level checks; the same idea for the production bundle is docs/attack-scripts/17-spa-token-scan.sh.
// (Why source checks at all? A browser cannot be asked "can a script read the token?" in a unit test – but the answer is always "no" if the token never reaches the page.)
import { describe, expect, it } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import config from '../vite.config'

const root = path.resolve(__dirname, '..')
const walk = (dir: string): string[] =>
  fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)])
const sources = walk(path.join(root, 'src')).filter(f => /\.(ts|tsx)$/.test(f)).map(f => ({ file: path.relative(root, f), text: fs.readFileSync(f, 'utf8') }))
const offenders = (re: RegExp) => sources.filter(s => re.test(s.text)).map(s => s.file)

type Proxy = Record<string, unknown> | undefined
const cfg = config as { server?: { proxy?: Proxy }; preview?: { proxy?: Proxy; headers?: Record<string, string> } }

describe('Step 17 – no credentials in JavaScript-accessible places', () => {
  it('does not use localStorage, sessionStorage, IndexedDB or document.cookie', () => {
    expect(offenders(/\b(localStorage|sessionStorage|indexedDB|document\.cookie)\b/)).toEqual([])
  })

  it('has no OpenID Connect / OAuth client library and no token handling', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'))
    const deps = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies })
    expect(deps.filter(d => /oidc|oauth|msal|auth0|keycloak|jwt/i.test(d))).toEqual([])
    expect(offenders(/oidc-client|userManager|signinRedirect|signoutRedirect/)).toEqual([])
    expect(offenders(/access_token|refresh_token|id_token|\bBearer\b|['"]Authorization['"]/i)).toEqual([])
  })

  it('never contacts the identity provider or the gateway origin itself: everything goes to its own origin', () => {
    expect(offenders(/localhost:8081|localhost:5443|\/realms\//)).toEqual([])
  })

  it('logs in, asks who it is and logs out through the BFF endpoints', () => {
    const all = sources.map(s => s.text).join('\n')
    expect(all).toContain('/bff/login')
    expect(all).toContain('/bff/user')
    expect(all).toContain('/bff/logout')
  })

  it('sends the CSRF header on every API request and no longer keeps a Callback route', () => {
    const client = fs.readFileSync(path.join(root, 'src/api/client.ts'), 'utf8')
    expect(client).toMatch(/X-CSRF/)
    expect(fs.existsSync(path.join(root, 'src/pages/Callback.tsx'))).toBe(false)
    expect(fs.existsSync(path.join(root, 'src/api/auth.ts'))).toBe(false)
  })
})

describe('Step 17 – one origin for the page and the BFF', () => {
  it('forwards /bff, /api and /avatars to the gateway in dev and in preview', () => {
    for (const proxy of [cfg.server?.proxy, cfg.preview?.proxy]) {
      expect(Object.keys(proxy ?? {}).sort()).toEqual(['/api', '/avatars', '/bff'])
    }
  })

  it('tightens the CSP of step 13: connect-src and img-src name no API or IdP origin', () => {
    const csp = Object.fromEntries((cfg.preview?.headers?.['Content-Security-Policy'] ?? '').split(';').map(s => s.trim()).filter(Boolean).map(d => {
      const [name, ...values] = d.split(/\s+/); return [name, values]
    }))
    expect(csp['connect-src']).toEqual(["'self'"])
    expect(csp['img-src'] ?? []).not.toContain('https://localhost:5443')
  })

  it('isolates the browsing context (COOP) and its responses (CORP)', () => {
    expect(cfg.preview?.headers?.['Cross-Origin-Opener-Policy']).toBe('same-origin')
    expect(cfg.preview?.headers?.['Cross-Origin-Resource-Policy']).toBe('same-origin')
  })
})
