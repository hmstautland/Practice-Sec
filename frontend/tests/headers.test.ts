// Step 13 – the built SPA must be served with a strict Content-Security-Policy. `vite preview` serves the production build,
// so its headers are what we check here (the dev server needs inline scripts for hot reload and cannot use this policy).
import { describe, expect, it } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import config from '../vite.config'

const headers = (config as { preview?: { headers?: Record<string, string> } }).preview?.headers ?? {}
const csp = Object.fromEntries((headers['Content-Security-Policy'] ?? '').split(';').map(s => s.trim()).filter(Boolean).map(d => {
  const [name, ...values] = d.split(/\s+/); return [name, values]
}))

describe('SPA security headers', () => {
  it('defines a CSP without unsafe script sources', () => {
    expect(csp['default-src']).toEqual(["'self'"])
    expect(csp['script-src']).toEqual(["'self'"])
    expect(JSON.stringify(csp['script-src'])).not.toMatch(/unsafe/)
  })
  it('locks down objects, base URI, framing and forms', () => {
    expect(csp['object-src']).toEqual(["'none'"])
    expect(csp['base-uri']).toEqual(["'none'"])
    expect(csp['frame-ancestors']).toEqual(["'none'"])
    expect(csp['form-action']).toEqual(["'self'"])
  })
  it('allows connections only to the API and the identity provider', () => {
    expect([...csp['connect-src']].sort()).toEqual(["'self'", 'http://localhost:8081', 'https://localhost:5443'].sort())
  })
  it('sets the companion headers', () => {
    expect(headers['X-Content-Type-Options']).toBe('nosniff')
    expect(headers['Referrer-Policy']).toBe('no-referrer')
    expect(headers['Permissions-Policy']).toContain('camera=()')
  })
  it('has no inline scripts in index.html (a CSP without unsafe-inline would block them)', () => {
    const html = fs.readFileSync(path.resolve(__dirname, '../index.html'), 'utf8')
    for (const tag of html.match(/<script\b[^>]*>/gi) ?? []) expect(tag).toMatch(/\bsrc=/)
    expect(html).not.toMatch(/\son\w+=/i)
  })
})
