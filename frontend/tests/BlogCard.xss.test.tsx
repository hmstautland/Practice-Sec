// Step 10 – output encoding. Run with:  npm test   (after installing the test tooling, see docs/10-input-validation.md)
import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, render } from '@testing-library/react'
import BlogCard from '../src/BlogCard'
import type { Blog } from '../src/api/client'

const blog = (over: Partial<Blog>): Blog => ({
  id: 1, authorId: 1, authorName: 'Alice', authorAvatar: 'https://example.com/a.png',
  title: 'Hello', body: '<p>hi</p>', createdAt: new Date().toISOString(), likes: 0, ...over,
})

declare global { interface Window { __xss?: number } }

afterEach(() => { cleanup(); delete window.__xss })

describe('BlogCard output encoding', () => {
  it('keeps harmless formatting', () => {
    const { container } = render(<BlogCard blog={blog({ body: '<p>hi <strong>there</strong></p>' })} />)
    expect(container.querySelector('p strong')?.textContent).toBe('there')
  })

  it('never renders script elements', () => {
    const { container } = render(<BlogCard blog={blog({ body: '<p>ok</p><script>window.__xss=2</script>' })} />)
    expect(container.querySelector('script')).toBeNull()
    expect(window.__xss).toBeUndefined()
  })

  it('drops event-handler attributes', () => {
    const { container } = render(<BlogCard blog={blog({ body: '<p onclick="window.__xss=1">x</p><img src="x" onerror="window.__xss=3">' })} />)
    expect(container.innerHTML.toLowerCase()).not.toContain('onerror')
    expect(container.innerHTML.toLowerCase()).not.toContain('onclick')
  })

  it('drops javascript: links and frames', () => {
    const { container } = render(<BlogCard blog={blog({ body: '<a href="javascript:window.__xss=4">x</a><iframe src="https://evil.example"></iframe>' })} />)
    expect(container.innerHTML.toLowerCase()).not.toContain('javascript:')
    expect(container.querySelector('iframe')).toBeNull()
  })

  it('shows titles and author names as text, never as markup', () => {
    const { container } = render(<BlogCard blog={blog({ title: '<img src=x onerror=alert(1)>', authorName: '<b>Mallory</b>' })} />)
    expect(container.querySelector('h3')?.textContent).toBe('<img src=x onerror=alert(1)>')
    expect(container.querySelector('h3 img')).toBeNull()
    expect(container.querySelector('.author b')).toBeNull()
  })
})
