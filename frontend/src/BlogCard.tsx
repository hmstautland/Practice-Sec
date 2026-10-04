import { API_BASE, type Blog } from './api/client'

export default function BlogCard({ blog, onLike }: { blog: Blog; onLike?: (b: Blog) => void }) {
  return (
    <article className="card">
      <header className="author">
        <img src={blog.authorAvatar.startsWith('/') ? `${API_BASE}${blog.authorAvatar}` : blog.authorAvatar} alt="" width={32} height={32} />
        <strong>{blog.authorName}</strong>
        <small>{new Date(blog.createdAt).toLocaleString()}</small>
      </header>
      <h3>{blog.title}</h3>
      {/* WEAKNESS: renders raw HTML from the database (stored XSS). */}
      <div dangerouslySetInnerHTML={{ __html: blog.body }} />
      <footer>
        ♥ {blog.likes} {onLike && <button onClick={() => onLike(blog)}>Like</button>}
      </footer>
    </article>
  )
}
