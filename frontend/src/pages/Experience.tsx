import { useEffect, useState } from 'react'
import BlogCard from '../BlogCard'
import { api, currentUser, type Blog } from '../api/client'

export default function Experience() {
  const me = currentUser()!
  const [blogs, setBlogs] = useState<Blog[]>([])
  const [q, setQ] = useState('')
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')

  const load = () => (q ? api.search(q) : api.blogs()).then(setBlogs)
  useEffect(() => { load() }, [])
  const like = async (b: Blog) => { await api.like(b.id); load() }
  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    await api.createBlog(me.id, title, body)
    setTitle(''); setBody(''); load()
  }

  return (
    <div>
      <h2>Experience — blogs from everyone</h2>
      <form onSubmit={create} className="card">
        <input value={title} onChange={e => setTitle(e.target.value)} placeholder="Title" />
        <textarea value={body} onChange={e => setBody(e.target.value)} placeholder="Write something (HTML allowed)…" />
        <button>Publish</button>
      </form>
      <div className="search">
        <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search blogs" />
        <button onClick={load}>Search</button>
      </div>
      {blogs.map(b => <BlogCard key={b.id} blog={b} onLike={like} />)}
    </div>
  )
}
