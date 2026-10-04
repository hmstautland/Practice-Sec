import { useEffect, useState } from 'react'
import BlogCard from '../BlogCard'
import { api, type Blog } from '../api/client'

export default function Timeline() {
  const [blogs, setBlogs] = useState<Blog[]>([])
  const load = () => api.timeline().then(setBlogs)
  useEffect(() => { load() }, [])
  const like = async (b: Blog) => { await api.like(b.id); load() }

  return (
    <div>
      <h2>Friends' timeline</h2>
      {blogs.length === 0 && <p>Your friends haven't posted anything.</p>}
      {blogs.map(b => <BlogCard key={b.id} blog={b} onLike={like} />)}
    </div>
  )
}
