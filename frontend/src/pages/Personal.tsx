import { useEffect, useState } from 'react'
import BlogCard from '../BlogCard'
import { api, currentUser, type Blog } from '../api/client'

export default function Personal() {
  const me = currentUser()!
  const [blogs, setBlogs] = useState<Blog[]>([])
  const load = () => api.likes(me.id).then(setBlogs)
  useEffect(() => { load() }, [])
  const unlike = async (b: Blog) => { await api.unlike(b.id); load() }

  return (
    <div>
      <h2>Blogs I've liked</h2>
      {blogs.length === 0 && <p>Nothing liked yet.</p>}
      {blogs.map(b => (
        <div key={b.id}><BlogCard blog={b} /><button onClick={() => unlike(b)}>Unlike</button></div>
      ))}
    </div>
  )
}
