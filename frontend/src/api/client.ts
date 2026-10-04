// Single place for all HTTP calls. Later tutorial steps change auth, base URL and versioning here.
export const API_BASE = 'https://localhost:5443'

export interface User {
  id: number; username: string; displayName: string; email: string; phone: string
  address: string; avatarUrl: string; bio: string; role: string
}
export interface Blog {
  id: number; authorId: number; authorName: string; authorAvatar: string
  title: string; body: string; createdAt: string; likes: number
}

// WEAKNESS: the "token" is just the user id and is kept in localStorage.
export const getToken = () => localStorage.getItem('token')
export const setSession = (token: string, user: User) => {
  localStorage.setItem('token', token)
  localStorage.setItem('user', JSON.stringify(user))
}
export const clearSession = () => { localStorage.removeItem('token'); localStorage.removeItem('user') }
export const currentUser = (): User | null => {
  const raw = localStorage.getItem('user')
  return raw ? JSON.parse(raw) : null
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  const token = getToken()
  if (token) headers.set('X-User-Id', token)
  if (init.body && !(init.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  const res = await fetch(API_BASE + path, { ...init, headers })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.status === 204 ? (undefined as T) : res.json()
}

export const api = {
  login: (username: string, password: string) =>
    request<{ token: string; user: User }>('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  user: (id: number) => request<User>(`/api/users/${id}`),
  updateUser: (id: number, u: User) => request<User>(`/api/users/${id}`, { method: 'PUT', body: JSON.stringify(u) }),
  friends: (id: number) => request<User[]>(`/api/users/${id}/friends`),
  uploadAvatar: (id: number, file: File) => {
    const fd = new FormData(); fd.append('file', file)
    return request<{ avatarUrl: string }>(`/api/users/${id}/avatar`, { method: 'POST', body: fd })
  },
  blogs: () => request<Blog[]>('/api/blogs'),
  search: (q: string) => request<Blog[]>(`/api/blogs/search?q=${encodeURIComponent(q)}`),
  createBlog: (authorId: number, title: string, body: string) =>
    request<Blog>('/api/blogs', { method: 'POST', body: JSON.stringify({ authorId, title, body }) }),
  likes: (id: number) => request<Blog[]>(`/api/users/${id}/likes`),
  timeline: () => request<Blog[]>('/api/timeline'),
  like: (blogId: number) => request<void>(`/api/blogs/${blogId}/like`, { method: 'POST' }),
  unlike: (blogId: number) => request<void>(`/api/blogs/${blogId}/like`, { method: 'DELETE' }),
}
