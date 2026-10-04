import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, setSession } from '../api/client'

export default function Login() {
  const [username, setUsername] = useState('alice')
  const [password, setPassword] = useState('password123')
  const [error, setError] = useState('')
  const nav = useNavigate()

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const { token, user } = await api.login(username, password)
      setSession(token, user)
      nav('/profile')
    } catch { setError('Login failed') }
  }

  return (
    <form onSubmit={submit} className="card narrow">
      <h2>Log in</h2>
      <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" />
      <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" />
      <button>Log in</button>
      {error && <p className="error">{error}</p>}
      <small>Seed users: alice, bob, carol, dave, eve — password123</small>
    </form>
  )
}
