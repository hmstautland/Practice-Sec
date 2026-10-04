import { useEffect, useState } from 'react'
import { api, API_BASE, currentUser, setSession, getToken, type User } from '../api/client'

export default function Profile() {
  const me = currentUser()!
  const [user, setUser] = useState<User | null>(null)
  const [friends, setFriends] = useState<User[]>([])
  const [msg, setMsg] = useState('')

  useEffect(() => {
    api.user(me.id).then(setUser)
    api.friends(me.id).then(setFriends)
  }, [me.id])

  if (!user) return <p>Loading…</p>
  const set = (k: keyof User) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setUser({ ...user, [k]: e.target.value })
  const avatar = user.avatarUrl.startsWith('/') ? API_BASE + user.avatarUrl : user.avatarUrl

  const save = async () => {
    const updated = await api.updateUser(user.id, user)
    setSession(getToken()!, updated); setMsg('Saved')
  }
  const upload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]; if (!file) return
    const { avatarUrl } = await api.uploadAvatar(user.id, file)
    setUser({ ...user, avatarUrl })
  }

  return (
    <div className="grid">
      <section className="card">
        <h2>Profile</h2>
        <img src={avatar} alt="avatar" width={96} height={96} className="avatar" />
        <input type="file" onChange={upload} />
        <label>Display name<input value={user.displayName} onChange={set('displayName')} /></label>
        <label>Email<input value={user.email} onChange={set('email')} /></label>
        <label>Phone<input value={user.phone} onChange={set('phone')} /></label>
        <label>Address<input value={user.address} onChange={set('address')} /></label>
        <label>Bio<textarea value={user.bio} onChange={set('bio')} /></label>
        <button onClick={save}>Save</button> {msg}
      </section>
      <section className="card">
        <h2>Friends ({friends.length})</h2>
        <ul className="friends">
          {friends.map(f => (
            <li key={f.id}>
              <img src={f.avatarUrl.startsWith('/') ? API_BASE + f.avatarUrl : f.avatarUrl} alt="" width={32} height={32} />
              <div><strong>{f.displayName}</strong><br /><small>{f.email} · {f.phone}</small></div>
            </li>
          ))}
        </ul>
      </section>
    </div>
  )
}
