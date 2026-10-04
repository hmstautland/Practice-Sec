import { BrowserRouter, NavLink, Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import Login from './pages/Login'
import Profile from './pages/Profile'
import Personal from './pages/Personal'
import Timeline from './pages/Timeline'
import Experience from './pages/Experience'
import { clearSession, currentUser } from './api/client'

function Guard({ children }: { children: React.ReactElement }) {
  return currentUser() ? children : <Navigate to="/login" />
}

function Nav() {
  const nav = useNavigate()
  const user = currentUser()
  if (!user) return null
  return (
    <nav>
      <NavLink to="/profile">Profile</NavLink>
      <NavLink to="/personal">Personal</NavLink>
      <NavLink to="/timeline">Timeline</NavLink>
      <NavLink to="/experience">Experience</NavLink>
      <span className="spacer" />
      <span>{user.displayName}</span>
      <button onClick={() => { clearSession(); nav('/login') }}>Log out</button>
    </nav>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Nav />
      <main>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/profile" element={<Guard><Profile /></Guard>} />
          <Route path="/personal" element={<Guard><Personal /></Guard>} />
          <Route path="/timeline" element={<Guard><Timeline /></Guard>} />
          <Route path="/experience" element={<Guard><Experience /></Guard>} />
          <Route path="*" element={<Navigate to="/profile" />} />
        </Routes>
      </main>
    </BrowserRouter>
  )
}
