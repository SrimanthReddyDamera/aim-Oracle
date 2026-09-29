import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { Activity, ArrowRight, Eye, EyeOff } from 'lucide-react'

export default function ResetPassword() {
  const navigate = useNavigate()
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [show, setShow] = useState(false)
  const [done, setDone] = useState(false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setDone(true)
    setTimeout(() => navigate('/login'), 2000)
  }

  return (
    <div className="min-h-screen bg-ob flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2.5 mb-10">
          <div className="w-7 h-7 rounded-md bg-oaccent flex items-center justify-center">
            <Activity size={14} className="text-white" />
          </div>
          <span className="font-semibold text-sm text-ot1">ORACLE</span>
        </div>

        {!done ? (
          <>
            <h1 className="text-2xl font-semibold text-ot1 mb-1">Set new password</h1>
            <p className="text-sm text-ot2 mb-8">Choose a strong password for your account.</p>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-ot2 mb-1.5">New password</label>
                <div className="relative">
                  <input type={show ? 'text' : 'password'} value={password}
                    onChange={e => setPassword(e.target.value)} placeholder="12+ characters" required
                    className="w-full px-3 py-2.5 pr-10 rounded-lg bg-os1 border border-oline text-sm text-ot1 placeholder-ot3 focus:outline-none focus:border-oaccent transition-colors" />
                  <button type="button" onClick={() => setShow(s => !s)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-ot3 hover:text-ot2">
                    {show ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-ot2 mb-1.5">Confirm password</label>
                <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)}
                  placeholder="Repeat password" required
                  className={`w-full px-3 py-2.5 rounded-lg bg-os1 border text-sm text-ot1 placeholder-ot3 focus:outline-none transition-colors ${
                    confirm && confirm !== password ? 'border-ored' : 'border-oline focus:border-oaccent'
                  }`} />
                {confirm && confirm !== password && (
                  <p className="text-xs text-ored mt-1">Passwords don't match</p>
                )}
              </div>
              <button type="submit" disabled={!password || password !== confirm}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-oaccent text-white text-sm font-medium hover:bg-indigo-500 transition-colors disabled:opacity-60">
                Reset password <ArrowRight size={14} />
              </button>
            </form>
          </>
        ) : (
          <div className="text-center">
            <div className="w-12 h-12 rounded-full bg-ogreen/10 border border-ogreen/20 flex items-center justify-center mx-auto mb-5">
              <span className="text-xl">✓</span>
            </div>
            <h1 className="text-xl font-semibold text-ot1 mb-2">Password updated</h1>
            <p className="text-sm text-ot2">Redirecting you to login…</p>
          </div>
        )}
      </div>
    </div>
  )
}
