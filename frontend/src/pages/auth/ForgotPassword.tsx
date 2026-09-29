import { useState } from 'react'
import { Link } from 'react-router'
import { Activity, ArrowRight, ArrowLeft, Mail } from 'lucide-react'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [sent, setSent] = useState(false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setSent(true)
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

        {!sent ? (
          <>
            <h1 className="text-2xl font-semibold text-ot1 mb-1">Reset your password</h1>
            <p className="text-sm text-ot2 mb-8">Enter your email and we'll send you a reset link.</p>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-ot2 mb-1.5">Email address</label>
                <input type="email" value={email} onChange={e => setEmail(e.target.value)}
                  placeholder="you@company.com" required
                  className="w-full px-3 py-2.5 rounded-lg bg-os1 border border-oline text-sm text-ot1 placeholder-ot3 focus:outline-none focus:border-oaccent transition-colors" />
              </div>
              <button type="submit"
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-oaccent text-white text-sm font-medium hover:bg-indigo-500 transition-colors">
                Send reset link <ArrowRight size={14} />
              </button>
            </form>
          </>
        ) : (
          <div className="text-center">
            <div className="w-12 h-12 rounded-full bg-oaccent/10 border border-oaccent/20 flex items-center justify-center mx-auto mb-5">
              <Mail size={20} className="text-oaccent" />
            </div>
            <h1 className="text-2xl font-semibold text-ot1 mb-2">Check your inbox</h1>
            <p className="text-sm text-ot2 mb-6">We sent a password reset link to <strong className="text-ot1">{email}</strong></p>
            <p className="text-xs text-ot3">Didn't receive it? <button onClick={() => setSent(false)} className="text-oaccent hover:text-indigo-400">Resend</button></p>
          </div>
        )}

        <div className="mt-8">
          <Link to="/login" className="flex items-center gap-1.5 text-xs text-ot2 hover:text-ot1 transition-colors">
            <ArrowLeft size={13} /> Back to login
          </Link>
        </div>
      </div>
    </div>
  )
}
