import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { Activity, ArrowRight, Check } from 'lucide-react'

export default function Signup() {
  const navigate = useNavigate()
  const [step, setStep] = useState(1)
  const [loading, setLoading] = useState(false)
  const [form, setForm] = useState({ name: '', email: '', company: '', password: '' })

  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm(f => ({ ...f, [k]: e.target.value }))

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (step === 1) { setStep(2); return }
    setLoading(true)
    setTimeout(() => navigate('/onboarding'), 1200)
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

        <div className="mb-2">
          <div className="flex gap-1.5 mb-6">
            {[1, 2].map(s => (
              <div key={s} className={`h-0.5 flex-1 rounded-full transition-colors ${s <= step ? 'bg-oaccent' : 'bg-oline2'}`} />
            ))}
          </div>
          <h1 className="text-2xl font-semibold text-ot1 mb-1">
            {step === 1 ? 'Create your account' : 'Secure your account'}
          </h1>
          <p className="text-sm text-ot2">
            {step === 1 ? 'Start your 14-day free trial. No credit card required.' : 'Choose a strong password for your account.'}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          {step === 1 ? (
            <>
              <div>
                <label className="block text-xs font-medium text-ot2 mb-1.5">Full name</label>
                <input value={form.name} onChange={set('name')} placeholder="Jordan Davis" required
                  className="w-full px-3 py-2.5 rounded-lg bg-os1 border border-oline text-sm text-ot1 placeholder-ot3 focus:outline-none focus:border-oaccent transition-colors" />
              </div>
              <div>
                <label className="block text-xs font-medium text-ot2 mb-1.5">Work email</label>
                <input type="email" value={form.email} onChange={set('email')} placeholder="you@company.com" required
                  className="w-full px-3 py-2.5 rounded-lg bg-os1 border border-oline text-sm text-ot1 placeholder-ot3 focus:outline-none focus:border-oaccent transition-colors" />
              </div>
              <div>
                <label className="block text-xs font-medium text-ot2 mb-1.5">Company</label>
                <input value={form.company} onChange={set('company')} placeholder="Acme Corp" required
                  className="w-full px-3 py-2.5 rounded-lg bg-os1 border border-oline text-sm text-ot1 placeholder-ot3 focus:outline-none focus:border-oaccent transition-colors" />
              </div>
            </>
          ) : (
            <div>
              <label className="block text-xs font-medium text-ot2 mb-1.5">Password</label>
              <input type="password" value={form.password} onChange={set('password')} placeholder="12+ characters" required
                className="w-full px-3 py-2.5 rounded-lg bg-os1 border border-oline text-sm text-ot1 placeholder-ot3 focus:outline-none focus:border-oaccent transition-colors" />
              <div className="mt-2 space-y-1">
                {['At least 12 characters', 'Uppercase and lowercase', 'Number or symbol'].map(r => (
                  <div key={r} className={`flex items-center gap-2 text-xs ${form.password.length >= 4 ? 'text-ogreen' : 'text-ot3'}`}>
                    <Check size={11} />
                    {r}
                  </div>
                ))}
              </div>
            </div>
          )}

          <button type="submit" disabled={loading}
            className="w-full flex items-center justify-center gap-2 py-2.5 rounded-lg bg-oaccent text-white text-sm font-medium hover:bg-indigo-500 transition-colors disabled:opacity-60">
            {loading ? (
              <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : step === 1 ? (
              <>Continue <ArrowRight size={14} /></>
            ) : (
              <>Create account <ArrowRight size={14} /></>
            )}
          </button>
        </form>

        <p className="text-center text-xs text-ot2 mt-6">
          Already have an account?{' '}
          <Link to="/login" className="text-oaccent hover:text-indigo-400 transition-colors">Sign in</Link>
        </p>
        <p className="text-center text-xs text-ot3 mt-3">
          By continuing, you agree to our{' '}
          <a href="#" className="hover:text-ot2 transition-colors">Terms</a> and{' '}
          <a href="#" className="hover:text-ot2 transition-colors">Privacy Policy</a>.
        </p>
      </div>
    </div>
  )
}
