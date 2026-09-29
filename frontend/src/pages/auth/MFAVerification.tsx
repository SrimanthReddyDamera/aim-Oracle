import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router'
import { Activity, Shield } from 'lucide-react'

export default function MFAVerification() {
  const navigate = useNavigate()
  const [code, setCode] = useState(['', '', '', '', '', ''])
  const refs = useRef<(HTMLInputElement | null)[]>([])

  const handleKey = (i: number, v: string) => {
    if (!/^\d?$/.test(v)) return
    const next = [...code]
    next[i] = v
    setCode(next)
    if (v && i < 5) refs.current[i + 1]?.focus()
    if (next.every(d => d)) {
      setTimeout(() => navigate('/app'), 800)
    }
  }

  const handleKeyDown = (i: number, e: React.KeyboardEvent) => {
    if (e.key === 'Backspace' && !code[i] && i > 0) refs.current[i - 1]?.focus()
  }

  return (
    <div className="min-h-screen bg-ob flex items-center justify-center px-4">
      <div className="w-full max-w-sm text-center">
        <div className="w-12 h-12 rounded-xl bg-oaccent/10 border border-oaccent/20 flex items-center justify-center mx-auto mb-6">
          <Shield size={20} className="text-oaccent" />
        </div>
        <h1 className="text-2xl font-semibold text-ot1 mb-2">Two-factor authentication</h1>
        <p className="text-sm text-ot2 mb-8">Enter the 6-digit code from your authenticator app</p>

        <div className="flex gap-2 justify-center mb-8">
          {code.map((d, i) => (
            <input
              key={i}
              ref={el => { refs.current[i] = el }}
              type="text"
              inputMode="numeric"
              maxLength={1}
              value={d}
              onChange={e => handleKey(i, e.target.value)}
              onKeyDown={e => handleKeyDown(i, e)}
              className="w-11 h-13 text-center text-lg font-mono font-semibold rounded-lg bg-os1 border border-oline text-ot1 focus:outline-none focus:border-oaccent transition-colors"
            />
          ))}
        </div>

        <p className="text-xs text-ot3">
          Lost access?{' '}
          <button className="text-oaccent hover:text-indigo-400 transition-colors">Use a backup code</button>
        </p>
      </div>
    </div>
  )
}
