import { useState } from 'react'
import { useNavigate } from 'react-router'
import { ArrowRight, Plus, X, Mail } from 'lucide-react'

const roles = ['Admin', 'Engineer', 'Viewer']

export default function TeamInvitation() {
  const navigate = useNavigate()
  const [invites, setInvites] = useState([
    { id: '1', email: '', role: 'Engineer' },
  ])

  const add = () => setInvites(i => [...i, { id: Date.now().toString(), email: '', role: 'Engineer' }])
  const remove = (id: string) => setInvites(i => i.filter(x => x.id !== id))
  const set = (id: string, k: string, v: string) =>
    setInvites(i => i.map(x => x.id === id ? { ...x, [k]: v } : x))

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-xl font-semibold text-ot1 mb-1">Invite your team</h1>
        <p className="text-sm text-ot2">Add teammates to your ORACLE workspace. You can always invite more later.</p>
      </div>

      <div className="space-y-2.5 mb-4">
        {invites.map(inv => (
          <div key={inv.id} className="flex items-center gap-2.5">
            <div className="flex items-center flex-1 gap-2 px-3 py-2.5 rounded-lg bg-os1 border border-oline">
              <Mail size={13} className="text-ot3 flex-shrink-0" />
              <input
                type="email"
                placeholder="colleague@company.com"
                value={inv.email}
                onChange={e => set(inv.id, 'email', e.target.value)}
                className="flex-1 bg-transparent text-sm text-ot1 placeholder-ot3 focus:outline-none"
              />
            </div>
            <select value={inv.role} onChange={e => set(inv.id, 'role', e.target.value)}
              className="px-3 py-2.5 rounded-lg bg-os1 border border-oline text-sm text-ot1 focus:outline-none focus:border-oaccent">
              {roles.map(r => <option key={r}>{r}</option>)}
            </select>
            {invites.length > 1 && (
              <button onClick={() => remove(inv.id)} className="text-ot3 hover:text-ored transition-colors">
                <X size={15} />
              </button>
            )}
          </div>
        ))}
      </div>

      <button onClick={add}
        className="flex items-center gap-2 text-xs text-ot2 hover:text-ot1 transition-colors mb-8">
        <Plus size={13} /> Add another
      </button>

      <div className="flex items-center justify-between">
        <button onClick={() => navigate('/onboarding/initialization')}
          className="text-xs text-ot3 hover:text-ot2 transition-colors">
          Skip for now
        </button>
        <button onClick={() => navigate('/onboarding/initialization')}
          className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-oaccent text-white text-sm font-medium hover:bg-indigo-500 transition-colors">
          Send invites &amp; continue <ArrowRight size={14} />
        </button>
      </div>
    </div>
  )
}
