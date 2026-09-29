import { useState } from 'react'
import { useNavigate } from 'react-router'
import { ArrowRight, Plus, Trash2 } from 'lucide-react'

const defaults = [
  { id: '1', name: 'Production', type: 'production', color: 'ored' },
  { id: '2', name: 'Staging', type: 'staging', color: 'oamber' },
  { id: '3', name: 'Development', type: 'development', color: 'ogreen' },
]

const colorMap: Record<string, string> = {
  ored: 'bg-ored/10 border-ored/30 text-ored',
  oamber: 'bg-oamber/10 border-oamber/30 text-oamber',
  ogreen: 'bg-ogreen/10 border-ogreen/30 text-ogreen',
  oblue: 'bg-oblue/10 border-oblue/30 text-oblue',
}

export default function EnvironmentSetup() {
  const navigate = useNavigate()
  const [envs, setEnvs] = useState(defaults)

  const remove = (id: string) => setEnvs(e => e.filter(x => x.id !== id))
  const add = () => setEnvs(e => [...e, { id: Date.now().toString(), name: 'New Environment', type: 'custom', color: 'oblue' }])

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-xl font-semibold text-ot1 mb-1">Define your environments</h1>
        <p className="text-sm text-ot2">ORACLE tracks deployments and incidents across each environment.</p>
      </div>

      <div className="space-y-2.5 mb-4">
        {envs.map(env => (
          <div key={env.id} className="flex items-center gap-3 p-3.5 rounded-lg bg-os1 border border-oline">
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${colorMap[env.color] ?? colorMap.oblue}`}>
              {env.type}
            </span>
            <input
              value={env.name}
              onChange={e => setEnvs(prev => prev.map(x => x.id === env.id ? { ...x, name: e.target.value } : x))}
              className="flex-1 bg-transparent text-sm text-ot1 focus:outline-none"
            />
            <button onClick={() => remove(env.id)} className="text-ot3 hover:text-ored transition-colors">
              <Trash2 size={14} />
            </button>
          </div>
        ))}
      </div>

      <button onClick={add}
        className="flex items-center gap-2 text-xs text-ot2 hover:text-ot1 transition-colors mb-8">
        <Plus size={13} /> Add environment
      </button>

      <button onClick={() => navigate('/onboarding/configuration')}
        className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-oaccent text-white text-sm font-medium hover:bg-indigo-500 transition-colors">
        Continue <ArrowRight size={14} />
      </button>
    </div>
  )
}
