import { useState } from 'react'
import { useNavigate } from 'react-router'
import { ArrowRight, Brain, Zap, Shield, ToggleLeft, ToggleRight } from 'lucide-react'

const features = [
  {
    id: 'auto_investigate',
    icon: Brain,
    label: 'Auto-Investigation',
    description: 'ORACLE automatically investigates incidents and anomalies as they occur.',
    default: true,
  },
  {
    id: 'auto_remediate',
    icon: Zap,
    label: 'Autonomous Remediation',
    description: 'Allow ORACLE to execute pre-approved runbooks without human approval.',
    default: false,
  },
  {
    id: 'predictive',
    icon: Shield,
    label: 'Predictive Alerts',
    description: 'Surface issues before they become incidents using ML anomaly detection.',
    default: true,
  },
]

export default function OracleConfiguration() {
  const navigate = useNavigate()
  const [enabled, setEnabled] = useState<Record<string, boolean>>(
    Object.fromEntries(features.map(f => [f.id, f.default]))
  )
  const [sensitivity, setSensitivity] = useState(70)

  const toggle = (id: string) => setEnabled(s => ({ ...s, [id]: !s[id] }))

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-xl font-semibold text-ot1 mb-1">Configure ORACLE</h1>
        <p className="text-sm text-ot2">Tune how the AI operates in your environment. You can change these anytime in Settings.</p>
      </div>

      <div className="space-y-3 mb-6">
        {features.map(f => {
          const Icon = f.icon
          const on = enabled[f.id]
          return (
            <div key={f.id} className="flex items-start gap-4 p-4 rounded-lg bg-os1 border border-oline">
              <div className="w-8 h-8 rounded-md bg-oaccent/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                <Icon size={15} className="text-oaccent" />
              </div>
              <div className="flex-1">
                <div className="text-sm font-medium text-ot1">{f.label}</div>
                <div className="text-xs text-ot2 mt-0.5">{f.description}</div>
              </div>
              <button onClick={() => toggle(f.id)} className={`transition-colors ${on ? 'text-oaccent' : 'text-ot3'}`}>
                {on ? <ToggleRight size={22} /> : <ToggleLeft size={22} />}
              </button>
            </div>
          )
        })}
      </div>

      <div className="p-4 rounded-lg bg-os1 border border-oline mb-8">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-ot1">Alert sensitivity</span>
          <span className="text-xs font-mono text-oaccent">{sensitivity}%</span>
        </div>
        <input type="range" min={10} max={100} value={sensitivity}
          onChange={e => setSensitivity(Number(e.target.value))}
          className="w-full accent-oaccent" />
        <div className="flex justify-between text-[10px] text-ot3 mt-1">
          <span>Fewer alerts</span>
          <span>More alerts</span>
        </div>
      </div>

      <button onClick={() => navigate('/onboarding/team')}
        className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-oaccent text-white text-sm font-medium hover:bg-indigo-500 transition-colors">
        Continue <ArrowRight size={14} />
      </button>
    </div>
  )
}
