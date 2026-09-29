import { useState } from 'react'
import { useNavigate } from 'react-router'
import { ArrowRight, Check, Plus } from 'lucide-react'

const integrations = [
  { id: 'github', name: 'GitHub', category: 'Source Control', logo: '🐙', popular: true },
  { id: 'gitlab', name: 'GitLab', category: 'Source Control', logo: '🦊', popular: false },
  { id: 'pagerduty', name: 'PagerDuty', category: 'Incident Management', logo: '🔔', popular: true },
  { id: 'datadog', name: 'Datadog', category: 'Monitoring', logo: '🐕', popular: true },
  { id: 'aws', name: 'AWS', category: 'Cloud', logo: '☁️', popular: true },
  { id: 'gcp', name: 'Google Cloud', category: 'Cloud', logo: '🌐', popular: false },
  { id: 'jira', name: 'Jira', category: 'Project Management', logo: '📋', popular: true },
  { id: 'slack', name: 'Slack', category: 'Communication', logo: '💬', popular: true },
  { id: 'k8s', name: 'Kubernetes', category: 'Infrastructure', logo: '⚙️', popular: true },
]

export default function ConnectIntegrations() {
  const navigate = useNavigate()
  const [selected, setSelected] = useState<string[]>(['github', 'pagerduty', 'datadog'])

  const toggle = (id: string) =>
    setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-xl font-semibold text-ot1 mb-1">Connect your tools</h1>
        <p className="text-sm text-ot2">ORACLE works best with your existing stack. Connect at least one integration to continue.</p>
      </div>

      <div className="grid grid-cols-3 gap-2.5 mb-6">
        {integrations.map(i => {
          const active = selected.includes(i.id)
          return (
            <button key={i.id} onClick={() => toggle(i.id)}
              className={`relative flex flex-col items-center gap-2 p-4 rounded-lg border text-center transition-all ${
                active
                  ? 'border-oaccent bg-oaccent/5'
                  : 'border-oline bg-os1 hover:border-oline2'
              }`}>
              {active && (
                <div className="absolute top-2 right-2 w-4 h-4 rounded-full bg-oaccent flex items-center justify-center">
                  <Check size={10} className="text-white" />
                </div>
              )}
              <span className="text-2xl">{i.logo}</span>
              <div>
                <div className="text-xs font-medium text-ot1">{i.name}</div>
                <div className="text-[10px] text-ot3">{i.category}</div>
              </div>
            </button>
          )
        })}
      </div>

      <div className="flex items-center justify-between">
        <button onClick={() => navigate('/onboarding/environment')}
          className="text-xs text-ot3 hover:text-ot2 transition-colors">
          Skip for now
        </button>
        <button
          onClick={() => navigate('/onboarding/environment')}
          disabled={selected.length === 0}
          className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-oaccent text-white text-sm font-medium hover:bg-indigo-500 transition-colors disabled:opacity-60">
          Continue ({selected.length} selected) <ArrowRight size={14} />
        </button>
      </div>
    </div>
  )
}
