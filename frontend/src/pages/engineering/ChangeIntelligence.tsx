import { useState } from 'react'
import { Link } from 'react-router'
import { GitCommit, Rocket, AlertTriangle, TrendingUp, Brain, Filter } from 'lucide-react'

const changes = [
  {
    type: 'deploy', time: '09:38', label: 'deploy-771', detail: 'api-gateway v3.14.1 → v3.14.2 · production',
    risk: 'low', incident: null, to: '/app/operations/deployments/deploy-771',
  },
  {
    type: 'incident', time: '09:41', label: 'INC-0291', detail: 'Elevated latency on payment-service · production',
    risk: 'high', incident: 'INC-0291', to: '/app/operations/incidents/INC-0291',
  },
  {
    type: 'commit', time: '09:10', label: '#4821 merged', detail: 'auth-service: upgrade jwt library to v9.2',
    risk: 'low', incident: null, to: '/app/engineering/prs/4821',
  },
  {
    type: 'deploy', time: '09:04', label: 'deploy-770', detail: 'auth-service v2.9.0 · staging',
    risk: 'low', incident: null, to: '/app/operations/deployments/deploy-770',
  },
  {
    type: 'deploy', time: '07:12', label: 'deploy-769', detail: 'notification-worker v1.4.7 · production',
    risk: 'medium', incident: 'INC-0290', to: '/app/operations/deployments/deploy-769',
  },
  {
    type: 'incident', time: '08:16', label: 'INC-0290', detail: 'Memory leak in recommendation-worker · production',
    risk: 'high', incident: 'INC-0290', to: '/app/operations/incidents/INC-0290',
  },
]

const sorted = [...changes].sort((a, b) => b.time.localeCompare(a.time))

const typeConfig: Record<string, { icon: React.ElementType, color: string, dot: string }> = {
  deploy: { icon: Rocket, color: 'text-ogreen', dot: 'bg-ogreen' },
  incident: { icon: AlertTriangle, color: 'text-ored', dot: 'bg-ored' },
  commit: { icon: GitCommit, color: 'text-oblue', dot: 'bg-oblue' },
}

const riskColor: Record<string, string> = {
  high: 'text-ored bg-ored/10 border-ored/25',
  medium: 'text-oamber bg-oamber/10 border-oamber/25',
  low: 'text-ogreen bg-ogreen/10 border-ogreen/25',
}

export default function ChangeIntelligence() {
  const [filter, setFilter] = useState('All')

  const filters = ['All', 'Deploys', 'Incidents', 'Commits']
  const filtered = sorted.filter(c =>
    filter === 'All' || c.type === filter.slice(0, -1).toLowerCase()
  )

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-ot1 flex items-center gap-2">
            <TrendingUp size={18} className="text-oblue" />
            Change Intelligence
          </h1>
          <p className="text-sm text-ot2 mt-0.5">Correlates deployments, commits, and incidents across your stack</p>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <div className="flex bg-os1 rounded-lg border border-oline p-0.5">
          {filters.map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                filter === f ? 'bg-os2 text-ot1' : 'text-ot2 hover:text-ot1'
              }`}>{f}</button>
          ))}
        </div>
      </div>

      {/* Correlation panel */}
      <div className="p-4 rounded-xl bg-oaccent/5 border border-oaccent/20 flex items-start gap-3">
        <Brain size={16} className="text-oaccent mt-0.5 flex-shrink-0" />
        <div>
          <div className="text-xs font-medium text-oaccent mb-1">ORACLE Correlation</div>
          <p className="text-xs text-ot2">
            deploy-769 (notification-worker v1.4.7, 07:12) is correlated with INC-0290 (08:16) with 89% confidence.
            The shared-utils 3.2.0 dependency introduced in this deploy contains an EventEmitter leak.
          </p>
        </div>
      </div>

      {/* Timeline */}
      <div className="relative">
        <div className="absolute left-[87px] top-0 bottom-0 w-px bg-oline" />
        <div className="space-y-4">
          {filtered.map((c, i) => {
            const cfg = typeConfig[c.type]
            const Icon = cfg.icon
            return (
              <div key={i} className="flex items-start gap-4">
                <span className="text-[11px] font-mono text-ot3 w-16 flex-shrink-0 mt-1.5 text-right">{c.time}</span>
                <div className="relative flex items-center justify-center w-5 flex-shrink-0 mt-1.5">
                  <div className={`w-3 h-3 rounded-full border-2 border-ob ${cfg.dot}`} />
                </div>
                <Link to={c.to}
                  className="flex-1 p-3 rounded-lg bg-os1 border border-oline hover:border-oline2 transition-all group">
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <div className="flex items-center gap-2">
                      <Icon size={12} className={cfg.color} />
                      <span className="text-xs font-medium text-ot1 group-hover:text-oaccent transition-colors">{c.label}</span>
                      <span className={`text-[10px] font-mono px-1 py-0.5 rounded border ${riskColor[c.risk]}`}>{c.risk}</span>
                    </div>
                    {c.incident && (
                      <span className="text-[10px] font-mono text-ored flex items-center gap-1">
                        <AlertTriangle size={9} /> correlated
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-ot2">{c.detail}</p>
                </Link>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
