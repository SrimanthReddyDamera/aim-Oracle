import { useState } from 'react'
import { Link } from 'react-router'
import { Search, Plus, CheckCircle2, XCircle, Clock } from 'lucide-react'

const categories = ['All', 'Source Control', 'Monitoring', 'Incident Management', 'Cloud', 'Communication', 'Project Management']

const integrations = [
  { id: 'github', name: 'GitHub', category: 'Source Control', logo: '🐙', connected: true, status: 'healthy', syncedAt: '1m ago', events: 1420 },
  { id: 'pagerduty', name: 'PagerDuty', category: 'Incident Management', logo: '🔔', connected: true, status: 'healthy', syncedAt: '30s ago', events: 87 },
  { id: 'datadog', name: 'Datadog', category: 'Monitoring', logo: '🐕', connected: true, status: 'healthy', syncedAt: '10s ago', events: 48220 },
  { id: 'aws', name: 'AWS', category: 'Cloud', logo: '☁️', connected: true, status: 'warning', syncedAt: '2m ago', events: 9841 },
  { id: 'slack', name: 'Slack', category: 'Communication', logo: '💬', connected: true, status: 'healthy', syncedAt: '5m ago', events: 342 },
  { id: 'jira', name: 'Jira', category: 'Project Management', logo: '📋', connected: true, status: 'healthy', syncedAt: '3m ago', events: 214 },
  { id: 'k8s', name: 'Kubernetes', category: 'Cloud', logo: '⚙️', connected: true, status: 'healthy', syncedAt: '5s ago', events: 72140 },
  { id: 'gitlab', name: 'GitLab', category: 'Source Control', logo: '🦊', connected: false, status: null, syncedAt: null, events: 0 },
  { id: 'gcp', name: 'Google Cloud', category: 'Cloud', logo: '🌐', connected: false, status: null, syncedAt: null, events: 0 },
  { id: 'opsgenie', name: 'Opsgenie', category: 'Incident Management', logo: '📟', connected: false, status: null, syncedAt: null, events: 0 },
  { id: 'prometheus', name: 'Prometheus', category: 'Monitoring', logo: '🔥', connected: false, status: null, syncedAt: null, events: 0 },
  { id: 'linear', name: 'Linear', category: 'Project Management', logo: '◆', connected: false, status: null, syncedAt: null, events: 0 },
]

const statusColor: Record<string, string> = {
  healthy: 'text-ogreen',
  warning: 'text-oamber',
  error: 'text-ored',
}

export default function Integrations() {
  const [search, setSearch] = useState('')
  const [cat, setCat] = useState('All')

  const filtered = integrations.filter(i =>
    i.name.toLowerCase().includes(search.toLowerCase()) &&
    (cat === 'All' || i.category === cat)
  )

  const connected = integrations.filter(i => i.connected).length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-ot1">Integrations</h1>
          <p className="text-sm text-ot2 mt-0.5">{connected} of {integrations.length} integrations connected</p>
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-os1 border border-oline">
          <Search size={13} className="text-ot3" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search integrations..."
            className="bg-transparent text-xs text-ot1 placeholder-ot3 focus:outline-none w-40" />
        </div>
        <div className="flex gap-1 flex-wrap">
          {categories.slice(0, 4).map(c => (
            <button key={c} onClick={() => setCat(c)}
              className={`px-2.5 py-1 rounded-md text-xs transition-colors ${
                cat === c ? 'bg-oaccent text-white' : 'bg-os1 border border-oline text-ot2 hover:text-ot1'
              }`}>{c}</button>
          ))}
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-4 gap-3">
        {filtered.map(i => (
          <Link key={i.id} to={i.connected ? `/app/integrations/${i.id}` : '#'}
            className={`p-4 rounded-xl border transition-all group ${
              i.connected
                ? 'bg-os1 border-oline hover:border-oline2'
                : 'bg-os1/50 border-oline opacity-60 cursor-default'
            }`}>
            <div className="flex items-start justify-between mb-3">
              <span className="text-2xl">{i.logo}</span>
              {i.connected ? (
                <CheckCircle2 size={14} className="text-ogreen" />
              ) : (
                <button className="text-[10px] px-2 py-0.5 rounded bg-oaccent/10 border border-oaccent/20 text-oaccent hover:bg-oaccent/20 transition-colors">
                  Connect
                </button>
              )}
            </div>
            <div className="text-sm font-medium text-ot1 mb-0.5">{i.name}</div>
            <div className="text-[10px] text-ot3 mb-2">{i.category}</div>
            {i.connected && i.status && (
              <div className="flex items-center justify-between text-[10px]">
                <span className={`flex items-center gap-1 ${statusColor[i.status]}`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${i.status === 'healthy' ? 'bg-ogreen' : 'bg-oamber'}`} />
                  {i.status}
                </span>
                <span className="text-ot3 font-mono">{i.syncedAt}</span>
              </div>
            )}
          </Link>
        ))}
      </div>
    </div>
  )
}
