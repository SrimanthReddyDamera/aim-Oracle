import { useState } from 'react'
import { Link } from 'react-router'
import { Brain, TrendingUp, AlertOctagon, Lightbulb, ChevronRight, Search, ArrowUpRight } from 'lucide-react'

const tabs = ['All', 'Anomalies', 'Predictions', 'Recommendations']

const insights = [
  {
    id: '1', type: 'anomaly', title: 'Unusual memory growth in payment-service',
    detail: 'Memory usage has grown 340% over the last 2 hours, far outside the normal range for this time of day. Correlated with deploy-769 (notification-worker v1.4.7) — likely a shared library regression.',
    confidence: 94, impact: 'high', services: ['payment-service', 'notification-worker'], time: '2m ago',
    tags: ['memory', 'regression', 'correlated-deploy'],
  },
  {
    id: '2', type: 'prediction', title: 'Database connection pool exhaustion likely within 40 min',
    detail: 'Connection pool utilization is trending at +4.2/min. At this rate, the pool will be exhausted in ~38 minutes, causing request failures for auth-service and api-gateway.',
    confidence: 87, impact: 'critical', services: ['auth-service', 'api-gateway', 'postgres-primary'], time: '11m ago',
    tags: ['database', 'capacity', 'prediction'],
  },
  {
    id: '3', type: 'recommendation', title: 'Scale recommendation-worker to handle load',
    detail: 'Queue depth for recommendation-worker has exceeded threshold for 22 minutes. Adding 2 replicas will reduce p95 latency from 1.8s to ~0.4s and clear the queue within 8 minutes.',
    confidence: 91, impact: 'medium', services: ['recommendation-worker'], time: '18m ago',
    tags: ['scaling', 'queue', 'performance'],
  },
  {
    id: '4', type: 'anomaly', title: 'Spike in 4xx errors from mobile clients',
    detail: 'iOS client version 4.2.1 is generating 12× normal 4xx error rate since 08:30 UTC. The pattern matches a breaking API change in auth-service v2.9.0 deployed at 09:04.',
    confidence: 88, impact: 'medium', services: ['auth-service', 'api-gateway'], time: '33m ago',
    tags: ['api', 'mobile', 'breaking-change'],
  },
  {
    id: '5', type: 'recommendation', title: 'Enable automatic retries for payment-processor',
    detail: 'payment-processor has a 3.1% transient failure rate against the upstream Stripe API. Enabling idempotent retries with exponential backoff would recover ~2,800 transactions/day automatically.',
    confidence: 78, impact: 'medium', services: ['payment-processor'], time: '1h ago',
    tags: ['resilience', 'retries', 'payment'],
  },
]

const investigations = [
  { id: 'inv-021', title: 'INC-0291 — Payment service latency root cause', status: 'active', progress: 67, duration: '18m' },
  { id: 'inv-020', title: 'INC-0290 — Memory leak root cause analysis', status: 'active', progress: 89, duration: '1h 4m' },
  { id: 'inv-019', title: 'Deploy-769 regression analysis', status: 'completed', progress: 100, duration: '44m' },
]

const typeIcon: Record<string, React.ElementType> = {
  anomaly: AlertOctagon,
  prediction: TrendingUp,
  recommendation: Lightbulb,
}

const typeColor: Record<string, string> = {
  anomaly: 'text-ored bg-ored/10 border-ored/25',
  prediction: 'text-oamber bg-oamber/10 border-oamber/25',
  recommendation: 'text-oaccent bg-oaccent/10 border-oaccent/25',
}

const impactColor: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-ored',
  medium: 'text-oamber',
  low: 'text-ogreen',
}

export default function IntelligenceCenter() {
  const [tab, setTab] = useState('All')
  const [search, setSearch] = useState('')

  const filtered = insights.filter(i => {
    const matchTab = tab === 'All' || i.type === tab.slice(0, -1).toLowerCase() + (tab.endsWith('s') ? '' : '')
      || i.type + 's' === tab.toLowerCase()
    const matchSearch = i.title.toLowerCase().includes(search.toLowerCase())
    return matchTab && matchSearch
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-ot1 flex items-center gap-2">
            <Brain size={18} className="text-oaccent" />
            Intelligence Center
          </h1>
          <p className="text-sm text-ot2 mt-0.5">AI-generated insights across your entire system</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-oaccent font-mono bg-oaccent/5 border border-oaccent/20 px-3 py-1.5 rounded-lg">
          <span className="w-1.5 h-1.5 rounded-full bg-oaccent oa-ping" />
          {insights.length} active insights · 2 investigations running
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* Insights panel */}
        <div className="col-span-2 space-y-4">
          {/* Controls */}
          <div className="flex items-center gap-3">
            <div className="flex bg-os1 rounded-lg border border-oline p-0.5">
              {tabs.map(t => (
                <button key={t} onClick={() => setTab(t)}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                    tab === t ? 'bg-os2 text-ot1' : 'text-ot2 hover:text-ot1'
                  }`}>{t}</button>
              ))}
            </div>
            <div className="flex items-center flex-1 gap-2 px-3 py-1.5 rounded-lg bg-os1 border border-oline">
              <Search size={13} className="text-ot3" />
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search insights..."
                className="flex-1 bg-transparent text-xs text-ot1 placeholder-ot3 focus:outline-none" />
            </div>
          </div>

          {/* Insight cards */}
          <div className="space-y-3">
            {filtered.map(ins => {
              const Icon = typeIcon[ins.type]
              return (
                <Link key={ins.id} to={`/app/intelligence/investigation/${ins.id}`}
                  className="block p-4 rounded-xl bg-os1 border border-oline hover:border-oline2 transition-all group">
                  <div className="flex items-start justify-between gap-3 mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border ${typeColor[ins.type]}`}>
                        <Icon size={10} /> {ins.type}
                      </span>
                      <span className={`text-[10px] font-medium ${impactColor[ins.impact]}`}>{ins.impact} impact</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono text-ot3">{ins.time}</span>
                      <ArrowUpRight size={12} className="text-ot3 group-hover:text-oaccent transition-colors" />
                    </div>
                  </div>
                  <h3 className="text-sm font-medium text-ot1 mb-1.5 group-hover:text-oaccent transition-colors">{ins.title}</h3>
                  <p className="text-xs text-ot2 leading-relaxed mb-3 line-clamp-2">{ins.detail}</p>
                  <div className="flex items-center justify-between">
                    <div className="flex flex-wrap gap-1">
                      {ins.services.map(s => (
                        <span key={s} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-os2 border border-oline text-ot2">{s}</span>
                      ))}
                    </div>
                    <div className="flex items-center gap-1.5">
                      <div className="w-16 h-1 rounded-full bg-os2">
                        <div className="h-full rounded-full bg-oaccent" style={{ width: `${ins.confidence}%` }} />
                      </div>
                      <span className="text-[10px] font-mono text-oaccent">{ins.confidence}%</span>
                    </div>
                  </div>
                </Link>
              )
            })}
          </div>
        </div>

        {/* Investigations sidebar */}
        <div className="space-y-4">
          <div className="rounded-xl bg-os1 border border-oaccent/20 overflow-hidden">
            <div className="px-4 py-3 border-b border-oaccent/20 bg-oaccent/5">
              <span className="text-sm font-medium text-ot1">Active Investigations</span>
            </div>
            <div className="divide-y divide-oline">
              {investigations.map(inv => (
                <Link key={inv.id} to={`/app/intelligence/investigation/${inv.id}`}
                  className="block px-4 py-3 hover:bg-os2 transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                      inv.status === 'active' ? 'text-ogreen bg-ogreen/10' : 'text-ot3 bg-os2'
                    }`}>{inv.status}</span>
                    <span className="text-[10px] font-mono text-ot3">{inv.duration}</span>
                  </div>
                  <p className="text-xs text-ot1 mb-2 leading-snug">{inv.title}</p>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1 rounded-full bg-os2">
                      <div className={`h-full rounded-full ${inv.status === 'completed' ? 'bg-ogreen' : 'bg-oaccent animate-pulse'}`}
                        style={{ width: `${inv.progress}%` }} />
                    </div>
                    <span className="text-[10px] font-mono text-ot3">{inv.progress}%</span>
                  </div>
                </Link>
              ))}
            </div>
          </div>

          {/* ORACLE core status */}
          <div className="rounded-xl bg-os1 border border-oline p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="w-2 h-2 rounded-full bg-oaccent oa-ping" />
              <span className="text-xs font-medium text-ot1">ORACLE Core</span>
            </div>
            {[
              { label: 'Models loaded', value: '12/12' },
              { label: 'Signal latency', value: '230ms' },
              { label: 'Events processed/s', value: '4,821' },
              { label: 'Accuracy (30d)', value: '96.2%' },
            ].map(s => (
              <div key={s.label} className="flex items-center justify-between py-1.5 border-b border-oline last:border-0">
                <span className="text-xs text-ot2">{s.label}</span>
                <span className="text-xs font-mono text-ot1">{s.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
