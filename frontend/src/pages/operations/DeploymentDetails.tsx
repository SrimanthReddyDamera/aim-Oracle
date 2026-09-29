import { useParams, Link } from 'react-router'
import { ChevronLeft, Brain, GitCommit, User, Clock, CheckCircle2, XCircle, Loader2, AlertTriangle, RotateCcw } from 'lucide-react'

const stages = [
  { name: 'Checkout', status: 'succeeded', duration: '4s' },
  { name: 'Build', status: 'succeeded', duration: '1m 42s' },
  { name: 'Unit Tests', status: 'succeeded', duration: '2m 11s' },
  { name: 'Integration Tests', status: 'running', duration: '4m 12s' },
  { name: 'Security Scan', status: 'pending', duration: '—' },
  { name: 'Deploy Canary', status: 'pending', duration: '—' },
  { name: 'Deploy Prod', status: 'pending', duration: '—' },
]

const metrics = [
  { label: 'Error rate', before: '0.08%', after: '0.08%', change: 'neutral' },
  { label: 'p95 latency', before: '124ms', after: '127ms', change: 'slight-up' },
  { label: 'Throughput', before: '4,820 rps', after: '4,847 rps', change: 'up' },
  { label: 'Memory', before: '328MB', after: '331MB', change: 'neutral' },
]

export default function DeploymentDetails() {
  const { id } = useParams()

  return (
    <div className="space-y-6 max-w-4xl">
      <Link to="/app/operations" className="flex items-center gap-1.5 text-xs text-ot2 hover:text-ot1 transition-colors">
        <ChevronLeft size={14} /> Operations
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded text-oamber bg-oamber/10">running</span>
            <span className="text-[10px] font-mono text-ot3">{id} · 4m 12s</span>
          </div>
          <h1 className="text-xl font-semibold text-ot1">api-gateway → production</h1>
          <p className="text-sm text-ot2 mt-1 font-mono">v3.14.1 → v3.14.2</p>
        </div>
        <div className="flex items-center gap-2">
          <Link to="/app/intelligence/investigation/inv-021"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-oaccent/10 border border-oaccent/20 text-xs text-oaccent">
            <Brain size={13} /> AI Risk Analysis
          </Link>
          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-ored/10 border border-ored/25 text-xs text-ored hover:bg-ored/20">
            <RotateCcw size={13} /> Rollback
          </button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 space-y-4">
          {/* Stage timeline */}
          <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
            <div className="px-4 py-3 border-b border-oline">
              <span className="text-sm font-medium text-ot1">Pipeline Progress</span>
            </div>
            <div className="p-4 space-y-2">
              {stages.map((s, i) => (
                <div key={s.name} className="flex items-center gap-3">
                  <div className="w-5 flex-shrink-0 flex items-center justify-center">
                    {s.status === 'succeeded' && <CheckCircle2 size={16} className="text-ogreen" />}
                    {s.status === 'running' && <Loader2 size={16} className="text-oamber animate-spin" />}
                    {s.status === 'failed' && <XCircle size={16} className="text-ored" />}
                    {s.status === 'pending' && <div className="w-4 h-4 rounded-full border border-oline" />}
                  </div>
                  <span className={`text-sm flex-1 ${
                    s.status === 'pending' ? 'text-ot3' :
                    s.status === 'running' ? 'text-ot1' : 'text-ot2'
                  }`}>{s.name}</span>
                  <span className="text-xs font-mono text-ot3">{s.duration}</span>
                  {s.status === 'running' && (
                    <div className="w-20 h-1 rounded-full bg-os2">
                      <div className="h-full rounded-full bg-oamber animate-pulse" style={{ width: '55%' }} />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Health metrics */}
          <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
            <div className="px-4 py-3 border-b border-oline">
              <span className="text-sm font-medium text-ot1">Health Metrics (Canary vs Baseline)</span>
            </div>
            <table className="w-full">
              <thead>
                <tr className="border-b border-oline">
                  <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2">Metric</th>
                  <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2">Before</th>
                  <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2">After</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-oline">
                {metrics.map(m => (
                  <tr key={m.label}>
                    <td className="px-4 py-2.5 text-xs text-ot2">{m.label}</td>
                    <td className="px-4 py-2.5 text-xs font-mono text-ot3">{m.before}</td>
                    <td className="px-4 py-2.5 text-xs font-mono font-medium text-ot1">{m.after}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          <div className="rounded-xl bg-os1 border border-oline p-4 space-y-3">
            {[
              { label: 'Service', value: 'api-gateway' },
              { label: 'Environment', value: 'production' },
              { label: 'Initiator', value: 'GitHub Actions' },
              { label: 'Commit', value: 'a4f2e19' },
              { label: 'Branch', value: 'main' },
              { label: 'Started', value: '09:38 UTC' },
            ].map(f => (
              <div key={f.label} className="flex items-center justify-between">
                <span className="text-xs text-ot3">{f.label}</span>
                <span className="text-xs font-mono text-ot1">{f.value}</span>
              </div>
            ))}
          </div>

          {/* AI Risk */}
          <div className="rounded-xl bg-oaccent/5 border border-oaccent/25 p-4">
            <div className="flex items-center gap-2 mb-2">
              <Brain size={13} className="text-oaccent" />
              <span className="text-xs font-medium text-oaccent">AI Risk Analysis</span>
            </div>
            <div className="flex items-center gap-2 mb-2">
              <div className="flex-1 h-1.5 rounded-full bg-os2">
                <div className="h-full rounded-full bg-ogreen" style={{ width: '82%' }} />
              </div>
              <span className="text-xs font-mono text-ogreen">Low risk</span>
            </div>
            <p className="text-xs text-ot2">3 changed files, no database migrations, 2 days since last deploy. Historical success rate for this service: 98.4%.</p>
          </div>
        </div>
      </div>
    </div>
  )
}
