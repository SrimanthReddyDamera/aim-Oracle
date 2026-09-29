import { useParams, Link } from 'react-router'
import { ChevronLeft, CheckCircle2, RefreshCw, Trash2, ToggleRight, Clock } from 'lucide-react'

const recentEvents = [
  { type: 'push', detail: 'Push to main — a4f2e19', ago: '4m ago' },
  { type: 'pr', detail: 'PR #4821 merged — auth-service', ago: '2h ago' },
  { type: 'pr', detail: 'PR #4820 opened — payment-service', ago: '3h ago' },
  { type: 'deploy', detail: 'Deployment status: api-gateway v3.14.2 succeeded', ago: '4m ago' },
]

const permissions = [
  { name: 'Read repository contents', granted: true },
  { name: 'Read pull requests', granted: true },
  { name: 'Write commit statuses', granted: true },
  { name: 'Read organization members', granted: true },
  { name: 'Write webhooks', granted: false },
]

export default function IntegrationDetails() {
  const { id } = useParams()

  return (
    <div className="space-y-6 max-w-3xl">
      <Link to="/app/integrations" className="flex items-center gap-1.5 text-xs text-ot2 hover:text-ot1 transition-colors">
        <ChevronLeft size={14} /> Integrations
      </Link>

      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <span className="text-4xl">🐙</span>
          <div>
            <div className="flex items-center gap-2 mb-0.5">
              <h1 className="text-xl font-semibold text-ot1 capitalize">{id}</h1>
              <span className="flex items-center gap-1 text-[10px] font-mono text-ogreen"><CheckCircle2 size={11} />connected</span>
            </div>
            <p className="text-sm text-ot2">Source Control · Connected 14 days ago</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-os1 border border-oline text-xs text-ot2 hover:text-ot1">
            <RefreshCw size={13} /> Sync now
          </button>
          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-ored/10 border border-ored/25 text-xs text-ored hover:bg-ored/20">
            <Trash2 size={13} /> Disconnect
          </button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Events (24h)', value: '1,420' },
          { label: 'Repos synced', value: '12' },
          { label: 'Last sync', value: '1m ago' },
        ].map(s => (
          <div key={s.label} className="p-3 rounded-lg bg-os1 border border-oline">
            <div className="text-xs text-ot3 mb-1">{s.label}</div>
            <div className="text-lg font-bold font-mono text-ot1">{s.value}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Permissions */}
        <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
          <div className="px-4 py-3 border-b border-oline">
            <span className="text-sm font-medium text-ot1">Permissions</span>
          </div>
          <div className="divide-y divide-oline">
            {permissions.map(p => (
              <div key={p.name} className="flex items-center justify-between px-4 py-2.5">
                <span className="text-xs text-ot1">{p.name}</span>
                {p.granted ? (
                  <CheckCircle2 size={14} className="text-ogreen" />
                ) : (
                  <span className="text-[10px] text-ot3">not granted</span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Recent events */}
        <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
          <div className="px-4 py-3 border-b border-oline">
            <span className="text-sm font-medium text-ot1">Recent Events</span>
          </div>
          <div className="divide-y divide-oline">
            {recentEvents.map((e, i) => (
              <div key={i} className="flex items-start gap-3 px-4 py-2.5">
                <span className="text-[10px] font-mono px-1 py-0.5 rounded bg-os2 text-ot3 flex-shrink-0 mt-0.5">{e.type}</span>
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-ot1 truncate">{e.detail}</p>
                </div>
                <span className="text-[10px] text-ot3 flex-shrink-0">{e.ago}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
