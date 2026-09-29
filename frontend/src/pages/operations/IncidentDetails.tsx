import { useParams, Link } from 'react-router'
import { ChevronLeft, Brain, Rocket, GitCommit, Clock, User, AlertTriangle, CheckCircle2, Zap, ExternalLink } from 'lucide-react'

const timeline = [
  { time: '09:41:02', event: 'Incident opened — payment-service p95 latency > 2s', author: 'ORACLE', type: 'incident' },
  { time: '09:41:15', event: 'PagerDuty alert created — routed to Platform on-call', author: 'ORACLE', type: 'alert' },
  { time: '09:41:20', event: 'Morgan L. acknowledged', author: 'Morgan L.', type: 'ack' },
  { time: '09:43:01', event: 'ORACLE investigation started — correlating 847 signals', author: 'ORACLE', type: 'investigation' },
  { time: '09:44:30', event: 'Root cause hypothesis: memory pressure from shared-utils 3.2.0', author: 'ORACLE', type: 'oracle' },
  { time: '09:45:12', event: 'Morgan L. commented: Confirmed — heap growing at ~4MB/min', author: 'Morgan L.', type: 'comment' },
  { time: '09:46:00', event: 'Rollback of notification-worker initiated (automated)', author: 'ORACLE', type: 'action' },
]

const affectedServices = [
  { name: 'payment-service', impact: 'high', error_rate: '3.2%', latency_p95: '2.4s' },
  { name: 'recommendation-worker', impact: 'medium', error_rate: '0.4%', latency_p95: '1.1s' },
  { name: 'api-gateway', impact: 'low', error_rate: '0.1%', latency_p95: '180ms' },
]

const typeColor: Record<string, string> = {
  incident: 'bg-ored',
  alert: 'bg-oamber',
  ack: 'bg-oblue',
  investigation: 'bg-oaccent',
  oracle: 'bg-oaccent',
  action: 'bg-ogreen',
  comment: 'bg-oline2',
}

export default function IncidentDetails() {
  const { id } = useParams()

  return (
    <div className="space-y-6 max-w-5xl">
      <Link to="/app/operations" className="flex items-center gap-1.5 text-xs text-ot2 hover:text-ot1 transition-colors">
        <ChevronLeft size={14} /> Operations
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border text-ored bg-ored/10 border-ored/25">high</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded text-oamber bg-oamber/10">investigating</span>
            <span className="text-[10px] font-mono text-ot3">{id} · production · 18m</span>
          </div>
          <h1 className="text-xl font-semibold text-ot1">Elevated latency on payment-service</h1>
        </div>
        <div className="flex items-center gap-2">
          <Link to="/app/intelligence/investigation/inv-021"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-oaccent/10 border border-oaccent/20 text-xs text-oaccent hover:bg-oaccent/20">
            <Brain size={13} /> ORACLE Investigation
          </Link>
          <button className="px-3 py-1.5 rounded-lg bg-ogreen/10 border border-ogreen/25 text-xs text-ogreen hover:bg-ogreen/20">
            Resolve
          </button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 space-y-4">
          {/* Impact summary */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: 'Duration', value: '18m', icon: Clock },
              { label: 'Affected users', value: '~4,200', icon: User },
              { label: 'Error rate', value: '3.2%', icon: AlertTriangle },
            ].map(m => {
              const Icon = m.icon
              return (
                <div key={m.label} className="p-3 rounded-lg bg-os1 border border-oline">
                  <div className="flex items-center gap-1.5 text-xs text-ot2 mb-1"><Icon size={12} />{m.label}</div>
                  <div className="text-lg font-bold font-mono text-ot1">{m.value}</div>
                </div>
              )
            })}
          </div>

          {/* Timeline */}
          <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
            <div className="px-4 py-3 border-b border-oline">
              <span className="text-sm font-medium text-ot1">Incident Timeline</span>
            </div>
            <div className="p-4 space-y-3">
              {timeline.map((t, i) => (
                <div key={i} className="flex items-start gap-3">
                  <span className="text-[10px] font-mono text-ot3 w-16 flex-shrink-0 mt-0.5">{t.time}</span>
                  <div className={`w-2 h-2 rounded-full mt-1 flex-shrink-0 ${typeColor[t.type]}`} />
                  <div>
                    <span className="text-xs text-ot1">{t.event}</span>
                    <span className="text-[10px] text-ot3 ml-2">— {t.author}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Affected services */}
          <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
            <div className="px-4 py-3 border-b border-oline">
              <span className="text-sm font-medium text-ot1">Affected Services</span>
            </div>
            <table className="w-full">
              <thead>
                <tr className="border-b border-oline">
                  <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2">Service</th>
                  <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2">Impact</th>
                  <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2">Error rate</th>
                  <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2">p95 latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-oline">
                {affectedServices.map(s => (
                  <tr key={s.name}>
                    <td className="px-4 py-2.5 text-sm font-medium text-ot1">{s.name}</td>
                    <td className="px-4 py-2.5">
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                        s.impact === 'high' ? 'text-ored bg-ored/10 border-ored/25' :
                        s.impact === 'medium' ? 'text-oamber bg-oamber/10 border-oamber/25' :
                        'text-oblue bg-oblue/10 border-oblue/25'
                      }`}>{s.impact}</span>
                    </td>
                    <td className="px-4 py-2.5 text-xs font-mono text-ot1">{s.error_rate}</td>
                    <td className="px-4 py-2.5 text-xs font-mono text-ot1">{s.latency_p95}</td>
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
              { label: 'Assignee', value: 'Morgan L.' },
              { label: 'Team', value: 'Platform' },
              { label: 'Severity', value: 'High' },
              { label: 'Environment', value: 'production' },
              { label: 'Opened', value: '09:41 UTC' },
            ].map(f => (
              <div key={f.label} className="flex items-center justify-between">
                <span className="text-xs text-ot3">{f.label}</span>
                <span className="text-xs text-ot1 font-medium">{f.value}</span>
              </div>
            ))}
          </div>

          {/* Related */}
          <div className="rounded-xl bg-os1 border border-oline p-4">
            <span className="text-xs font-medium text-ot2 mb-3 block">Related</span>
            <div className="space-y-2">
              <Link to="/app/intelligence/investigation/inv-021"
                className="flex items-center gap-2 text-xs text-ot2 hover:text-oaccent transition-colors">
                <Brain size={12} /> ORACLE investigation
              </Link>
              <Link to="/app/operations/deployments/deploy-769"
                className="flex items-center gap-2 text-xs text-ot2 hover:text-oaccent transition-colors">
                <Rocket size={12} /> deploy-769 (likely cause)
              </Link>
            </div>
          </div>

          {/* ORACLE recommended action */}
          <div className="rounded-xl bg-oaccent/5 border border-oaccent/25 p-4">
            <div className="flex items-center gap-2 mb-2">
              <Brain size={13} className="text-oaccent" />
              <span className="text-xs font-medium text-oaccent">ORACLE Recommendation</span>
            </div>
            <p className="text-xs text-ot2 mb-3">Rollback notification-worker to v1.4.6 to remove the shared-utils regression.</p>
            <button className="w-full flex items-center justify-center gap-1.5 py-2 rounded-lg bg-oaccent text-white text-xs font-medium hover:bg-indigo-500 transition-colors">
              <Zap size={12} /> Execute Rollback
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
