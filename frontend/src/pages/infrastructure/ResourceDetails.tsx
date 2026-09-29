import { useParams, Link } from 'react-router'
import { ChevronLeft, Brain, AlertTriangle, Server } from 'lucide-react'

const metricHistory = [
  { time: '09:00', cpu: 61, memory: 71 },
  { time: '09:10', cpu: 64, memory: 73 },
  { time: '09:20', cpu: 70, memory: 76 },
  { time: '09:30', cpu: 75, memory: 81 },
  { time: '09:40', cpu: 82, memory: 89 },
]

const events = [
  { time: '09:35', event: 'Memory utilization exceeded 85% threshold', type: 'warning' },
  { time: '09:20', event: 'Automated checkpoint completed', type: 'info' },
  { time: '08:00', event: 'Daily maintenance window: VACUUM ANALYZE', type: 'info' },
]

export default function ResourceDetails() {
  const { id } = useParams()
  const latest = metricHistory[metricHistory.length - 1]

  return (
    <div className="space-y-6 max-w-4xl">
      <Link to="/app/infrastructure" className="flex items-center gap-1.5 text-xs text-ot2 hover:text-ot1 transition-colors">
        <ChevronLeft size={14} /> Infrastructure
      </Link>

      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded text-oamber bg-oamber/10">warning</span>
            <span className="text-[10px] font-mono text-ot3">RDS PostgreSQL · us-east-1</span>
          </div>
          <h1 className="text-xl font-semibold text-ot1 font-mono">{id}</h1>
        </div>
        <Link to="/app/intelligence"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-oaccent/10 border border-oaccent/20 text-xs text-oaccent">
          <Brain size={13} /> AI Analysis
        </Link>
      </div>

      {/* Current metrics */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'CPU', value: `${latest.cpu}%`, warn: latest.cpu > 75 },
          { label: 'Memory', value: `${latest.memory}%`, warn: latest.memory > 80 },
          { label: 'Connections', value: '248/300', warn: false },
          { label: 'IOPS', value: '1,842', warn: false },
        ].map(m => (
          <div key={m.label} className={`p-3 rounded-lg border ${m.warn ? 'bg-oamber/5 border-oamber/25' : 'bg-os1 border-oline'}`}>
            <div className="text-xs text-ot3 mb-1">{m.label}</div>
            <div className={`text-xl font-bold font-mono ${m.warn ? 'text-oamber' : 'text-ot1'}`}>{m.value}</div>
          </div>
        ))}
      </div>

      {/* Sparkline chart (CSS-based) */}
      <div className="rounded-xl bg-os1 border border-oline p-4">
        <div className="flex items-center justify-between mb-4">
          <span className="text-sm font-medium text-ot1">CPU & Memory (last hour)</span>
        </div>
        <div className="flex items-end gap-2 h-24">
          {metricHistory.map((m, i) => (
            <div key={i} className="flex-1 flex items-end gap-0.5">
              <div className="flex-1 rounded-sm bg-oaccent/60 transition-all" style={{ height: `${m.cpu}%` }} title={`CPU ${m.cpu}%`} />
              <div className="flex-1 rounded-sm bg-oamber/60 transition-all" style={{ height: `${m.memory}%` }} title={`Mem ${m.memory}%`} />
            </div>
          ))}
        </div>
        <div className="flex justify-between mt-2">
          {metricHistory.map(m => (
            <span key={m.time} className="text-[10px] font-mono text-ot3">{m.time}</span>
          ))}
        </div>
        <div className="flex items-center gap-4 mt-3">
          <span className="flex items-center gap-1.5 text-[10px] text-ot2"><span className="w-2 h-2 rounded-sm bg-oaccent/60" />CPU</span>
          <span className="flex items-center gap-1.5 text-[10px] text-ot2"><span className="w-2 h-2 rounded-sm bg-oamber/60" />Memory</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Config */}
        <div className="rounded-xl bg-os1 border border-oline p-4">
          <span className="text-sm font-medium text-ot1 mb-3 block">Configuration</span>
          <div className="space-y-2">
            {[
              { k: 'Instance class', v: 'db.r6g.2xlarge' },
              { k: 'Engine', v: 'PostgreSQL 15.4' },
              { k: 'Storage', v: '500 GB gp3' },
              { k: 'Multi-AZ', v: 'Yes' },
              { k: 'Backup retention', v: '30 days' },
            ].map(f => (
              <div key={f.k} className="flex justify-between">
                <span className="text-xs text-ot3">{f.k}</span>
                <span className="text-xs font-mono text-ot1">{f.v}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Events */}
        <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
          <div className="px-4 py-3 border-b border-oline">
            <span className="text-sm font-medium text-ot1">Events</span>
          </div>
          <div className="divide-y divide-oline">
            {events.map((e, i) => (
              <div key={i} className="flex items-start gap-3 px-4 py-2.5">
                <span className="text-[10px] font-mono text-ot3 w-12 flex-shrink-0 mt-0.5">{e.time}</span>
                <span className={`w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0 ${e.type === 'warning' ? 'bg-oamber' : 'bg-oline2'}`} />
                <span className="text-xs text-ot2">{e.event}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
