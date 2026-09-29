import { Link } from 'react-router'
import { Server, Cpu, MemoryStick, HardDrive, AlertTriangle, ChevronRight, Activity } from 'lucide-react'

const resources = [
  { id: 'k8s-prod', name: 'k8s-prod', type: 'Kubernetes Cluster', status: 'healthy', cpu: 68, memory: 74, pods: '142/160', region: 'us-east-1' },
  { id: 'k8s-staging', name: 'k8s-staging', type: 'Kubernetes Cluster', status: 'healthy', cpu: 31, memory: 42, pods: '48/80', region: 'us-east-1' },
  { id: 'postgres-primary', name: 'postgres-primary', type: 'RDS PostgreSQL', status: 'warning', cpu: 82, memory: 89, pods: null, region: 'us-east-1' },
  { id: 'redis-cache', name: 'redis-cache', type: 'ElastiCache Redis', status: 'healthy', cpu: 24, memory: 61, pods: null, region: 'us-east-1' },
  { id: 'kafka-prod', name: 'kafka-prod', type: 'MSK Kafka', status: 'healthy', cpu: 45, memory: 58, pods: null, region: 'us-east-1' },
  { id: 'cdn-global', name: 'cdn-global', type: 'CloudFront CDN', status: 'healthy', cpu: null, memory: null, pods: null, region: 'Global' },
]

const alerts = [
  { id: 'alert-021', resource: 'postgres-primary', message: 'Memory utilization > 85% for 15 minutes', severity: 'warning', ago: '8m ago' },
  { id: 'alert-020', resource: 'k8s-prod', message: 'Pod evictions detected — disk pressure on node-07', severity: 'info', ago: '1h ago' },
]

const statusColor: Record<string, { dot: string, text: string }> = {
  healthy: { dot: 'bg-ogreen', text: 'text-ogreen' },
  warning: { dot: 'bg-oamber', text: 'text-oamber' },
  critical: { dot: 'bg-ored', text: 'text-ored' },
  unknown: { dot: 'bg-ot3', text: 'text-ot3' },
}

function MetricBar({ value, warn = 75, crit = 90 }: { value: number | null, warn?: number, crit?: number }) {
  if (value === null) return <span className="text-xs text-ot3">—</span>
  const color = value >= crit ? 'bg-ored' : value >= warn ? 'bg-oamber' : 'bg-ogreen'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 rounded-full bg-os2">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${value}%` }} />
      </div>
      <span className={`text-xs font-mono ${value >= crit ? 'text-ored' : value >= warn ? 'text-oamber' : 'text-ot1'}`}>{value}%</span>
    </div>
  )
}

export default function InfrastructureOverview() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-ot1">Infrastructure</h1>
        <div className="flex items-center gap-2">
          <Link to="/app/infrastructure/topology"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-os1 border border-oline text-xs text-ot2 hover:text-ot1 transition-colors">
            <Activity size={13} /> System Topology
          </Link>
        </div>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Healthy', value: '5', color: 'text-ogreen' },
          { label: 'Warning', value: '1', color: 'text-oamber' },
          { label: 'Critical', value: '0', color: 'text-ored' },
          { label: 'Active Alerts', value: '2', color: 'text-oamber' },
        ].map(s => (
          <div key={s.label} className="p-3 rounded-lg bg-os1 border border-oline">
            <div className="text-xs text-ot3 mb-1">{s.label}</div>
            <div className={`text-2xl font-bold font-mono ${s.color}`}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Resources table */}
      <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
        <div className="px-4 py-3 border-b border-oline">
          <span className="text-sm font-medium text-ot1">Resources</span>
        </div>
        <table className="w-full">
          <thead>
            <tr className="border-b border-oline">
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2.5">Resource</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2.5">Type</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2.5">Status</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2.5">CPU</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2.5">Memory</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2.5">Region</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-oline">
            {resources.map(r => {
              const sc = statusColor[r.status]
              return (
                <tr key={r.id} className="hover:bg-os2 transition-colors">
                  <td className="px-4 py-3">
                    <Link to={`/app/infrastructure/resources/${r.id}`}
                      className="text-sm font-medium text-ot1 hover:text-oaccent transition-colors font-mono">{r.name}</Link>
                  </td>
                  <td className="px-4 py-3 text-xs text-ot2">{r.type}</td>
                  <td className="px-4 py-3">
                    <span className={`flex items-center gap-1.5 text-xs ${sc.text}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${sc.dot}`} />
                      {r.status}
                    </span>
                  </td>
                  <td className="px-4 py-3"><MetricBar value={r.cpu} /></td>
                  <td className="px-4 py-3"><MetricBar value={r.memory} /></td>
                  <td className="px-4 py-3 text-xs font-mono text-ot2">{r.region}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Alerts */}
      {alerts.length > 0 && (
        <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
          <div className="px-4 py-3 border-b border-oline">
            <span className="text-sm font-medium text-ot1 flex items-center gap-2">
              <AlertTriangle size={14} className="text-oamber" /> Active Alerts
            </span>
          </div>
          <div className="divide-y divide-oline">
            {alerts.map(a => (
              <div key={a.id} className="flex items-start gap-3 px-4 py-3">
                <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border flex-shrink-0 mt-0.5 ${
                  a.severity === 'warning' ? 'text-oamber bg-oamber/10 border-oamber/25' : 'text-oblue bg-oblue/10 border-oblue/25'
                }`}>{a.severity}</span>
                <div className="flex-1">
                  <span className="text-xs font-medium text-ot2 font-mono">{a.resource}</span>
                  <p className="text-xs text-ot1">{a.message}</p>
                </div>
                <span className="text-[10px] text-ot3 flex-shrink-0">{a.ago}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
