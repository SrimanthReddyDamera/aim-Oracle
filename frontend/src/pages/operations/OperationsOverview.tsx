import { useState } from 'react'
import { Link } from 'react-router'
import { AlertTriangle, Rocket, GitBranch, Clock, ChevronRight, Filter, Search } from 'lucide-react'

const tabs = ['Incidents', 'Deployments', 'Pipelines']

const incidents = [
  { id: 'INC-0291', title: 'Elevated latency on payment-service', severity: 'high', status: 'investigating', env: 'production', duration: '18m', team: 'Platform', assigned: 'Morgan L.' },
  { id: 'INC-0290', title: 'Memory leak in recommendation-worker', severity: 'medium', status: 'investigating', env: 'production', duration: '1h 4m', team: 'ML', assigned: 'Alex K.' },
  { id: 'INC-0289', title: 'Elevated 5xx rate on api-gateway', severity: 'low', status: 'monitoring', env: 'staging', duration: '3h 22m', team: 'Platform', assigned: 'Jordan D.' },
  { id: 'INC-0288', title: 'auth-service OOM killed on pod restart', severity: 'medium', status: 'resolved', env: 'production', duration: '11m', team: 'Auth', assigned: 'Sam R.' },
  { id: 'INC-0287', title: 'CDN cache invalidation loop', severity: 'low', status: 'resolved', env: 'production', duration: '2h 8m', team: 'Infra', assigned: 'Taylor W.' },
]

const deployments = [
  { id: 'deploy-771', service: 'api-gateway', version: 'v3.14.2', env: 'production', status: 'running', progress: 62, initiator: 'GitHub Actions', ago: '4m ago' },
  { id: 'deploy-770', service: 'auth-service', version: 'v2.9.0', env: 'staging', status: 'succeeded', progress: 100, initiator: 'GitHub Actions', ago: '31m ago' },
  { id: 'deploy-769', service: 'notification-worker', version: 'v1.4.7', env: 'production', status: 'succeeded', progress: 100, initiator: 'GitHub Actions', ago: '2h ago' },
  { id: 'deploy-768', service: 'payment-service', version: 'v4.2.1', env: 'staging', status: 'failed', progress: 45, initiator: 'Jordan D.', ago: '4h ago' },
]

const pipelines = [
  { id: 'pipe-8821', name: 'api-gateway · CI', branch: 'main', status: 'running', stage: 'Integration Tests', duration: '4m 12s', ago: '4m ago' },
  { id: 'pipe-8820', name: 'auth-service · Release', branch: 'release/2.9', status: 'succeeded', stage: 'Deploy → Staging', duration: '8m 37s', ago: '32m ago' },
  { id: 'pipe-8819', name: 'payment-service · CI', branch: 'feat/retry-logic', status: 'failed', stage: 'Unit Tests', duration: '2m 14s', ago: '1h ago' },
  { id: 'pipe-8818', name: 'frontend · CI', branch: 'main', status: 'succeeded', stage: 'Build', duration: '3m 52s', ago: '1h 20m ago' },
]

const sevColor: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/25',
  high: 'text-ored bg-ored/10 border-ored/25',
  medium: 'text-oamber bg-oamber/10 border-oamber/25',
  low: 'text-oblue bg-oblue/10 border-oblue/25',
}

const statusColor: Record<string, string> = {
  investigating: 'text-ored bg-ored/10',
  monitoring: 'text-oamber bg-oamber/10',
  resolved: 'text-ogreen bg-ogreen/10',
  running: 'text-oamber bg-oamber/10',
  succeeded: 'text-ogreen bg-ogreen/10',
  failed: 'text-ored bg-ored/10',
}

export default function OperationsOverview() {
  const [tab, setTab] = useState('Incidents')
  const [search, setSearch] = useState('')

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-ot1">Operations</h1>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-os1 border border-oline">
            <Search size={13} className="text-ot3" />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Filter..."
              className="w-36 bg-transparent text-xs text-ot1 placeholder-ot3 focus:outline-none" />
          </div>
          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-os1 border border-oline text-xs text-ot2 hover:text-ot1">
            <Filter size={13} /> Filter
          </button>
          <Link to="/app/operations/automation"
            className="px-3 py-1.5 rounded-lg bg-oaccent text-white text-xs font-medium hover:bg-indigo-500 transition-colors">
            Automation
          </Link>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-os1 p-0.5 rounded-lg border border-oline w-fit">
        {tabs.map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`flex items-center gap-1.5 px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              tab === t ? 'bg-os2 text-ot1' : 'text-ot2 hover:text-ot1'
            }`}>
            {t === 'Incidents' && <AlertTriangle size={13} />}
            {t === 'Deployments' && <Rocket size={13} />}
            {t === 'Pipelines' && <GitBranch size={13} />}
            {t}
          </button>
        ))}
      </div>

      {/* Incidents table */}
      {tab === 'Incidents' && (
        <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-oline">
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">ID</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Title</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Severity</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Status</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Env</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Duration</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Assigned</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-oline">
              {incidents.filter(i => i.title.toLowerCase().includes(search.toLowerCase())).map(inc => (
                <tr key={inc.id} className="hover:bg-os2 transition-colors">
                  <td className="px-4 py-3">
                    <Link to={`/app/operations/incidents/${inc.id}`}
                      className="text-xs font-mono text-oaccent hover:text-indigo-400">{inc.id}</Link>
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/app/operations/incidents/${inc.id}`}
                      className="text-sm text-ot1 hover:text-oaccent transition-colors">{inc.title}</Link>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${sevColor[inc.severity]}`}>{inc.severity}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${statusColor[inc.status]}`}>{inc.status}</span>
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-ot2">{inc.env}</td>
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1 text-xs text-ot2"><Clock size={11} />{inc.duration}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-ot2">{inc.assigned}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Deployments table */}
      {tab === 'Deployments' && (
        <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-oline">
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">ID</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Service</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Version</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Environment</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Status</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Progress</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-oline">
              {deployments.map(d => (
                <tr key={d.id} className="hover:bg-os2 transition-colors">
                  <td className="px-4 py-3">
                    <Link to={`/app/operations/deployments/${d.id}`}
                      className="text-xs font-mono text-oaccent hover:text-indigo-400">{d.id}</Link>
                  </td>
                  <td className="px-4 py-3 text-sm text-ot1 font-medium">{d.service}</td>
                  <td className="px-4 py-3 text-xs font-mono text-ot2">{d.version}</td>
                  <td className="px-4 py-3 text-xs font-mono text-ot2">{d.env}</td>
                  <td className="px-4 py-3">
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${statusColor[d.status]}`}>{d.status}</span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1 rounded-full bg-os2">
                        <div className={`h-full rounded-full ${d.status === 'failed' ? 'bg-ored' : d.status === 'running' ? 'bg-oamber' : 'bg-ogreen'}`}
                          style={{ width: `${d.progress}%` }} />
                      </div>
                      <span className="text-[10px] font-mono text-ot3">{d.progress}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-ot3">{d.ago}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pipelines table */}
      {tab === 'Pipelines' && (
        <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-oline">
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Pipeline</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Branch</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Status</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Stage</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Duration</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-oline">
              {pipelines.map(p => (
                <tr key={p.id} className="hover:bg-os2 transition-colors">
                  <td className="px-4 py-3">
                    <Link to={`/app/operations/pipelines/${p.id}`}
                      className="text-sm text-ot1 hover:text-oaccent transition-colors">{p.name}</Link>
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-ot2">{p.branch}</td>
                  <td className="px-4 py-3">
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${statusColor[p.status]}`}>{p.status}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-ot2">{p.stage}</td>
                  <td className="px-4 py-3 text-xs font-mono text-ot2">{p.duration}</td>
                  <td className="px-4 py-3 text-xs text-ot3">{p.ago}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
