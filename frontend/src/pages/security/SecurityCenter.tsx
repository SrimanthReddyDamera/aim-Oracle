import { useState } from 'react'
import { Link } from 'react-router'
import { Shield, AlertTriangle, Lock, Package, ChevronRight, Brain, Search } from 'lucide-react'

const findings = [
  { id: 'SEC-0142', title: 'Exposed AWS credentials in environment variable log output', severity: 'critical', type: 'secret', repo: 'api-gateway', status: 'open', ago: '2h ago' },
  { id: 'SEC-0141', title: 'CVE-2024-21626 — runc container breakout vulnerability', severity: 'high', type: 'vulnerability', repo: 'k8s-prod', status: 'open', ago: '6h ago' },
  { id: 'SEC-0140', title: 'Outdated lodash 4.17.15 with known prototype pollution', severity: 'high', type: 'dependency', repo: 'frontend', status: 'open', ago: '1d ago' },
  { id: 'SEC-0139', title: 'Missing rate limiting on /api/auth/login endpoint', severity: 'medium', type: 'vulnerability', repo: 'api-gateway', status: 'open', ago: '2d ago' },
  { id: 'SEC-0138', title: 'SQL query built with string concatenation (potential injection)', severity: 'medium', type: 'vulnerability', repo: 'payment-service', status: 'open', ago: '3d ago' },
  { id: 'SEC-0137', title: 'npm package colors 1.4.0 contains malicious code', severity: 'low', type: 'dependency', repo: 'notification-worker', status: 'resolved', ago: '4d ago' },
]

const severityColor: Record<string, string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/25',
  high: 'text-ored bg-ored/10 border-ored/25',
  medium: 'text-oamber bg-oamber/10 border-oamber/25',
  low: 'text-oblue bg-oblue/10 border-oblue/25',
}

const typeIcon: Record<string, React.ElementType> = {
  secret: Lock,
  vulnerability: AlertTriangle,
  dependency: Package,
}

export default function SecurityCenter() {
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('All')

  const filtered = findings.filter(f =>
    f.title.toLowerCase().includes(search.toLowerCase()) &&
    (filter === 'All' || f.status === filter.toLowerCase() || f.severity === filter.toLowerCase())
  )

  const counts = {
    critical: findings.filter(f => f.severity === 'critical' && f.status === 'open').length,
    high: findings.filter(f => f.severity === 'high' && f.status === 'open').length,
    medium: findings.filter(f => f.severity === 'medium' && f.status === 'open').length,
    score: 84,
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-ot1 flex items-center gap-2">
          <Shield size={18} className="text-oamber" />
          Security Center
        </h1>
        <div className="flex items-center gap-2 text-xs text-oaccent bg-oaccent/5 border border-oaccent/20 px-3 py-1.5 rounded-lg">
          <Brain size={13} />
          AI Security Analysis active
        </div>
      </div>

      {/* Score + summary */}
      <div className="grid grid-cols-4 gap-3">
        <div className="p-4 rounded-xl bg-os1 border border-oamber/25">
          <div className="text-xs text-ot3 mb-1">Security Score</div>
          <div className="text-3xl font-bold font-mono text-oamber">{counts.score}</div>
          <div className="text-xs text-ot3 mt-0.5">/ 100</div>
        </div>
        <div className="p-4 rounded-xl bg-os1 border border-oline">
          <div className="text-xs text-ot3 mb-1">Critical</div>
          <div className="text-3xl font-bold font-mono text-red-400">{counts.critical}</div>
        </div>
        <div className="p-4 rounded-xl bg-os1 border border-oline">
          <div className="text-xs text-ot3 mb-1">High</div>
          <div className="text-3xl font-bold font-mono text-ored">{counts.high}</div>
        </div>
        <div className="p-4 rounded-xl bg-os1 border border-oline">
          <div className="text-xs text-ot3 mb-1">Medium</div>
          <div className="text-3xl font-bold font-mono text-oamber">{counts.medium}</div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-os1 border border-oline flex-1 max-w-xs">
          <Search size={13} className="text-ot3" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search findings..."
            className="flex-1 bg-transparent text-xs text-ot1 placeholder-ot3 focus:outline-none" />
        </div>
        <div className="flex bg-os1 rounded-lg border border-oline p-0.5">
          {['All', 'open', 'resolved'].map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`px-3 py-1 rounded-md text-xs font-medium transition-colors ${
                filter === f ? 'bg-os2 text-ot1' : 'text-ot2 hover:text-ot1'
              }`}>{f.charAt(0).toUpperCase() + f.slice(1)}</button>
          ))}
        </div>
      </div>

      {/* Findings table */}
      <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-oline">
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Severity</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Finding</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Type</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Resource</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Status</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Detected</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-oline">
            {filtered.map(f => {
              const Icon = typeIcon[f.type] ?? AlertTriangle
              return (
                <tr key={f.id} className="hover:bg-os2 transition-colors">
                  <td className="px-4 py-3">
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${severityColor[f.severity]}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/app/security/findings/${f.id}`}
                      className="text-sm text-ot1 hover:text-oaccent transition-colors line-clamp-1">{f.title}</Link>
                    <span className="text-[10px] font-mono text-ot3">{f.id}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-1 text-xs text-ot2"><Icon size={12} />{f.type}</span>
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-ot2">{f.repo}</td>
                  <td className="px-4 py-3">
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                      f.status === 'open' ? 'text-ored bg-ored/10' : 'text-ogreen bg-ogreen/10'
                    }`}>{f.status}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-ot3">{f.ago}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
