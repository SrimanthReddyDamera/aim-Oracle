import { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router'
import {
  AlertTriangle, Rocket, GitBranch, Shield, TrendingUp, TrendingDown,
  CheckCircle2, Clock, ArrowUpRight, Brain, Activity, Cpu, Zap, ChevronRight, Plus, RefreshCw, X
} from 'lucide-react'
import { oracleApi } from '@/lib/api'
import { IncidentInvestigation, SystemMetrics } from '@/types/oracle'

const severityColor: Record<string, string> = {
  HIGH: 'text-ored bg-ored/10 border-ored/25',
  high: 'text-ored bg-ored/10 border-ored/25',
  MEDIUM: 'text-oamber bg-oamber/10 border-oamber/25',
  medium: 'text-oamber bg-oamber/10 border-oamber/25',
  LOW: 'text-oblue bg-oblue/10 border-oblue/25',
  low: 'text-oblue bg-oblue/10 border-oblue/25',
  CRITICAL: 'text-red-400 bg-red-400/10 border-red-400/25',
  critical: 'text-red-400 bg-red-400/10 border-red-400/25',
}

const statusColor: Record<string, string> = {
  running: 'text-oamber bg-oamber/10',
  succeeded: 'text-ogreen bg-ogreen/10',
  failed: 'text-ored bg-ored/10',
}

const activityColor: Record<string, string> = {
  incident: 'bg-ored',
  deploy: 'bg-ogreen',
  oracle: 'bg-oaccent',
  pr: 'bg-oblue',
  security: 'bg-oamber',
}

const deployments = [
  { id: 'deploy-771', service: 'auth-service', version: 'v3.1.4', env: 'production', status: 'succeeded', progress: 100, ago: '2m ago' },
  { id: 'deploy-770', service: 'payment_gateway', version: 'v2.14.3', env: 'production', status: 'running', progress: 74, ago: '8m ago' },
  { id: 'deploy-769', service: 'aim-oracle-engine', version: 'v4.5.0', env: 'production', status: 'succeeded', progress: 100, ago: '24m ago' },
]

const insights = [
  { id: 1, type: 'causal', title: 'KAN-4: JWT expiration cascade correlated to auth-service deployment', confidence: 94, time: 'Just now' },
  { id: 2, type: 'anomaly', title: 'mTLS 1.3 session ticket invalidation observed on Redis failover', confidence: 98, time: '11m ago' },
  { id: 3, type: 'prediction', title: 'Automated remediation patch verified in sandbox with 0 regressions', confidence: 96, time: '18m ago' },
]

const activity = [
  { time: '15:21', event: 'Autonomous investigation created for Jira ticket KAN-4 (auth-service)', type: 'oracle' },
  { time: '15:18', event: 'Sandbox replay gate executed for ORC-INC-2026-9496 — PASSED', type: 'oracle' },
  { time: '15:15', event: 'GitHub repository SrimanthReddyDamera/aim-Oracle telemetry synchronized', type: 'deploy' },
  { time: '15:14', event: 'Jira Cloud starkindustries4229.atlassian.net (Project KAN) health 200 OK', type: 'pr' },
  { time: '14:48', event: 'INC-2026-0402 verified in ephemeral container with cryptographic attestation', type: 'security' },
]

export default function CommandCenter() {
  const navigate = useNavigate()
  const [liveIncidents, setLiveIncidents] = useState<IncidentInvestigation[]>([])
  const [metrics, setMetrics] = useState<SystemMetrics>({
    activeInvestigations: 3,
    investigationsCompleted: 2,
    verifiedResolutions: 2,
    evidenceItemsProcessed: 28,
  })
  const [loading, setLoading] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [newTitle, setNewTitle] = useState('KAN-4: Authentication token validation failure during customer login')
  const [newService, setNewService] = useState('auth-service')
  const [newRepo, setNewRepo] = useState('SrimanthReddyDamera/aim-Oracle')
  const [newStack, setNewStack] = useState('auth_service.py:142: verify_jwt_token() raised TokenExpiredError')

  const fetchLive = async () => {
    setLoading(true)
    try {
      const [invs, m] = await Promise.all([
        oracleApi.getInvestigations(),
        oracleApi.getSystemMetrics(),
      ])
      if (invs && invs.length > 0) {
        setLiveIncidents(invs)
      }
      if (m) {
        setMetrics(m)
      }
    } catch (e) {
      console.warn('Backend polling error:', e)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchLive()
    const timer = setInterval(fetchLive, 10000)
    return () => clearInterval(timer)
  }, [])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const res = await oracleApi.createInvestigation({
        title: newTitle,
        service: newService,
        environment: 'production',
        repository: newRepo,
        stackTrace: newStack,
        deployment: 'v3.1.4',
        cloudProvider: 'aws-us-east-1',
        timeRange: 'Past 30 minutes',
        additionalNotes: 'Triggered from ORACLE Enterprise Command Center',
        selectedSources: ['jira', 'github', 'logs', 'apm'],
      })
      setModalOpen(false)
      fetchLive()
      navigate(`/app/intelligence/investigation/${res.id || 'ORC-INC-2026-9496'}`)
    } catch (err: any) {
      alert(`Investigation creation error: ${err.message || err}`)
    }
  }

  const kpis = [
    { label: 'Active Incidents', value: String(metrics.activeInvestigations || liveIncidents.length || 3), delta: 'Live', trend: 'up', color: 'ored', icon: AlertTriangle },
    { label: 'Verified Gates', value: String(metrics.verifiedResolutions || 2), delta: '+2 today', trend: 'up', color: 'ogreen', icon: Rocket },
    { label: 'Evidence Processed', value: String(metrics.evidenceItemsProcessed || 28), delta: '+12 items', trend: 'up', color: 'oblue', icon: GitBranch },
    { label: 'Security Health', value: '98%', delta: 'Attested', trend: 'up', color: 'oaccent', icon: Shield },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-ot1">Command Center</h1>
          <p className="text-sm text-ot2 mt-0.5">Tuesday, September 29, 2026 · 09:44 UTC</p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-oaccent/10 border border-oaccent/20 text-xs text-oaccent font-mono">
          <span className="w-1.5 h-1.5 rounded-full bg-oaccent oa-ping" />
          ORACLE active · 3 investigations running
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-4 gap-4">
        {kpis.map(k => {
          const Icon = k.icon
          return (
            <div key={k.label} className="p-4 rounded-xl bg-os1 border border-oline">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs text-ot2">{k.label}</span>
                <Icon size={14} className={`text-${k.color}`} />
              </div>
              <div className="text-2xl font-bold font-mono text-ot1 mb-1">{k.value}</div>
              <div className={`flex items-center gap-1 text-xs ${
                k.trend === 'up' ? (k.color === 'ored' ? 'text-ored' : 'text-ogreen') :
                (k.color === 'ored' ? 'text-ogreen' : 'text-ored')
              }`}>
                {k.trend === 'up' ? <TrendingUp size={11} /> : <TrendingDown size={11} />}
                {k.delta} from yesterday
              </div>
            </div>
          )
        })}
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-3 gap-4">
        {/* Active Incidents */}
        <div className="col-span-2 rounded-xl bg-os1 border border-oline overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-oline">
            <span className="text-sm font-medium text-ot1 flex items-center gap-2">
              <AlertTriangle size={14} className="text-ored" />
              Active Incidents & Ingress
              <span className="text-[10px] font-mono text-ogreen bg-ogreen/10 px-1.5 py-0.5 rounded border border-ogreen/20">LIVE</span>
            </span>
            <div className="flex items-center gap-3">
              <button
                onClick={() => setModalOpen(true)}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-oaccent text-white text-xs font-medium hover:bg-indigo-500 transition-colors"
              >
                <Plus size={12} /> New Investigation
              </button>
              <button
                onClick={fetchLive}
                className="text-xs text-ot3 hover:text-ot1 transition-colors p-1"
                title="Refresh"
              >
                <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
              </button>
              <Link to="/app/operations" className="text-xs text-oaccent hover:text-indigo-400 flex items-center gap-1">
                All <ChevronRight size={12} />
              </Link>
            </div>
          </div>
          <div className="divide-y divide-oline">
            {(liveIncidents.length > 0 ? liveIncidents : [
              {
                id: 'ORC-INC-2026-9496',
                title: 'KAN-4: Authentication token validation failure during customer login',
                severity: 'HIGH',
                service: 'auth-service',
                environment: 'production',
                jiraKey: 'KAN-4',
                confidence: 94,
                stage: 'ROOT_CAUSE_IDENTIFIED',
                createdAt: '2026-09-29T15:21:00Z',
                assigned: 'SRE',
              },
              {
                id: 'INC-1042',
                title: 'Payment API returning 500 errors (PR #284 cache key migration)',
                severity: 'HIGH',
                service: 'payment-api',
                environment: 'production',
                jiraKey: 'PAY-1042',
                confidence: 94,
                stage: 'ROOT_CAUSE_IDENTIFIED',
                createdAt: '2026-09-29T14:24:00Z',
                assigned: 'ORACLE',
              }
            ]).map(inc => (
              <Link key={inc.id} to={`/app/intelligence/investigation/${inc.id}`}
                className="flex items-center gap-3 px-4 py-3 hover:bg-os2 transition-colors group">
                <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${severityColor[inc.severity] || severityColor.HIGH}`}>
                  {inc.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-ot1 truncate group-hover:text-oaccent transition-colors font-medium">
                    {inc.title}
                  </div>
                  <div className="text-xs text-ot3 font-mono mt-0.5 flex items-center gap-2">
                    <span className="text-oaccent">{inc.id}</span>
                    <span>·</span>
                    <span>{inc.service}</span>
                    <span>·</span>
                    <span>{inc.environment || 'production'}</span>
                    {(inc as any).jiraKey && (
                      <>
                        <span>·</span>
                        <span className="text-oblue bg-oblue/10 px-1 rounded">{(inc as any).jiraKey}</span>
                      </>
                    )}
                    <span>·</span>
                    <span className="text-ogreen font-semibold">{inc.confidence || 94}% confidence</span>
                  </div>
                </div>
                <div className="w-6 h-6 rounded-full bg-os2 border border-oline flex items-center justify-center text-[10px] font-medium text-ot2">
                  {(inc as any).assigned || 'AI'}
                </div>
              </Link>
            ))}
          </div>
        </div>

        {/* ORACLE Insights */}
        <div className="rounded-xl bg-os1 border border-oaccent/20 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-oaccent/20 bg-oaccent/5">
            <span className="text-sm font-medium text-ot1 flex items-center gap-2">
              <Brain size={14} className="text-oaccent" />
              ORACLE Insights
            </span>
            <Link to="/app/intelligence" className="text-xs text-oaccent hover:text-indigo-400 flex items-center gap-1">
              Intelligence <ChevronRight size={12} />
            </Link>
          </div>
          <div className="divide-y divide-oline">
            {insights.map(ins => (
              <div key={ins.id} className="px-4 py-3">
                <div className="flex items-start justify-between gap-2 mb-1">
                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                    ins.type === 'anomaly' ? 'text-ored bg-ored/10 border-ored/25' :
                    ins.type === 'prediction' ? 'text-oamber bg-oamber/10 border-oamber/25' :
                    'text-oaccent bg-oaccent/10 border-oaccent/25'
                  }`}>{ins.type}</span>
                  <span className="text-[10px] font-mono text-ot3">{ins.time}</span>
                </div>
                <p className="text-xs text-ot1 leading-relaxed mb-1">{ins.title}</p>
                <div className="flex items-center gap-1.5">
                  <div className="flex-1 h-1 rounded-full bg-os2">
                    <div className="h-full rounded-full bg-oaccent" style={{ width: `${ins.confidence}%` }} />
                  </div>
                  <span className="text-[10px] font-mono text-oaccent">{ins.confidence}%</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Deployments + Activity */}
      <div className="grid grid-cols-2 gap-4">
        {/* Active Deployments */}
        <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-oline">
            <span className="text-sm font-medium text-ot1 flex items-center gap-2">
              <Rocket size={14} className="text-ogreen" />
              Active Deployments
            </span>
            <Link to="/app/operations" className="text-xs text-oaccent hover:text-indigo-400 flex items-center gap-1">
              All <ChevronRight size={12} />
            </Link>
          </div>
          <div className="divide-y divide-oline">
            {deployments.map(d => (
              <Link key={d.id} to={`/app/operations/deployments/${d.id}`}
                className="flex items-center gap-3 px-4 py-3 hover:bg-os2 transition-colors group">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm text-ot1 font-medium truncate">{d.service}</span>
                    <span className="text-[10px] font-mono text-ot3">{d.version}</span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${statusColor[d.status]}`}>{d.status}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1 rounded-full bg-os2">
                      <div className={`h-full rounded-full transition-all ${d.status === 'succeeded' ? 'bg-ogreen' : 'bg-oamber'}`}
                        style={{ width: `${d.progress}%` }} />
                    </div>
                    <span className="text-[10px] font-mono text-ot3">{d.ago}</span>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </div>

        {/* Live Activity Feed */}
        <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-oline">
            <span className="text-sm font-medium text-ot1 flex items-center gap-2">
              <Activity size={14} className="text-oblue" />
              Live Activity
            </span>
            <span className="flex items-center gap-1.5 text-[10px] font-mono text-ogreen">
              <span className="w-1.5 h-1.5 rounded-full bg-ogreen oa-ping" />
              Live
            </span>
          </div>
          <div className="divide-y divide-oline max-h-60 overflow-y-auto">
            {activity.map((a, i) => (
              <div key={i} className="flex items-start gap-3 px-4 py-2.5">
                <span className="text-[10px] font-mono text-ot3 mt-0.5 w-10 flex-shrink-0">{a.time}</span>
                <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 mt-1.5 ${activityColor[a.type]}`} />
                <span className="text-xs text-ot2 leading-relaxed">{a.event}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* New Investigation Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-os1 border border-oline rounded-xl overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between px-5 py-4 border-b border-oline bg-os2">
              <div className="flex items-center gap-2">
                <Brain size={16} className="text-oaccent" />
                <h3 className="text-sm font-semibold text-ot1">Trigger Autonomous AI Investigation</h3>
              </div>
              <button onClick={() => setModalOpen(false)} className="text-ot3 hover:text-ot1">
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleCreate} className="p-5 space-y-4">
              <div>
                <label className="block text-xs font-medium text-ot2 mb-1">Incident / Jira Alert Title</label>
                <input
                  type="text"
                  value={newTitle}
                  onChange={e => setNewTitle(e.target.value)}
                  className="w-full px-3 py-2 bg-os2 border border-oline rounded-md text-xs text-ot1 focus:outline-none focus:border-oaccent"
                  required
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-ot2 mb-1">Impacted Microservice</label>
                  <input
                    type="text"
                    value={newService}
                    onChange={e => setNewService(e.target.value)}
                    className="w-full px-3 py-2 bg-os2 border border-oline rounded-md text-xs text-ot1 focus:outline-none focus:border-oaccent"
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-ot2 mb-1">Target GitHub Repository</label>
                  <input
                    type="text"
                    value={newRepo}
                    onChange={e => setNewRepo(e.target.value)}
                    className="w-full px-3 py-2 bg-os2 border border-oline rounded-md text-xs text-ot1 focus:outline-none focus:border-oaccent"
                    required
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-ot2 mb-1">Stack Trace / Telemetry Signature</label>
                <textarea
                  value={newStack}
                  onChange={e => setNewStack(e.target.value)}
                  rows={4}
                  className="w-full px-3 py-2 bg-os2 border border-oline rounded-md text-xs font-mono text-ot1 focus:outline-none focus:border-oaccent"
                  required
                />
              </div>
              <div className="flex items-center justify-between pt-2 border-t border-oline">
                <span className="text-[11px] text-ot3 font-mono">Sources: Jira Cloud + GitHub + APM</span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setModalOpen(false)}
                    className="px-3 py-1.5 rounded-md text-xs text-ot2 hover:text-ot1"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-1.5 rounded-md bg-oaccent text-white text-xs font-medium hover:bg-indigo-500 transition-colors flex items-center gap-1.5"
                  >
                    <Zap size={12} /> Launch Investigation
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
