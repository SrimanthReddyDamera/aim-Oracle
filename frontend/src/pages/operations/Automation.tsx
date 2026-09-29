import { useState } from 'react'
import { Link } from 'react-router'
import { Zap, Plus, Play, Pause, Clock, CheckCircle2, AlertTriangle, ChevronRight } from 'lucide-react'

const automations = [
  {
    id: 'auto-001', name: 'Auto-rollback on error spike', status: 'active',
    trigger: 'Error rate > 1% for 5 minutes', lastRun: '2h ago', runs: 14, success: 13,
    description: 'Automatically rolls back the most recent deployment when error rate spikes above threshold.',
  },
  {
    id: 'auto-002', name: 'Scale on queue depth', status: 'active',
    trigger: 'Queue depth > 1,000 messages', lastRun: '34m ago', runs: 87, success: 87,
    description: 'Scales worker pods horizontally when the task queue exceeds 1,000 pending messages.',
  },
  {
    id: 'auto-003', name: 'PagerDuty alert on critical incident', status: 'active',
    trigger: 'Incident severity = critical', lastRun: '1d ago', runs: 3, success: 3,
    description: 'Pages on-call engineer via PagerDuty within 30 seconds of a critical incident.',
  },
  {
    id: 'auto-004', name: 'Nightly security scan', status: 'paused',
    trigger: 'Cron: 02:00 UTC daily', lastRun: '22h ago', runs: 30, success: 29,
    description: 'Runs Trivy container scans and uploads results to Security Center.',
  },
]

const executions = [
  { id: 'exec-421', automation: 'Scale on queue depth', status: 'succeeded', trigger: 'Queue: 1,247 messages', ago: '34m ago' },
  { id: 'exec-420', automation: 'Auto-rollback on error spike', status: 'succeeded', trigger: 'Error rate: 1.4%', ago: '2h ago' },
  { id: 'exec-419', automation: 'Nightly security scan', status: 'succeeded', trigger: 'Cron', ago: '22h ago' },
  { id: 'exec-418', automation: 'Auto-rollback on error spike', status: 'failed', trigger: 'Error rate: 2.1%', ago: '1d ago' },
]

export default function Automation() {
  const [running, setRunning] = useState<Record<string, boolean>>({})

  const toggleRun = (id: string) =>
    setRunning(r => ({ ...r, [id]: !r[id] }))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-ot1 flex items-center gap-2">
          <Zap size={18} className="text-oaccent" />
          Automation
        </h1>
        <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-oaccent text-white text-xs font-medium hover:bg-indigo-500 transition-colors">
          <Plus size={14} /> New Automation
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {automations.map(a => (
          <div key={a.id} className="p-4 rounded-xl bg-os1 border border-oline hover:border-oline2 transition-colors">
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${a.status === 'active' ? 'bg-ogreen' : 'bg-ot3'}`} />
                <span className="text-sm font-medium text-ot1">{a.name}</span>
              </div>
              <button onClick={() => toggleRun(a.id)}
                className="text-ot3 hover:text-ot1 transition-colors">
                {a.status === 'active' ? <Pause size={14} /> : <Play size={14} />}
              </button>
            </div>
            <p className="text-xs text-ot2 mb-3">{a.description}</p>
            <div className="flex items-center gap-2 text-[10px] font-mono text-ot3 mb-3">
              <Clock size={10} /> {a.trigger}
            </div>
            <div className="flex items-center gap-4 text-[11px] text-ot3">
              <span><span className="text-ot1 font-medium">{a.runs}</span> total runs</span>
              <span><span className="text-ogreen font-medium">{a.success}</span> succeeded</span>
              <span>Last: {a.lastRun}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Execution history */}
      <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
        <div className="px-4 py-3 border-b border-oline">
          <span className="text-sm font-medium text-ot1">Recent Executions</span>
        </div>
        <table className="w-full">
          <thead>
            <tr className="border-b border-oline">
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2.5">ID</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2.5">Automation</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2.5">Trigger</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2.5">Status</th>
              <th className="text-left text-[11px] font-medium text-ot3 px-4 py-2.5">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-oline">
            {executions.map(e => (
              <tr key={e.id} className="hover:bg-os2 transition-colors">
                <td className="px-4 py-2.5 text-xs font-mono text-ot3">{e.id}</td>
                <td className="px-4 py-2.5 text-sm text-ot1">{e.automation}</td>
                <td className="px-4 py-2.5 text-xs text-ot2">{e.trigger}</td>
                <td className="px-4 py-2.5">
                  <span className={`flex items-center gap-1 text-[10px] font-mono w-fit px-1.5 py-0.5 rounded ${
                    e.status === 'succeeded' ? 'text-ogreen bg-ogreen/10' : 'text-ored bg-ored/10'
                  }`}>
                    {e.status === 'succeeded' ? <CheckCircle2 size={10} /> : <AlertTriangle size={10} />}
                    {e.status}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-xs text-ot3">{e.ago}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
