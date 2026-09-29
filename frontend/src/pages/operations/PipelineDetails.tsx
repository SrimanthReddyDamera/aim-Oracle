import { useParams, Link } from 'react-router'
import { ChevronLeft, CheckCircle2, XCircle, Loader2, Clock, GitBranch, User } from 'lucide-react'

const stages = [
  {
    name: 'Checkout & Setup', status: 'succeeded', duration: '4s',
    logs: ['Cloning repository...', 'Setting up Node 22...', 'Restoring cache...', '✓ Setup complete']
  },
  {
    name: 'Build', status: 'succeeded', duration: '1m 42s',
    logs: ['Running: tsc --noEmit', 'Running: vite build', '✓ Build artifacts: 2.4MB']
  },
  {
    name: 'Unit Tests', status: 'succeeded', duration: '2m 11s',
    logs: ['Running 847 test suites', 'All tests passed', '✓ Coverage: 87.2%']
  },
  {
    name: 'Integration Tests', status: 'running', duration: '4m 12s',
    logs: ['Starting test environment...', 'Running API integration tests...', '218/340 tests passed...']
  },
  { name: 'Security Scan', status: 'pending', duration: '—', logs: [] },
  { name: 'Deploy Canary', status: 'pending', duration: '—', logs: [] },
]

export default function PipelineDetails() {
  const { id } = useParams()

  return (
    <div className="space-y-6 max-w-4xl">
      <Link to="/app/operations" className="flex items-center gap-1.5 text-xs text-ot2 hover:text-ot1 transition-colors">
        <ChevronLeft size={14} /> Operations
      </Link>

      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded text-oamber bg-oamber/10">running</span>
            <span className="text-[10px] font-mono text-ot3">{id}</span>
          </div>
          <h1 className="text-xl font-semibold text-ot1">api-gateway · CI Pipeline</h1>
          <div className="flex items-center gap-3 mt-1 text-xs text-ot2">
            <span className="flex items-center gap-1"><GitBranch size={11} />main</span>
            <span className="font-mono">a4f2e19</span>
            <span className="flex items-center gap-1"><User size={11} />Jordan D.</span>
            <span className="flex items-center gap-1"><Clock size={11} />4m 12s</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="space-y-2">
          {stages.map(s => (
            <button key={s.name}
              className={`w-full flex items-center gap-3 p-3 rounded-lg border text-left transition-colors ${
                s.status === 'running' ? 'border-oamber/30 bg-oamber/5' :
                s.status === 'succeeded' ? 'border-ogreen/20 bg-os1' :
                s.status === 'failed' ? 'border-ored/30 bg-ored/5' :
                'border-oline bg-os1 opacity-50'
              }`}>
              <div>
                {s.status === 'succeeded' && <CheckCircle2 size={15} className="text-ogreen" />}
                {s.status === 'running' && <Loader2 size={15} className="text-oamber animate-spin" />}
                {s.status === 'failed' && <XCircle size={15} className="text-ored" />}
                {s.status === 'pending' && <div className="w-4 h-4 rounded-full border border-oline" />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs font-medium text-ot1 truncate">{s.name}</div>
                <div className="text-[10px] font-mono text-ot3">{s.duration}</div>
              </div>
            </button>
          ))}
        </div>

        <div className="col-span-2 rounded-xl bg-os2 border border-oline overflow-hidden">
          <div className="px-4 py-2.5 border-b border-oline bg-ob">
            <span className="text-xs font-mono text-ot2">Integration Tests · stdout</span>
          </div>
          <div className="p-4 font-mono text-xs space-y-1 text-ogreen">
            <div className="text-ot3">$ npm run test:integration</div>
            <div>Starting test environment...</div>
            <div>Waiting for services to be healthy...</div>
            <div className="text-ogreen">✓ postgres healthy</div>
            <div className="text-ogreen">✓ redis healthy</div>
            <div className="text-ogreen">✓ api-gateway reachable</div>
            <div className="mt-2 text-ot1">Running API integration tests...</div>
            <div className="text-ogreen">✓ GET /health (12ms)</div>
            <div className="text-ogreen">✓ POST /auth/login (48ms)</div>
            <div className="text-ogreen">✓ GET /users/:id (23ms)</div>
            <div className="text-ogreen">✓ POST /payments/initiate (89ms)</div>
            <div className="text-ot2">… 214 more tests passing</div>
            <div className="text-oamber">218/340 complete · running...</div>
            <span className="text-oamber oa-blink">▊</span>
          </div>
        </div>
      </div>
    </div>
  )
}
