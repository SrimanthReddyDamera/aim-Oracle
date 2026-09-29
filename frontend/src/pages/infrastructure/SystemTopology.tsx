import { useState } from 'react'
import { Link } from 'react-router'
import { Search, Filter, ZoomIn, ZoomOut, Maximize2 } from 'lucide-react'

const nodes = [
  { id: 'frontend', label: 'frontend', type: 'service', x: 300, y: 60, status: 'healthy' },
  { id: 'api-gateway', label: 'api-gateway', type: 'service', x: 300, y: 180, status: 'healthy' },
  { id: 'auth-service', label: 'auth-service', type: 'service', x: 100, y: 310, status: 'healthy' },
  { id: 'payment-service', label: 'payment-service', type: 'service', x: 300, y: 310, status: 'warning' },
  { id: 'recommendation-worker', label: 'rec-worker', type: 'service', x: 500, y: 310, status: 'warning' },
  { id: 'postgres-primary', label: 'postgres', type: 'database', x: 200, y: 440, status: 'warning' },
  { id: 'redis-cache', label: 'redis', type: 'cache', x: 420, y: 440, status: 'healthy' },
  { id: 'kafka-prod', label: 'kafka', type: 'queue', x: 300, y: 560, status: 'healthy' },
]

const edges = [
  { from: 'frontend', to: 'api-gateway' },
  { from: 'api-gateway', to: 'auth-service' },
  { from: 'api-gateway', to: 'payment-service' },
  { from: 'api-gateway', to: 'recommendation-worker' },
  { from: 'auth-service', to: 'postgres-primary' },
  { from: 'payment-service', to: 'postgres-primary' },
  { from: 'recommendation-worker', to: 'redis-cache' },
  { from: 'payment-service', to: 'kafka-prod' },
]

const statusColor: Record<string, { fill: string, stroke: string, text: string }> = {
  healthy: { fill: '#0f2714', stroke: '#22c55e', text: '#22c55e' },
  warning: { fill: '#2a1c06', stroke: '#f59e0b', text: '#f59e0b' },
  critical: { fill: '#250909', stroke: '#f43f5e', text: '#f43f5e' },
}

const typeShape: Record<string, string> = {
  service: 'rect',
  database: 'cylinder',
  cache: 'diamond',
  queue: 'hexagon',
}

export default function SystemTopology() {
  const [selected, setSelected] = useState<string | null>(null)
  const sel = nodes.find(n => n.id === selected)

  const nodePos = Object.fromEntries(nodes.map(n => [n.id, { x: n.x, y: n.y }]))

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-ot1">System Topology</h1>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-os1 border border-oline">
            <Search size={13} className="text-ot3" />
            <input placeholder="Search services..." className="bg-transparent text-xs text-ot1 placeholder-ot3 focus:outline-none w-32" />
          </div>
          <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-os1 border border-oline text-xs text-ot2">
            <Filter size={13} /> Filter
          </button>
        </div>
      </div>

      <div className="flex gap-4">
        {/* Canvas */}
        <div className="flex-1 rounded-xl bg-os1 border border-oline overflow-hidden relative" style={{ height: 640 }}>
          <div className="absolute top-3 right-3 flex gap-1 z-10">
            {[ZoomIn, ZoomOut, Maximize2].map((Icon, i) => (
              <button key={i} className="w-7 h-7 rounded bg-os2 border border-oline flex items-center justify-center text-ot2 hover:text-ot1">
                <Icon size={13} />
              </button>
            ))}
          </div>
          <svg width="100%" height="100%" viewBox="0 0 600 640" className="absolute inset-0">
            {/* Grid */}
            <defs>
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="1" />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#grid)" />

            {/* Edges */}
            {edges.map(e => {
              const from = nodePos[e.from]
              const to = nodePos[e.to]
              if (!from || !to) return null
              return (
                <line key={`${e.from}-${e.to}`}
                  x1={from.x} y1={from.y + 16}
                  x2={to.x} y2={to.y - 16}
                  stroke="rgba(255,255,255,0.1)" strokeWidth="1.5"
                  strokeDasharray={e.from === 'payment-service' ? '4 4' : 'none'}
                />
              )
            })}

            {/* Nodes */}
            {nodes.map(n => {
              const sc = statusColor[n.status] ?? statusColor.healthy
              const isSelected = selected === n.id
              return (
                <g key={n.id} transform={`translate(${n.x}, ${n.y})`}
                  onClick={() => setSelected(n.id === selected ? null : n.id)}
                  className="cursor-pointer">
                  <rect x={-52} y={-16} width={104} height={32} rx={6}
                    fill={sc.fill}
                    stroke={isSelected ? '#6366f1' : sc.stroke}
                    strokeWidth={isSelected ? 2 : 1}
                  />
                  {/* Status dot */}
                  <circle cx={-40} cy={0} r={4} fill={sc.stroke} />
                  <text x={-28} y={0} textAnchor="start" dominantBaseline="middle"
                    fill={sc.text} fontSize={10} fontFamily="JetBrains Mono, monospace" fontWeight="500">
                    {n.label}
                  </text>
                </g>
              )
            })}
          </svg>
        </div>

        {/* Detail panel */}
        {sel && (
          <div className="w-56 flex-shrink-0 rounded-xl bg-os1 border border-oline p-4">
            <h3 className="text-sm font-medium text-ot1 mb-1 font-mono">{sel.id}</h3>
            <span className={`text-[10px] font-mono ${statusColor[sel.status]?.text ?? 'text-ot3'}`}>{sel.status}</span>
            <div className="mt-4 space-y-2">
              {[
                { k: 'Type', v: sel.type },
                { k: 'Status', v: sel.status },
              ].map(f => (
                <div key={f.k} className="flex justify-between">
                  <span className="text-xs text-ot3">{f.k}</span>
                  <span className="text-xs text-ot1">{f.v}</span>
                </div>
              ))}
            </div>
            <Link to={`/app/infrastructure/resources/${sel.id}`}
              className="block mt-4 text-center text-xs text-oaccent hover:text-indigo-400 border border-oaccent/25 rounded-lg py-1.5 transition-colors">
              View Resource →
            </Link>
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="flex items-center gap-6 text-[11px] text-ot3">
        {Object.entries(statusColor).map(([k, v]) => (
          <span key={k} className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full" style={{ background: v.stroke }} />
            {k}
          </span>
        ))}
      </div>
    </div>
  )
}
