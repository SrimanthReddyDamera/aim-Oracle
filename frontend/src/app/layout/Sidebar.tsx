import { NavLink, useLocation } from 'react-router'
import {
  LayoutDashboard, Brain, Zap, GitBranch, Server, Shield,
  Plug, Settings, ChevronRight, Activity, AlertTriangle,
  Cpu, Lock, Link2, SlidersHorizontal, Home
} from 'lucide-react'
import { useState } from 'react'

const nav = [
  { label: 'Command Center', icon: LayoutDashboard, to: '/app' },
  { label: 'Intelligence', icon: Brain, to: '/app/intelligence' },
  {
    label: 'Operations', icon: Zap, to: '/app/operations',
    children: [
      { label: 'Overview', to: '/app/operations' },
      { label: 'Automation', to: '/app/operations/automation' },
    ]
  },
  {
    label: 'Engineering', icon: GitBranch, to: '/app/engineering',
    children: [
      { label: 'Overview', to: '/app/engineering' },
      { label: 'Change Intelligence', to: '/app/engineering/changes' },
    ]
  },
  {
    label: 'Infrastructure', icon: Server, to: '/app/infrastructure',
    children: [
      { label: 'Overview', to: '/app/infrastructure' },
      { label: 'System Topology', to: '/app/infrastructure/topology' },
    ]
  },
  { label: 'Security', icon: Shield, to: '/app/security' },
  { label: 'Integrations', icon: Plug, to: '/app/integrations' },
  { label: 'Settings', icon: Settings, to: '/app/settings' },
]

type NavItem = {
  label: string
  icon: React.ElementType
  to: string
  children?: { label: string; to: string }[]
}

function NavItem({ item }: { item: NavItem }) {
  const location = useLocation()
  const isActive = location.pathname === item.to || (item.to !== '/app' && location.pathname.startsWith(item.to))
  const [open, setOpen] = useState(isActive)
  const Icon = item.icon

  if (item.children) {
    return (
      <div>
        <button
          onClick={() => setOpen(o => !o)}
          className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
            isActive ? 'text-ot1 bg-os2' : 'text-ot2 hover:text-ot1 hover:bg-os1'
          }`}
        >
          <Icon size={15} />
          <span className="flex-1 text-left">{item.label}</span>
          <ChevronRight size={12} className={`transition-transform ${open ? 'rotate-90' : ''}`} />
        </button>
        {open && (
          <div className="mt-0.5 ml-6 pl-3 border-l border-oline space-y-0.5">
            {item.children.map(c => (
              <NavLink
                key={c.to}
                to={c.to}
                end
                className={({ isActive }) =>
                  `block px-2 py-1.5 text-xs rounded transition-colors ${
                    isActive ? 'text-oaccent' : 'text-ot2 hover:text-ot1'
                  }`
                }
              >
                {c.label}
              </NavLink>
            ))}
          </div>
        )}
      </div>
    )
  }

  return (
    <NavLink
      to={item.to}
      end={item.to === '/app'}
      className={({ isActive }) =>
        `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
          isActive ? 'text-ot1 bg-os2' : 'text-ot2 hover:text-ot1 hover:bg-os1'
        }`
      }
    >
      <Icon size={15} />
      {item.label}
    </NavLink>
  )
}

export default function Sidebar() {
  return (
    <aside className="fixed top-0 left-0 h-screen w-56 flex flex-col border-r border-oline bg-ob z-40">
      {/* Logo */}
      <div className="flex items-center gap-2.5 px-4 h-14 border-b border-oline">
        <div className="w-7 h-7 rounded-md bg-oaccent flex items-center justify-center flex-shrink-0">
          <Activity size={14} className="text-white" />
        </div>
        <span className="font-semibold text-sm tracking-wide text-ot1">ORACLE</span>
        <span className="ml-auto text-[10px] font-mono text-ot3 bg-os1 px-1.5 py-0.5 rounded border border-oline">v2.4</span>
      </div>

      {/* System status pill */}
      <div className="px-3 py-2.5 border-b border-oline">
        <div className="flex items-center gap-2 px-2.5 py-1.5 rounded bg-os1 border border-oline">
          <span className="w-1.5 h-1.5 rounded-full bg-ogreen flex-shrink-0" />
          <span className="text-[11px] text-ot2 font-mono">All systems operational</span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto p-2 space-y-0.5">
        {nav.map(item => (
          <NavItem key={item.to} item={item as NavItem} />
        ))}
      </nav>

      {/* Bottom */}
      <div className="p-3 border-t border-oline">
        <div className="flex items-center gap-2.5 px-2 py-2 rounded-md hover:bg-os1 cursor-pointer transition-colors">
          <div className="w-7 h-7 rounded-full bg-os2 border border-oline2 flex items-center justify-center text-xs font-medium text-ot2">
            JD
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs font-medium text-ot1 truncate">Jordan Davis</div>
            <div className="text-[10px] text-ot3 truncate">Admin</div>
          </div>
          <Settings size={13} className="text-ot3" />
        </div>
      </div>
    </aside>
  )
}
