import { useLocation, Link } from 'react-router'
import { Search, Bell, Command, HelpCircle, ChevronRight } from 'lucide-react'
import { useState } from 'react'

const breadcrumbMap: Record<string, string> = {
  app: 'Command Center',
  intelligence: 'Intelligence',
  investigation: 'Investigation',
  operations: 'Operations',
  incidents: 'Incidents',
  deployments: 'Deployments',
  pipelines: 'Pipelines',
  automation: 'Automation',
  engineering: 'Engineering',
  repos: 'Repository',
  prs: 'Pull Request',
  changes: 'Change Intelligence',
  infrastructure: 'Infrastructure',
  resources: 'Resource',
  topology: 'System Topology',
  security: 'Security',
  findings: 'Finding',
  integrations: 'Integrations',
  settings: 'Settings',
}

export default function Topbar() {
  const location = useLocation()
  const segments = location.pathname.split('/').filter(Boolean)
  const [searchOpen, setSearchOpen] = useState(false)

  const crumbs = segments.map((seg, i) => ({
    label: breadcrumbMap[seg] ?? seg,
    path: '/' + segments.slice(0, i + 1).join('/'),
    last: i === segments.length - 1,
  }))

  return (
    <header className="fixed top-0 left-56 right-0 h-14 border-b border-oline bg-ob/90 backdrop-blur z-30 flex items-center px-5 gap-4">
      {/* Breadcrumb */}
      <nav className="flex items-center gap-1 text-xs text-ot2 flex-1 min-w-0">
        {crumbs.map((c, i) => (
          <span key={c.path} className="flex items-center gap-1">
            {i > 0 && <ChevronRight size={11} className="text-ot3" />}
            {c.last ? (
              <span className="text-ot1 font-medium">{c.label}</span>
            ) : (
              <Link to={c.path} className="hover:text-ot1 transition-colors">{c.label}</Link>
            )}
          </span>
        ))}
      </nav>

      {/* Search */}
      <button
        onClick={() => setSearchOpen(true)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-os1 border border-oline text-ot2 text-xs hover:border-oline2 transition-colors w-48"
      >
        <Search size={13} />
        <span className="flex-1 text-left">Search...</span>
        <span className="text-ot3 font-mono flex items-center gap-0.5">
          <Command size={10} />K
        </span>
      </button>

      {/* Actions */}
      <div className="flex items-center gap-1">
        <button className="relative w-8 h-8 rounded-md hover:bg-os1 flex items-center justify-center text-ot2 hover:text-ot1 transition-colors">
          <Bell size={15} />
          <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-ored" />
        </button>
        <button className="w-8 h-8 rounded-md hover:bg-os1 flex items-center justify-center text-ot2 hover:text-ot1 transition-colors">
          <HelpCircle size={15} />
        </button>
      </div>
    </header>
  )
}
