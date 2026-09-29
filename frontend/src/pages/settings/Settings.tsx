import { useState } from 'react'
import {
  Building2, Users, Shield, Brain, Bell, Lock, Key, Cpu,
  ChevronRight, Plus, Trash2, ToggleLeft, ToggleRight, Check, Copy
} from 'lucide-react'

const sections = [
  { id: 'general', label: 'General', icon: Building2 },
  { id: 'team', label: 'Team', icon: Users },
  { id: 'roles', label: 'Roles & Permissions', icon: Shield },
  { id: 'ai', label: 'AI Configuration', icon: Brain },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'security', label: 'Security', icon: Lock },
  { id: 'api', label: 'API Keys', icon: Key },
  { id: 'mcp', label: 'MCP', icon: Cpu },
]

const members = [
  { name: 'Jordan Davis', email: 'jordan@acme.com', role: 'Admin', avatar: 'JD', status: 'active' },
  { name: 'Morgan Lee', email: 'morgan@acme.com', role: 'Engineer', avatar: 'ML', status: 'active' },
  { name: 'Alex Kim', email: 'alex@acme.com', role: 'Engineer', avatar: 'AK', status: 'active' },
  { name: 'Sam Rivera', email: 'sam@acme.com', role: 'Viewer', avatar: 'SR', status: 'active' },
  { name: 'Taylor Wong', email: 'taylor@acme.com', role: 'Engineer', avatar: 'TW', status: 'pending' },
]

const apiKeys = [
  { id: 'key-001', name: 'CI/CD Pipeline', key: 'orc_••••••••••••4f2e', created: '14 days ago', lastUsed: '4m ago' },
  { id: 'key-002', name: 'Monitoring Agent', key: 'orc_••••••••••••9b1a', created: '30 days ago', lastUsed: '10s ago' },
]

export default function Settings() {
  const [activeSection, setActiveSection] = useState('general')
  const [orgName, setOrgName] = useState('Acme Corp')
  const [sensitivity, setSensitivity] = useState(70)
  const [autoRemediate, setAutoRemediate] = useState(false)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  const copyKey = (id: string) => {
    setCopiedKey(id)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  return (
    <div className="flex gap-6">
      {/* Settings nav */}
      <nav className="w-48 flex-shrink-0">
        <div className="space-y-0.5">
          {sections.map(s => {
            const Icon = s.icon
            return (
              <button key={s.id} onClick={() => setActiveSection(s.id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors text-left ${
                  activeSection === s.id ? 'bg-os2 text-ot1' : 'text-ot2 hover:text-ot1 hover:bg-os1'
                }`}>
                <Icon size={14} />
                {s.label}
              </button>
            )
          })}
        </div>
      </nav>

      {/* Content */}
      <div className="flex-1 min-w-0">
        {activeSection === 'general' && (
          <div className="space-y-6 max-w-xl">
            <h1 className="text-lg font-semibold text-ot1">General</h1>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-ot2 mb-1.5">Organization name</label>
                <input value={orgName} onChange={e => setOrgName(e.target.value)}
                  className="w-full px-3 py-2.5 rounded-lg bg-os1 border border-oline text-sm text-ot1 focus:outline-none focus:border-oaccent transition-colors" />
              </div>
              <div>
                <label className="block text-xs font-medium text-ot2 mb-1.5">Workspace slug</label>
                <div className="flex items-center">
                  <span className="px-3 py-2.5 bg-os2 border border-r-0 border-oline rounded-l-lg text-xs text-ot3 font-mono">oracle.ai/</span>
                  <input defaultValue="acme" className="flex-1 px-3 py-2.5 rounded-r-lg bg-os1 border border-oline text-sm text-ot1 font-mono focus:outline-none focus:border-oaccent transition-colors" />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-ot2 mb-1.5">Timezone</label>
                <select className="w-full px-3 py-2.5 rounded-lg bg-os1 border border-oline text-sm text-ot1 focus:outline-none focus:border-oaccent transition-colors">
                  <option>UTC (Coordinated Universal Time)</option>
                  <option>America/New_York</option>
                  <option>America/Los_Angeles</option>
                </select>
              </div>
              <button className="px-4 py-2 rounded-lg bg-oaccent text-white text-sm font-medium hover:bg-indigo-500 transition-colors">
                Save changes
              </button>
            </div>
          </div>
        )}

        {activeSection === 'team' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h1 className="text-lg font-semibold text-ot1">Team</h1>
              <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-oaccent text-white text-xs font-medium hover:bg-indigo-500 transition-colors">
                <Plus size={13} /> Invite member
              </button>
            </div>
            <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-oline">
                    <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Member</th>
                    <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Role</th>
                    <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Status</th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-oline">
                  {members.map(m => (
                    <tr key={m.email} className="hover:bg-os2 transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2.5">
                          <div className="w-7 h-7 rounded-full bg-oaccent/20 border border-oaccent/30 flex items-center justify-center text-[10px] font-medium text-oaccent">
                            {m.avatar}
                          </div>
                          <div>
                            <div className="text-sm font-medium text-ot1">{m.name}</div>
                            <div className="text-[10px] text-ot3">{m.email}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-ot2">{m.role}</td>
                      <td className="px-4 py-3">
                        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                          m.status === 'active' ? 'text-ogreen bg-ogreen/10' : 'text-oamber bg-oamber/10'
                        }`}>{m.status}</span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button className="text-ot3 hover:text-ored transition-colors"><Trash2 size={13} /></button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeSection === 'ai' && (
          <div className="space-y-6 max-w-xl">
            <h1 className="text-lg font-semibold text-ot1">AI Configuration</h1>
            <div className="space-y-4">
              <div className="flex items-start justify-between p-4 rounded-lg bg-os1 border border-oline">
                <div>
                  <div className="text-sm font-medium text-ot1">Auto-Investigation</div>
                  <div className="text-xs text-ot2 mt-0.5">Automatically investigate incidents when detected</div>
                </div>
                <button className="text-oaccent"><ToggleRight size={22} /></button>
              </div>
              <div className="flex items-start justify-between p-4 rounded-lg bg-os1 border border-oline">
                <div>
                  <div className="text-sm font-medium text-ot1">Autonomous Remediation</div>
                  <div className="text-xs text-ot2 mt-0.5">Allow ORACLE to execute pre-approved actions</div>
                </div>
                <button onClick={() => setAutoRemediate(r => !r)} className={autoRemediate ? 'text-oaccent' : 'text-ot3'}>
                  {autoRemediate ? <ToggleRight size={22} /> : <ToggleLeft size={22} />}
                </button>
              </div>
              <div className="p-4 rounded-lg bg-os1 border border-oline">
                <div className="flex items-center justify-between mb-3">
                  <div className="text-sm font-medium text-ot1">Alert Sensitivity</div>
                  <span className="text-xs font-mono text-oaccent">{sensitivity}%</span>
                </div>
                <input type="range" min={10} max={100} value={sensitivity}
                  onChange={e => setSensitivity(Number(e.target.value))}
                  className="w-full accent-oaccent" />
              </div>
              <button className="px-4 py-2 rounded-lg bg-oaccent text-white text-sm font-medium hover:bg-indigo-500 transition-colors">
                Save configuration
              </button>
            </div>
          </div>
        )}

        {activeSection === 'api' && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h1 className="text-lg font-semibold text-ot1">API Keys</h1>
              <button className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-oaccent text-white text-xs font-medium hover:bg-indigo-500 transition-colors">
                <Plus size={13} /> Create key
              </button>
            </div>
            <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-oline">
                    <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Name</th>
                    <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Key</th>
                    <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Created</th>
                    <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Last used</th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-oline">
                  {apiKeys.map(k => (
                    <tr key={k.id} className="hover:bg-os2 transition-colors">
                      <td className="px-4 py-3 text-sm font-medium text-ot1">{k.name}</td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-ot2 bg-os2 px-2 py-1 rounded">{k.key}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-ot3">{k.created}</td>
                      <td className="px-4 py-3 text-xs text-ot3">{k.lastUsed}</td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center gap-2 justify-end">
                          <button onClick={() => copyKey(k.id)}
                            className="text-ot3 hover:text-ot1 transition-colors">
                            {copiedKey === k.id ? <Check size={13} className="text-ogreen" /> : <Copy size={13} />}
                          </button>
                          <button className="text-ot3 hover:text-ored transition-colors"><Trash2 size={13} /></button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {!['general', 'team', 'ai', 'api'].includes(activeSection) && (
          <div className="flex items-center justify-center h-64 text-ot3 text-sm">
            {sections.find(s => s.id === activeSection)?.label} settings coming soon
          </div>
        )}
      </div>
    </div>
  )
}
