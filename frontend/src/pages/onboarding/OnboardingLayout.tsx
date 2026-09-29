import { Outlet, useLocation, Link } from 'react-router'
import { Activity, Check } from 'lucide-react'

const steps = [
  { label: 'Organization', path: '/onboarding' },
  { label: 'Integrations', path: '/onboarding/integrations' },
  { label: 'Environment', path: '/onboarding/environment' },
  { label: 'Configuration', path: '/onboarding/configuration' },
  { label: 'Team', path: '/onboarding/team' },
  { label: 'Initialize', path: '/onboarding/initialization' },
]

export default function OnboardingLayout() {
  const { pathname } = useLocation()
  const current = steps.findIndex(s => s.path === pathname)

  return (
    <div className="min-h-screen bg-ob flex flex-col">
      {/* Top nav */}
      <div className="flex items-center justify-between px-8 h-16 border-b border-oline">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-md bg-oaccent flex items-center justify-center">
            <Activity size={14} className="text-white" />
          </div>
          <span className="font-semibold text-sm text-ot1">ORACLE</span>
        </div>
        <span className="text-xs text-ot3 font-mono">Setup · Step {current + 1} of {steps.length}</span>
        <Link to="/login" className="text-xs text-ot2 hover:text-ot1 transition-colors">Sign out</Link>
      </div>

      {/* Stepper */}
      <div className="flex items-center justify-center gap-0 px-8 py-6 border-b border-oline">
        {steps.map((s, i) => (
          <div key={s.path} className="flex items-center">
            <div className="flex flex-col items-center gap-1.5">
              <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-medium transition-colors ${
                i < current ? 'bg-oaccent text-white' :
                i === current ? 'bg-oaccent text-white ring-4 ring-oaccent/20' :
                'bg-os2 border border-oline text-ot3'
              }`}>
                {i < current ? <Check size={13} /> : i + 1}
              </div>
              <span className={`text-[10px] font-medium whitespace-nowrap ${
                i === current ? 'text-ot1' : i < current ? 'text-oaccent' : 'text-ot3'
              }`}>{s.label}</span>
            </div>
            {i < steps.length - 1 && (
              <div className={`w-16 h-px mx-2 mb-4 ${i < current ? 'bg-oaccent' : 'bg-oline'}`} />
            )}
          </div>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 flex items-start justify-center p-8">
        <div className="w-full max-w-xl">
          <Outlet />
        </div>
      </div>
    </div>
  )
}
