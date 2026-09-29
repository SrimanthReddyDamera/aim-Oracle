import { useState } from 'react'
import { useNavigate } from 'react-router'
import { ArrowRight, Building2 } from 'lucide-react'

export default function OrganizationSetup() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ name: '', slug: '', size: '', industry: '' })
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm(f => ({ ...f, [k]: e.target.value }))

  const sizes = ['1–10', '11–50', '51–200', '201–500', '500+']
  const industries = ['SaaS / Software', 'Fintech', 'E-commerce', 'Healthcare', 'Media', 'Enterprise', 'Other']

  return (
    <div>
      <div className="flex items-center gap-3 mb-8">
        <div className="w-10 h-10 rounded-lg bg-oaccent/10 border border-oaccent/20 flex items-center justify-center">
          <Building2 size={18} className="text-oaccent" />
        </div>
        <div>
          <h1 className="text-xl font-semibold text-ot1">Set up your organization</h1>
          <p className="text-sm text-ot2">This is how your team will be identified in ORACLE.</p>
        </div>
      </div>

      <form onSubmit={e => { e.preventDefault(); navigate('/onboarding/integrations') }} className="space-y-5">
        <div>
          <label className="block text-xs font-medium text-ot2 mb-1.5">Organization name</label>
          <input value={form.name} onChange={set('name')} placeholder="Acme Corp" required
            className="w-full px-3 py-2.5 rounded-lg bg-os1 border border-oline text-sm text-ot1 placeholder-ot3 focus:outline-none focus:border-oaccent transition-colors" />
        </div>
        <div>
          <label className="block text-xs font-medium text-ot2 mb-1.5">Workspace slug</label>
          <div className="flex items-center">
            <span className="px-3 py-2.5 bg-os2 border border-r-0 border-oline rounded-l-lg text-xs text-ot3 font-mono">oracle.ai/</span>
            <input value={form.slug} onChange={set('slug')} placeholder="acme" required
              className="flex-1 px-3 py-2.5 rounded-r-lg bg-os1 border border-oline text-sm text-ot1 placeholder-ot3 focus:outline-none focus:border-oaccent transition-colors font-mono" />
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-ot2 mb-1.5">Team size</label>
            <select value={form.size} onChange={set('size')} required
              className="w-full px-3 py-2.5 rounded-lg bg-os1 border border-oline text-sm text-ot1 focus:outline-none focus:border-oaccent transition-colors">
              <option value="">Select size</option>
              {sizes.map(s => <option key={s}>{s}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-ot2 mb-1.5">Industry</label>
            <select value={form.industry} onChange={set('industry')} required
              className="w-full px-3 py-2.5 rounded-lg bg-os1 border border-oline text-sm text-ot1 focus:outline-none focus:border-oaccent transition-colors">
              <option value="">Select industry</option>
              {industries.map(s => <option key={s}>{s}</option>)}
            </select>
          </div>
        </div>
        <div className="pt-2">
          <button type="submit"
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-oaccent text-white text-sm font-medium hover:bg-indigo-500 transition-colors">
            Continue <ArrowRight size={14} />
          </button>
        </div>
      </form>
    </div>
  )
}
