import { useParams, Link } from 'react-router'
import { ChevronLeft, GitCommit, GitPullRequest, Shield, Brain, Star, GitBranch } from 'lucide-react'

const commits = [
  { hash: 'a4f2e19', message: 'chore: update routing middleware config', author: 'Jordan D.', ago: '4m ago', verified: true },
  { hash: 'b3c1d08', message: 'feat: add rate limiting to /payments endpoint', author: 'Morgan L.', ago: '2h ago', verified: true },
  { hash: 'c2b0e97', message: 'fix: correct header sanitization in auth middleware', author: 'Alex K.', ago: '1d ago', verified: true },
  { hash: 'd1a9f86', message: 'test: add integration tests for user creation flow', author: 'Sam R.', ago: '2d ago', verified: false },
]

const pullRequests = [
  { id: '4821', title: 'chore: upgrade jwt library to v9.2', status: 'merged', author: 'AK', reviews: 2 },
  { id: '4818', title: 'refactor: split auth middleware', status: 'open', author: 'SR', reviews: 0 },
  { id: '4810', title: 'feat: add OAuth2 PKCE support', status: 'open', author: 'ML', reviews: 1 },
]

export default function RepositoryDetails() {
  const { id } = useParams()

  return (
    <div className="space-y-6 max-w-4xl">
      <Link to="/app/engineering" className="flex items-center gap-1.5 text-xs text-ot2 hover:text-ot1 transition-colors">
        <ChevronLeft size={14} /> Engineering
      </Link>

      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-ot1 font-mono">{id}</h1>
          <div className="flex items-center gap-3 mt-1 text-xs text-ot2">
            <span className="flex items-center gap-1"><GitBranch size={11} />main</span>
            <span className="font-mono text-oblue">Go</span>
            <span>Health: <strong className="text-ogreen">97</strong></span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 text-xs text-oaccent bg-oaccent/5 border border-oaccent/20 px-3 py-1.5 rounded-lg">
            <Brain size={13} /> AI Insights active
          </div>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Open PRs', value: '3', icon: GitPullRequest },
          { label: 'Commits (30d)', value: '142', icon: GitCommit },
          { label: 'Test Coverage', value: '91%', icon: Shield },
          { label: 'Security Issues', value: '0', icon: Shield },
        ].map(s => {
          const Icon = s.icon
          return (
            <div key={s.label} className="p-3 rounded-lg bg-os1 border border-oline">
              <div className="text-xs text-ot3 mb-1">{s.label}</div>
              <div className="text-lg font-bold font-mono text-ot1">{s.value}</div>
            </div>
          )
        })}
      </div>

      <div className="grid grid-cols-2 gap-4">
        {/* Recent commits */}
        <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
          <div className="px-4 py-3 border-b border-oline">
            <span className="text-sm font-medium text-ot1">Recent Commits</span>
          </div>
          <div className="divide-y divide-oline">
            {commits.map(c => (
              <div key={c.hash} className="px-4 py-3">
                <div className="flex items-start justify-between gap-2 mb-0.5">
                  <span className="text-xs font-mono text-oaccent">{c.hash}</span>
                  <span className="text-[10px] text-ot3">{c.ago}</span>
                </div>
                <p className="text-xs text-ot1 mb-1">{c.message}</p>
                <span className="text-[10px] text-ot3">{c.author}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Pull requests */}
        <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
          <div className="px-4 py-3 border-b border-oline">
            <span className="text-sm font-medium text-ot1">Pull Requests</span>
          </div>
          <div className="divide-y divide-oline">
            {pullRequests.map(pr => (
              <Link key={pr.id} to={`/app/engineering/prs/${pr.id}`}
                className="flex items-center gap-3 px-4 py-3 hover:bg-os2 transition-colors group">
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-ot1 truncate group-hover:text-oaccent">{pr.title}</p>
                  <span className="text-[10px] text-ot3">#{pr.id} · {pr.reviews} reviews</span>
                </div>
                <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                  pr.status === 'merged' ? 'text-oaccent bg-oaccent/10' : 'text-ogreen bg-ogreen/10'
                }`}>{pr.status}</span>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
