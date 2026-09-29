import { useState } from 'react'
import { Link } from 'react-router'
import { GitBranch, GitPullRequest, Star, AlertTriangle, ChevronRight, ArrowUpRight } from 'lucide-react'

const repos = [
  { id: 'api-gateway', name: 'api-gateway', lang: 'Go', stars: 24, prs: 8, health: 92, lastDeploy: '4m ago', coverage: 84, issues: 2 },
  { id: 'auth-service', name: 'auth-service', lang: 'Go', stars: 18, prs: 3, health: 97, lastDeploy: '31m ago', coverage: 91, issues: 0 },
  { id: 'payment-service', name: 'payment-service', lang: 'TypeScript', stars: 31, prs: 12, health: 78, lastDeploy: '6h ago', coverage: 79, issues: 5 },
  { id: 'recommendation-worker', name: 'recommendation-worker', lang: 'Python', stars: 9, prs: 2, health: 85, lastDeploy: '2h ago', coverage: 72, issues: 3 },
  { id: 'notification-worker', name: 'notification-worker', lang: 'TypeScript', stars: 6, prs: 1, health: 71, lastDeploy: '2h ago', coverage: 68, issues: 4 },
  { id: 'frontend', name: 'frontend', lang: 'TypeScript', stars: 42, prs: 15, health: 95, lastDeploy: '1h ago', coverage: 76, issues: 1 },
]

const recentPRs = [
  { id: '4821', title: 'chore: upgrade jwt library to v9.2', repo: 'auth-service', author: 'AK', status: 'merged', reviews: 2, checks: 'passed' },
  { id: '4820', title: 'feat: add retry logic with exponential backoff', repo: 'payment-service', author: 'ML', status: 'open', reviews: 1, checks: 'running' },
  { id: '4819', title: 'fix: memory leak in metrics collector', repo: 'notification-worker', author: 'JD', status: 'open', reviews: 3, checks: 'failed' },
  { id: '4818', title: 'refactor: split auth middleware', repo: 'api-gateway', author: 'SR', status: 'open', reviews: 0, checks: 'passed' },
]

const langColor: Record<string, string> = {
  Go: 'text-oblue',
  TypeScript: 'text-oaccent',
  Python: 'text-oamber',
}

const statusColor: Record<string, string> = {
  merged: 'text-oaccent bg-oaccent/10',
  open: 'text-ogreen bg-ogreen/10',
  closed: 'text-ot3 bg-os2',
}

const checksColor: Record<string, string> = {
  passed: 'text-ogreen',
  running: 'text-oamber',
  failed: 'text-ored',
}

export default function EngineeringOverview() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-ot1">Engineering</h1>
        <Link to="/app/engineering/changes" className="text-xs text-oaccent hover:text-indigo-400 flex items-center gap-1">
          Change Intelligence <ChevronRight size={12} />
        </Link>
      </div>

      {/* Repo grid */}
      <div>
        <h2 className="text-xs font-medium text-ot2 mb-3 uppercase tracking-wider">Repositories</h2>
        <div className="grid grid-cols-3 gap-3">
          {repos.map(r => (
            <Link key={r.id} to={`/app/engineering/repos/${r.id}`}
              className="p-4 rounded-xl bg-os1 border border-oline hover:border-oline2 transition-all group">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <div className="text-sm font-medium text-ot1 group-hover:text-oaccent transition-colors">{r.name}</div>
                  <span className={`text-[10px] font-mono ${langColor[r.lang] ?? 'text-ot3'}`}>{r.lang}</span>
                </div>
                <div className={`text-sm font-bold font-mono ${
                  r.health >= 90 ? 'text-ogreen' : r.health >= 75 ? 'text-oamber' : 'text-ored'
                }`}>{r.health}</div>
              </div>
              <div className="flex items-center gap-3 text-[11px] text-ot3">
                <span className="flex items-center gap-1"><GitPullRequest size={10} />{r.prs} PRs</span>
                <span>Coverage: {r.coverage}%</span>
                {r.issues > 0 && (
                  <span className="flex items-center gap-1 text-ored"><AlertTriangle size={10} />{r.issues}</span>
                )}
              </div>
            </Link>
          ))}
        </div>
      </div>

      {/* Recent PRs */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xs font-medium text-ot2 uppercase tracking-wider">Recent Pull Requests</h2>
        </div>
        <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-oline">
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">PR</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Title</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Repo</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Status</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Checks</th>
                <th className="text-left text-[11px] font-medium text-ot3 px-4 py-3">Author</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-oline">
              {recentPRs.map(pr => (
                <tr key={pr.id} className="hover:bg-os2 transition-colors">
                  <td className="px-4 py-3">
                    <Link to={`/app/engineering/prs/${pr.id}`}
                      className="text-xs font-mono text-oaccent hover:text-indigo-400">#{pr.id}</Link>
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/app/engineering/prs/${pr.id}`}
                      className="text-sm text-ot1 hover:text-oaccent transition-colors">{pr.title}</Link>
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-ot2">{pr.repo}</td>
                  <td className="px-4 py-3">
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${statusColor[pr.status]}`}>{pr.status}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-mono ${checksColor[pr.checks]}`}>{pr.checks}</span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="w-6 h-6 rounded-full bg-os2 border border-oline flex items-center justify-center text-[10px] font-medium text-ot2">
                      {pr.author}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
