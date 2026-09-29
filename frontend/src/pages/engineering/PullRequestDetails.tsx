import { useParams, Link } from 'react-router'
import { ChevronLeft, Brain, CheckCircle2, XCircle, Clock, MessageSquare, GitMerge, Shield } from 'lucide-react'

const changedFiles = [
  { path: 'pkg/auth/middleware.go', additions: 42, deletions: 18, status: 'modified' },
  { path: 'pkg/auth/middleware_test.go', additions: 84, deletions: 12, status: 'modified' },
  { path: 'go.mod', additions: 1, deletions: 1, status: 'modified' },
  { path: 'go.sum', additions: 4, deletions: 4, status: 'modified' },
]

const checks = [
  { name: 'Build', status: 'passed', duration: '1m 42s' },
  { name: 'Unit Tests', status: 'passed', duration: '2m 11s' },
  { name: 'Integration Tests', status: 'passed', duration: '6m 44s' },
  { name: 'Security Scan (Trivy)', status: 'passed', duration: '1m 08s' },
  { name: 'Lint', status: 'passed', duration: '22s' },
]

const reviews = [
  { reviewer: 'Morgan L.', status: 'approved', comment: 'LGTM — nice cleanup, tests are thorough.', ago: '2h ago' },
  { reviewer: 'Alex K.', status: 'approved', comment: 'Good changes. Left one minor nit on line 87.', ago: '3h ago' },
]

const aiReview = {
  summary: 'This PR upgrades jwt-go from v4 to v9.2. The migration is straightforward and correct. Test coverage is good at 91%.',
  suggestions: [
    { severity: 'info', text: 'pkg/auth/middleware.go:87 — Consider adding explicit algorithm validation to prevent algorithm confusion attacks.', line: 87 },
    { severity: 'info', text: 'The new ParseWithClaims signature change is handled correctly across all call sites.', line: null },
  ],
  risk: 'low',
}

export default function PullRequestDetails() {
  const { id } = useParams()

  return (
    <div className="space-y-6 max-w-4xl">
      <Link to="/app/engineering" className="flex items-center gap-1.5 text-xs text-ot2 hover:text-ot1 transition-colors">
        <ChevronLeft size={14} /> Engineering
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded text-oaccent bg-oaccent/10">merged</span>
            <span className="text-[10px] font-mono text-ot3">#{id} · auth-service · main ← release/jwt-v9</span>
          </div>
          <h1 className="text-xl font-semibold text-ot1">chore: upgrade jwt library to v9.2</h1>
          <p className="text-sm text-ot2 mt-1">Opened by Alex K. · 4h ago · Merged by Jordan D. · 2h ago</p>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 space-y-4">
          {/* Changed files */}
          <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
            <div className="px-4 py-3 border-b border-oline flex items-center justify-between">
              <span className="text-sm font-medium text-ot1">Changed Files</span>
              <span className="text-xs text-ot3">{changedFiles.length} files changed</span>
            </div>
            <div className="divide-y divide-oline">
              {changedFiles.map(f => (
                <div key={f.path} className="flex items-center gap-3 px-4 py-2.5">
                  <span className="text-xs font-mono text-ot1 flex-1 truncate">{f.path}</span>
                  <span className="text-[10px] font-mono text-ogreen">+{f.additions}</span>
                  <span className="text-[10px] font-mono text-ored">-{f.deletions}</span>
                </div>
              ))}
            </div>
          </div>

          {/* CI Checks */}
          <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
            <div className="px-4 py-3 border-b border-oline">
              <span className="text-sm font-medium text-ot1">CI Status</span>
            </div>
            <div className="divide-y divide-oline">
              {checks.map(c => (
                <div key={c.name} className="flex items-center gap-3 px-4 py-2.5">
                  {c.status === 'passed' ? <CheckCircle2 size={14} className="text-ogreen" /> : <XCircle size={14} className="text-ored" />}
                  <span className="text-sm text-ot1 flex-1">{c.name}</span>
                  <span className="text-xs font-mono text-ot3">{c.duration}</span>
                </div>
              ))}
            </div>
          </div>

          {/* AI Code Review */}
          <div className="rounded-xl bg-oaccent/5 border border-oaccent/25 overflow-hidden">
            <div className="px-4 py-3 border-b border-oaccent/20 flex items-center gap-2">
              <Brain size={14} className="text-oaccent" />
              <span className="text-sm font-medium text-ot1">AI Code Review</span>
              <span className="ml-auto text-[10px] font-mono px-1.5 py-0.5 rounded text-ogreen bg-ogreen/10">{aiReview.risk} risk</span>
            </div>
            <div className="p-4">
              <p className="text-xs text-ot1 mb-3">{aiReview.summary}</p>
              <div className="space-y-2">
                {aiReview.suggestions.map((s, i) => (
                  <div key={i} className="flex items-start gap-2 p-2.5 rounded-lg bg-os1 border border-oline">
                    <span className={`text-[10px] font-mono px-1 py-0.5 rounded flex-shrink-0 ${
                      s.severity === 'warning' ? 'text-oamber bg-oamber/10' : 'text-oblue bg-oblue/10'
                    }`}>{s.severity}</span>
                    <p className="text-xs text-ot2">{s.text}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Reviews */}
          <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
            <div className="px-4 py-3 border-b border-oline">
              <span className="text-sm font-medium text-ot1">Reviews</span>
            </div>
            <div className="divide-y divide-oline">
              {reviews.map(r => (
                <div key={r.reviewer} className="px-4 py-3 flex items-start gap-3">
                  <div className="w-7 h-7 rounded-full bg-oaccent/20 border border-oaccent/30 flex items-center justify-center text-[10px] font-medium text-oaccent flex-shrink-0">
                    {r.reviewer.split(' ').map(w => w[0]).join('')}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className="text-xs font-medium text-ot1">{r.reviewer}</span>
                      <span className="text-[10px] font-mono text-ogreen flex items-center gap-0.5"><CheckCircle2 size={10} />approved</span>
                      <span className="text-[10px] text-ot3 ml-auto">{r.ago}</span>
                    </div>
                    <p className="text-xs text-ot2">{r.comment}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          <div className="rounded-xl bg-os1 border border-oline p-4 space-y-3">
            {[
              { label: 'Reviewers', value: '2 approved' },
              { label: 'Repository', value: 'auth-service' },
              { label: 'Base branch', value: 'main' },
              { label: 'Head branch', value: 'release/jwt-v9' },
              { label: 'Commits', value: '3' },
            ].map(f => (
              <div key={f.label} className="flex items-center justify-between">
                <span className="text-xs text-ot3">{f.label}</span>
                <span className="text-xs font-mono text-ot1">{f.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
