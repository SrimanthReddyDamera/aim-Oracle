import { useParams, Link } from 'react-router'
import { ChevronLeft, Brain, Lock, Shield, Code, CheckCircle2, AlertTriangle } from 'lucide-react'

export default function SecurityFinding() {
  const { id } = useParams()

  return (
    <div className="space-y-6 max-w-4xl">
      <Link to="/app/security" className="flex items-center gap-1.5 text-xs text-ot2 hover:text-ot1 transition-colors">
        <ChevronLeft size={14} /> Security Center
      </Link>

      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border text-red-400 bg-red-400/10 border-red-400/25">critical</span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded text-ored bg-ored/10">open</span>
            <span className="text-[10px] font-mono text-ot3">{id} · secret · api-gateway</span>
          </div>
          <h1 className="text-xl font-semibold text-ot1">Exposed AWS credentials in environment variable log output</h1>
        </div>
        <button className="px-3 py-1.5 rounded-lg bg-ogreen/10 border border-ogreen/25 text-xs text-ogreen hover:bg-ogreen/20">
          Mark Resolved
        </button>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 space-y-4">
          {/* Description */}
          <div className="rounded-xl bg-os1 border border-oline p-4">
            <h3 className="text-sm font-medium text-ot1 mb-2">Description</h3>
            <p className="text-sm text-ot2 leading-relaxed">
              AWS credentials (<code className="font-mono text-xs bg-os2 px-1 rounded">AWS_ACCESS_KEY_ID</code> and{' '}
              <code className="font-mono text-xs bg-os2 px-1 rounded">AWS_SECRET_ACCESS_KEY</code>) were found in structured
              log output from the api-gateway startup sequence. The values are being logged at INFO level during environment
              variable dump on boot.
            </p>
          </div>

          {/* Evidence */}
          <div className="rounded-xl bg-os1 border border-oline overflow-hidden">
            <div className="px-4 py-3 border-b border-oline flex items-center gap-2">
              <Code size={14} className="text-ot2" />
              <span className="text-sm font-medium text-ot1">Evidence</span>
            </div>
            <div className="p-4 font-mono text-xs bg-os2 text-ogreen space-y-0.5">
              <div className="text-ot3">// logs/api-gateway-2026-09-29.log:8421</div>
              <div>INFO  Starting api-gateway v3.14.2</div>
              <div>INFO  Environment:</div>
              <div className="text-ored">{'  AWS_ACCESS_KEY_ID=AKIA••••••••••••ABCD'}</div>
              <div className="text-ored">{'  AWS_SECRET_ACCESS_KEY=wJalr••••••••••••••••••••'}</div>
              <div>INFO  Listening on :8080</div>
            </div>
          </div>

          {/* AI Remediation */}
          <div className="rounded-xl bg-oaccent/5 border border-oaccent/25 overflow-hidden">
            <div className="px-4 py-3 border-b border-oaccent/20 flex items-center gap-2">
              <Brain size={14} className="text-oaccent" />
              <span className="text-sm font-medium text-ot1">ORACLE Remediation</span>
            </div>
            <div className="p-4 space-y-3">
              <p className="text-sm text-ot2">ORACLE recommends the following steps:</p>
              <ol className="space-y-2 text-sm text-ot2">
                {[
                  'Immediately rotate the exposed AWS credentials via the AWS IAM console.',
                  'Audit CloudTrail for any unauthorized API calls using the compromised key (last 24h).',
                  'Remove env-dump logging from api-gateway startup (cmd/server/main.go:47).',
                  'Implement log scrubbing middleware to redact credential patterns before output.',
                  'Enable AWS CloudTrail alerting for unusual activity.',
                ].map((s, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="w-5 h-5 rounded-full bg-oaccent/20 flex items-center justify-center text-[10px] text-oaccent font-mono flex-shrink-0 mt-0.5">{i + 1}</span>
                    {s}
                  </li>
                ))}
              </ol>
              <button className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-oaccent text-white text-xs font-medium hover:bg-indigo-500 transition-colors">
                Execute Automated Remediation
              </button>
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          <div className="rounded-xl bg-os1 border border-oline p-4 space-y-3">
            {[
              { label: 'Severity', value: 'Critical' },
              { label: 'Type', value: 'Secret Exposure' },
              { label: 'Resource', value: 'api-gateway' },
              { label: 'Detected', value: '2h ago' },
              { label: 'CVSS', value: 'N/A' },
            ].map(f => (
              <div key={f.label} className="flex items-center justify-between">
                <span className="text-xs text-ot3">{f.label}</span>
                <span className="text-xs font-medium text-ot1">{f.value}</span>
              </div>
            ))}
          </div>

          <div className="rounded-xl bg-ored/5 border border-ored/25 p-4">
            <div className="flex items-center gap-2 mb-2">
              <AlertTriangle size={13} className="text-ored" />
              <span className="text-xs font-medium text-ored">Immediate Action Required</span>
            </div>
            <p className="text-xs text-ot2">Rotate AWS credentials immediately. Any delay increases breach risk.</p>
          </div>
        </div>
      </div>
    </div>
  )
}
