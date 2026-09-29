import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import TiltCard from '@/components/ui/TiltCard'

const INTEGRATIONS = [
  { name: 'GitHub',         cat: 'Source Control', tag: 'GH', events: '842/hr',  color: '#f4f4f5', border: 'rgba(244,244,245,0.1)' },
  { name: 'GitLab',         cat: 'Source Control', tag: 'GL', events: '213/hr',  color: '#ff6600', border: 'rgba(255,102,0,0.15)' },
  { name: 'Jira',           cat: 'Issue Tracking', tag: 'JI', events: '64/hr',   color: '#0052cc', border: 'rgba(0,82,204,0.2)' },
  { name: 'Linear',         cat: 'Issue Tracking', tag: 'LN', events: '31/hr',   color: '#5e6ad2', border: 'rgba(94,106,210,0.2)' },
  { name: 'GitHub Actions', cat: 'CI/CD',          tag: 'GA', events: '287/hr',  color: '#3b82f6', border: 'rgba(59,130,246,0.18)' },
  { name: 'Snyk',           cat: 'Security',        tag: 'SK', events: '156/hr',  color: '#ef4444', border: 'rgba(239,68,68,0.16)' },
  { name: 'AWS',            cat: 'Cloud',           tag: 'AW', events: '428/hr',  color: '#f59e0b', border: 'rgba(245,158,11,0.18)' },
  { name: 'Slack',          cat: 'Communication',   tag: 'SL', events: '19/hr',   color: '#22c55e', border: 'rgba(34,197,94,0.15)' },
  { name: 'Datadog',        cat: 'Observability',   tag: 'DD', events: '312/hr',  color: '#a78bfa', border: 'rgba(167,139,250,0.16)' },
]

export default function ConnectSection() {
  const ref = useRef<HTMLElement>(null)
  const isInView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section
      id="connect"
      ref={ref}
      className="chapter-section"
      style={{ background: '#0d0d10' }}
    >
      <div className="absolute top-0 inset-x-0 h-px" style={{ background: 'rgba(255,255,255,0.06)' }} />

      <div className="relative max-w-7xl mx-auto px-6 md:px-12">

        {/* Chapter */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.5 }}
          className="flex items-center gap-4 mb-20"
        >
          <span className="font-mono text-[10px] tracking-[0.28em]" style={{ color: '#3f3f46' }}>
            02 / CONNECT
          </span>
          <div className="h-px w-12" style={{ background: 'rgba(255,255,255,0.07)' }} />
        </motion.div>

        {/* Header row */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-8 mb-16">
          <motion.h2
            initial={{ opacity: 0, y: 16 }}
            animate={isInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.65, delay: 0.05 }}
            style={{
              fontFamily: "'Inter',sans-serif",
              fontSize: 'clamp(28px,4vw,48px)',
              fontWeight: 700,
              letterSpacing: '-0.03em',
              color: '#f4f4f5',
              lineHeight: 1.12,
              maxWidth: 500,
            }}
          >
            Every tool your team<br />uses, connected
          </motion.h2>
          <motion.div
            initial={{ opacity: 0 }}
            animate={isInView ? { opacity: 1 } : {}}
            transition={{ duration: 0.5, delay: 0.2 }}
            style={{ flexShrink: 0 }}
          >
            <div style={{ fontSize: 13, color: '#71717a', lineHeight: 1.6, maxWidth: 260 }}>
              Native integrations, no custom glue code. Events flow in real time from your
              existing toolchain.
            </div>
          </motion.div>
        </div>

        {/* Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {INTEGRATIONS.map((int, i) => (
            <motion.div
              key={int.name}
              initial={{ opacity: 0, y: 20 }}
              animate={isInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.45, delay: 0.2 + i * 0.05 }}
            >
              <TiltCard
                intensity={8}
                glowColor="rgba(255,255,255,0.03)"
                style={{
                  border: `1px solid ${int.border}`,
                  background: '#09090b',
                  padding: '20px 20px 18px',
                }}
              >
                {/* Header */}
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
                  {/* Monogram */}
                  <div style={{
                    width: 34, height: 34,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    border: `1px solid ${int.border}`,
                    background: 'rgba(255,255,255,0.02)',
                    fontFamily: "'JetBrains Mono',monospace",
                    fontSize: 10, fontWeight: 600,
                    color: int.color,
                    letterSpacing: '0.05em',
                  }}>
                    {int.tag}
                  </div>
                  {/* Connected pill */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#22c55e' }} />
                    <span className="font-mono" style={{ fontSize: 9, color: '#3f3f46', letterSpacing: '0.12em' }}>
                      LIVE
                    </span>
                  </div>
                </div>

                {/* Name */}
                <div style={{ fontSize: 14, fontWeight: 500, color: '#e4e4e7', marginBottom: 2 }}>
                  {int.name}
                </div>
                <div className="font-mono" style={{ fontSize: 9, color: '#3f3f46', letterSpacing: '0.12em', marginBottom: 16 }}>
                  {int.cat.toUpperCase()}
                </div>

                {/* Sparkline + events */}
                <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2 }}>
                    {Array.from({ length: 10 }).map((_, j) => (
                      <div
                        key={j}
                        style={{
                          width: 3,
                          height: 4 + Math.abs(Math.sin(j * 1.3 + i)) * 14,
                          background: 'rgba(255,255,255,0.1)',
                          borderRadius: 1,
                        }}
                      />
                    ))}
                  </div>
                  <span className="font-mono" style={{ fontSize: 10, color: '#52525b' }}>
                    {int.events}
                  </span>
                </div>
              </TiltCard>
            </motion.div>
          ))}
        </div>

        {/* Footer line */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={isInView ? { opacity: 1 } : {}}
          transition={{ duration: 0.5, delay: 0.8 }}
          style={{ marginTop: 32, display: 'flex', alignItems: 'center', gap: 12 }}
        >
          <div className="h-px flex-1" style={{ background: 'rgba(255,255,255,0.05)' }} />
          <span className="font-mono" style={{ fontSize: 10, color: '#3f3f46', letterSpacing: '0.18em' }}>
            +9 MORE VIA ORACLE BRIDGE API
          </span>
          <div className="h-px flex-1" style={{ background: 'rgba(255,255,255,0.05)' }} />
        </motion.div>
      </div>
    </section>
  )
}
