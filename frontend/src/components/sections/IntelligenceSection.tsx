import { useRef, useEffect, useState } from 'react'
import { motion, useInView } from 'framer-motion'

const EVENTS = [
  { t: '16:42:31', type: 'BUILD',    label: 'FAILED',   msg: 'payments-api · main branch · exit code 1',            col: '#ef4444' },
  { t: '16:42:33', type: 'ORACLE',   label: 'INGESTED', msg: '847 correlated signals across 12 connected systems',   col: '#f4f4f5' },
  { t: '16:42:34', type: 'ANALYSIS', label: 'CAUSE',    msg: 'Dependency conflict — @stripe/node 14.8 broke lockfile', col: '#f59e0b' },
  { t: '16:42:35', type: 'SAST',     label: 'CVE',      msg: 'CVE-2024-4089 detected in transitive dependency chain', col: '#ef4444' },
  { t: '16:42:36', type: 'ORACLE',   label: 'SCORED',   msg: 'Severity: HIGH · Breach window: 34 min',               col: '#f4f4f5' },
  { t: '16:42:37', type: 'INCIDENT', label: 'CREATED',  msg: 'INC-4821 · Owner: @platform-team · SLA: 2 hrs',        col: '#a78bfa' },
  { t: '16:42:38', type: 'NOTIFY',   label: 'SENT',     msg: '#platform-alerts · incident briefing dispatched',       col: '#22c55e' },
  { t: '16:42:39', type: 'ORACLE',   label: 'ACTION',   msg: 'Recommendation: pin @stripe/node → 13.9.0-LTS',        col: '#f4f4f5' },
  { t: '16:42:40', type: 'PR',       label: 'OPENED',   msg: '#2841 — automated patch — CI triggered',               col: '#3b82f6' },
  { t: '16:42:41', type: 'ORACLE',   label: 'ETA',      msg: 'Resolution in ~8 min · based on 23 historical runs',   col: '#f4f4f5' },
]

const CAPABILITIES = [
  ['Root cause analysis',   'Correlates 800+ signals in under 3 seconds'],
  ['Predictive alerting',   'Flags risk windows before they become incidents'],
  ['Impact scoring',        'Severity + blast radius calculated automatically'],
  ['Remediation guidance',  'Actionable steps, not vague alerts'],
]

export default function IntelligenceSection() {
  const ref = useRef<HTMLElement>(null)
  const isInView = useInView(ref, { once: true, margin: '-80px' })
  const [lines, setLines] = useState(0)

  useEffect(() => {
    if (!isInView) return
    let i = 0
    const id = setInterval(() => {
      i++
      setLines(i)
      if (i >= EVENTS.length) clearInterval(id)
    }, 420)
    return () => clearInterval(id)
  }, [isInView])

  return (
    <section
      id="intelligence"
      ref={ref}
      className="chapter-section"
      style={{ background: '#09090b' }}
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
            03 / INTELLIGENCE
          </span>
          <div className="h-px w-12" style={{ background: 'rgba(255,255,255,0.07)' }} />
        </motion.div>

        <div className="grid md:grid-cols-2 gap-20 items-start">

          {/* Left: terminal */}
          <div>
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
                marginBottom: 16,
              }}
            >
              AI that understands<br />your full system
            </motion.h2>
            <motion.p
              initial={{ opacity: 0, y: 12 }}
              animate={isInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.55, delay: 0.12 }}
              style={{ fontSize: 14, color: '#71717a', lineHeight: 1.7, fontWeight: 300, maxWidth: 380, marginBottom: 36 }}
            >
              Not another alert dashboard. ORACLE correlates signals across your delivery
              lifecycle, isolates root causes, and recommends exactly what to do next.
            </motion.p>

            {/* Terminal */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={isInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.6, delay: 0.18 }}
              style={{ border: '1px solid rgba(255,255,255,0.08)', background: '#0c0c0f', overflow: 'hidden' }}
            >
              {/* Window chrome */}
              <div style={{
                display: 'flex', alignItems: 'center', gap: 7,
                padding: '10px 16px',
                borderBottom: '1px solid rgba(255,255,255,0.05)',
                background: 'rgba(255,255,255,0.02)',
              }}>
                {['#3f3f46','#3f3f46','#3f3f46'].map((c,i) => (
                  <div key={i} style={{ width: 8, height: 8, borderRadius: '50%', background: c }} />
                ))}
                <span className="font-mono" style={{ fontSize: 10, color: '#3f3f46', marginLeft: 8, letterSpacing: '0.12em' }}>
                  oracle — event stream
                </span>
                <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#ef4444' }} />
                  <span className="font-mono" style={{ fontSize: 9, color: '#3f3f46' }}>REC</span>
                </div>
              </div>

              {/* Events */}
              <div style={{ padding: '16px', minHeight: 340, fontFamily: "'JetBrains Mono',monospace" }}>
                {EVENTS.slice(0, lines).map((ev, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: -6 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.25 }}
                    style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 6 }}
                  >
                    <span style={{ fontSize: 10, color: '#3f3f46', flexShrink: 0, marginTop: 1 }}>{ev.t}</span>
                    <span style={{
                      fontSize: 9, letterSpacing: '0.1em',
                      padding: '1px 5px', flexShrink: 0, marginTop: 1,
                      background: `${ev.col}12`,
                      color: ev.col,
                      border: `1px solid ${ev.col}22`,
                    }}>
                      {ev.label}
                    </span>
                    <span style={{ fontSize: 11, color: ev.type === 'ORACLE' ? '#a1a1aa' : '#52525b', lineHeight: 1.5 }}>
                      {ev.msg}
                    </span>
                  </motion.div>
                ))}
                {lines < EVENTS.length && (
                  <span className="oa-blink" style={{ fontSize: 12, color: '#3f3f46' }}>▋</span>
                )}
              </div>
            </motion.div>
          </div>

          {/* Right: capabilities */}
          <div>
            <motion.div
              initial={{ opacity: 0 }}
              animate={isInView ? { opacity: 1 } : {}}
              transition={{ duration: 0.5, delay: 0.3 }}
              style={{ marginBottom: 40 }}
            >
              {/* Big stat */}
              <div style={{ marginBottom: 40 }}>
                <div style={{ fontSize: 72, fontWeight: 700, letterSpacing: '-0.04em', color: '#f4f4f5', lineHeight: 1 }}>
                  3s
                </div>
                <div style={{ fontSize: 13, color: '#71717a', marginTop: 8 }}>
                  Average time from event to root cause
                </div>
              </div>

              {/* Horizontal rule */}
              <div style={{ height: 1, background: 'rgba(255,255,255,0.06)', marginBottom: 32 }} />

              {/* Capabilities */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
                {CAPABILITIES.map(([title, desc], i) => (
                  <motion.div
                    key={title}
                    initial={{ opacity: 0, y: 10 }}
                    animate={isInView ? { opacity: 1, y: 0 } : {}}
                    transition={{ duration: 0.4, delay: 0.4 + i * 0.08 }}
                  >
                    <div style={{
                      display: 'flex', alignItems: 'flex-start', gap: 14,
                      paddingBottom: 24,
                      borderBottom: '1px solid rgba(255,255,255,0.05)',
                    }}>
                      <div style={{ width: 1, height: 36, background: 'rgba(255,255,255,0.15)', flexShrink: 0, marginTop: 2 }} />
                      <div>
                        <div style={{ fontSize: 14, fontWeight: 500, color: '#e4e4e7', marginBottom: 4 }}>{title}</div>
                        <div style={{ fontSize: 13, color: '#52525b', lineHeight: 1.5 }}>{desc}</div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    </section>
  )
}
