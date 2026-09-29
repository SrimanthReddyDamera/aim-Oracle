import { useRef, useState, useEffect } from 'react'
import { motion, useInView } from 'framer-motion'

const STEPS = [
  { id: 'detect',  label: 'Detect',  desc: 'Anomaly surfaces across correlated signal streams',           n: '01' },
  { id: 'analyze', label: 'Analyze', desc: 'Root cause isolated · blast radius calculated',               n: '02' },
  { id: 'decide',  label: 'Decide',  desc: 'Response strategy selected from versioned policy ruleset',    n: '03' },
  { id: 'approve', label: 'Approve', desc: 'Human gate — auto-approved for severity below threshold',     n: '04' },
  { id: 'execute', label: 'Execute', desc: 'Orchestrated runbook runs across affected services',          n: '05' },
  { id: 'verify',  label: 'Verify',  desc: 'Health checks confirm resolution · MTTR logged',             n: '06' },
]

const RUNS = [
  { name: 'Security patch deployment',     dur: '6m 12s', runs: 142,  status: 'completed' },
  { name: 'Incident auto-remediation',     dur: '2m 48s', runs: 89,   status: 'completed' },
  { name: 'Dependency vulnerability fix',  dur: '11m 03s', runs: 34,   status: 'running'   },
  { name: 'Failed build rollback',         dur: '1m 22s', runs: 203,  status: 'completed' },
]

export default function ActSection() {
  const ref = useRef<HTMLElement>(null)
  const isInView = useInView(ref, { once: true, margin: '-80px' })
  const [active, setActive] = useState(-1)

  useEffect(() => {
    if (!isInView) return
    let i = 0
    const id = setInterval(() => { setActive(i); i++; if (i >= STEPS.length) clearInterval(id) }, 500)
    return () => clearInterval(id)
  }, [isInView])

  return (
    <section id="act" ref={ref} className="chapter-section" style={{ background: '#0d0d10' }}>
      <div className="absolute top-0 inset-x-0 h-px" style={{ background: 'rgba(255,255,255,0.06)' }} />

      <div className="relative max-w-7xl mx-auto px-6 md:px-12">

        {/* Chapter */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.5 }}
          className="flex items-center gap-4 mb-20"
        >
          <span className="font-mono text-[10px] tracking-[0.28em]" style={{ color: '#3f3f46' }}>04 / ACT</span>
          <div className="h-px w-12" style={{ background: 'rgba(255,255,255,0.07)' }} />
        </motion.div>

        <div className="grid md:grid-cols-2 gap-20 items-start">

          {/* Left */}
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
              Automated action,<br />human control
            </motion.h2>
            <motion.p
              initial={{ opacity: 0, y: 12 }}
              animate={isInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.55, delay: 0.12 }}
              style={{ fontSize: 14, color: '#71717a', lineHeight: 1.7, fontWeight: 300, marginBottom: 36, maxWidth: 380 }}
            >
              ORACLE executes runbooks across your infrastructure with configurable approval gates.
              Humans stay in control. Machines handle the heavy lifting.
            </motion.p>

            {/* Workflow steps */}
            <div style={{ position: 'relative' }}>
              {STEPS.map((step, i) => {
                const on = i <= active
                return (
                  <motion.div
                    key={step.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={isInView ? { opacity: 1, x: 0 } : {}}
                    transition={{ duration: 0.4, delay: 0.2 + i * 0.06 }}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: 16,
                      paddingBottom: 24,
                      borderBottom: i < STEPS.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                      marginBottom: i < STEPS.length - 1 ? 24 : 0,
                    }}
                  >
                    {/* Step indicator */}
                    <div style={{ position: 'relative', flexShrink: 0 }}>
                      <div style={{
                        width: 28, height: 28,
                        border: `1px solid ${on ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.07)'}`,
                        background: on ? 'rgba(255,255,255,0.05)' : 'transparent',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        transition: 'all 0.4s',
                      }}>
                        {on && i < active ? (
                          <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                            <path d="M1.5 5L4 7.5L8.5 2.5" stroke="#22c55e" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
                          </svg>
                        ) : (
                          <span className="font-mono" style={{ fontSize: 9, color: on ? '#a1a1aa' : '#3f3f46' }}>{step.n}</span>
                        )}
                      </div>
                      {i < STEPS.length - 1 && (
                        <div style={{
                          position: 'absolute', top: 28, left: '50%', transform: 'translateX(-50%)',
                          width: 1, height: 24,
                          background: on ? 'rgba(255,255,255,0.12)' : 'rgba(255,255,255,0.04)',
                          transition: 'background 0.4s',
                        }} />
                      )}
                    </div>
                    {/* Content */}
                    <div style={{ paddingTop: 4 }}>
                      <div style={{
                        fontSize: 14, fontWeight: 500, marginBottom: 3,
                        color: on ? '#e4e4e7' : '#3f3f46',
                        transition: 'color 0.4s',
                      }}>
                        {step.label}
                      </div>
                      <div style={{
                        fontSize: 13, color: on ? '#52525b' : '#27272a',
                        lineHeight: 1.55, transition: 'color 0.4s',
                      }}>
                        {step.desc}
                      </div>
                    </div>
                  </motion.div>
                )
              })}
            </div>
          </div>

          {/* Right: recent runs */}
          <div>
            <motion.div
              initial={{ opacity: 0 }}
              animate={isInView ? { opacity: 1 } : {}}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              {/* Big stat */}
              <div style={{ marginBottom: 40 }}>
                <div style={{ fontSize: 72, fontWeight: 700, letterSpacing: '-0.04em', color: '#f4f4f5', lineHeight: 1 }}>
                  64%
                </div>
                <div style={{ fontSize: 13, color: '#71717a', marginTop: 8 }}>
                  Reduction in mean time to resolution vs baseline
                </div>
              </div>

              <div style={{ height: 1, background: 'rgba(255,255,255,0.06)', marginBottom: 32 }} />

              <div className="font-mono" style={{ fontSize: 10, color: '#3f3f46', letterSpacing: '0.2em', marginBottom: 16 }}>
                RECENT EXECUTIONS
              </div>

              <div style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
                {RUNS.map((run, i) => (
                  <motion.div
                    key={run.name}
                    initial={{ opacity: 0 }}
                    animate={isInView ? { opacity: 1 } : {}}
                    transition={{ duration: 0.35, delay: 0.5 + i * 0.07 }}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '14px 18px',
                      borderBottom: i < RUNS.length - 1 ? '1px solid rgba(255,255,255,0.05)' : 'none',
                      background: '#09090b',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{
                        width: 6, height: 6, borderRadius: '50%',
                        background: run.status === 'running' ? '#f59e0b' : '#22c55e',
                        flexShrink: 0,
                      }} />
                      <span style={{ fontSize: 13, color: '#a1a1aa' }}>{run.name}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 20 }} className="font-mono">
                      <span style={{ fontSize: 10, color: '#3f3f46' }}>{run.dur}</span>
                      <span style={{ fontSize: 10, color: '#3f3f46' }}>{run.runs}×</span>
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
