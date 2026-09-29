import { useRef, useEffect } from 'react'
import { motion, useInView } from 'framer-motion'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import AnimatedCounter from '@/components/ui/AnimatedCounter'

const METRICS = [
  { value: 247,   suffix: '',    label: 'Systems connected',    decimals: 0 },
  { value: 1842,  suffix: '',    label: 'Events per hour',      decimals: 0 },
  { value: 99.98, suffix: '%',   label: 'Operational uptime',   decimals: 2 },
  { value: 17,    suffix: '',    label: 'Active workflows',      decimals: 0 },
]

const CAPABILITIES = [
  'Real-time event ingestion',
  'Cross-system correlation',
  'Dependency graph mapping',
  'Anomaly detection at scale',
]

const ARCH_NODES = [
  { id: 'code',   label: 'Code',     x: 160,  y: 150, isCore: false },
  { id: 'build',  label: 'Build',    x: 350,  y: 100, isCore: false },
  { id: 'scan',   label: 'Scan',     x: 540,  y: 150, isCore: false },
  { id: 'deploy', label: 'Deploy',   x: 730,  y: 100, isCore: false },
  { id: 'cloud',  label: 'Cloud',    x: 890,  y: 150, isCore: false },
  { id: 'oracle', label: 'ORACLE',   x: 525,  y: 280, isCore: true  },
  { id: 'track',  label: 'Track',    x: 160,  y: 310, isCore: false },
  { id: 'teams',  label: 'Teams',    x: 890,  y: 310, isCore: false },
]

const ARCH_EDGES: [string, string][] = [
  ['code', 'build'], ['build', 'scan'], ['scan', 'deploy'], ['deploy', 'cloud'],
  ['code', 'oracle'], ['build', 'oracle'], ['scan', 'oracle'],
  ['deploy', 'oracle'], ['cloud', 'oracle'],
  ['track', 'oracle'], ['teams', 'oracle'],
]

export default function ObserveSection() {
  const ref = useRef<HTMLElement>(null)
  const isInView = useInView(ref, { once: true, margin: '-100px' })

  useEffect(() => {
    const ctx = gsap.context(() => {
      gsap.fromTo('.obs-line',
        { strokeDashoffset: 300, opacity: 0 },
        { strokeDashoffset: 0, opacity: 1, duration: 0.9, stagger: 0.06, ease: 'power2.out',
          scrollTrigger: { trigger: ref.current, start: 'top 72%' } }
      )
      gsap.fromTo('.obs-node',
        { scale: 0, opacity: 0 },
        { scale: 1, opacity: 1, duration: 0.45, stagger: 0.07, ease: 'back.out(1.5)',
          scrollTrigger: { trigger: ref.current, start: 'top 72%' } }
      )
    }, ref)
    return () => ctx.revert()
  }, [])

  const nodeMap = Object.fromEntries(ARCH_NODES.map(n => [n.id, n]))

  return (
    <section id="observe" ref={ref} className="chapter-section" style={{ background: '#09090b' }}>
      {/* Faint horizontal rule at top */}
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
            01 / OBSERVE
          </span>
          <div className="h-px w-12" style={{ background: 'rgba(255,255,255,0.07)' }} />
        </motion.div>

        {/* Two columns */}
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
                marginBottom: 20,
              }}
            >
              Unified visibility<br />across every system
            </motion.h2>
            <motion.p
              initial={{ opacity: 0, y: 12 }}
              animate={isInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.55, delay: 0.12 }}
              style={{ fontSize: 14, color: '#71717a', lineHeight: 1.7, fontWeight: 300, maxWidth: 380, marginBottom: 36 }}
            >
              ORACLE ingests events from every layer of your stack — version control,
              pipelines, security scanners, cloud providers — correlating them into one
              continuous operational picture.
            </motion.p>

            {/* Metrics */}
            <div className="grid grid-cols-2 gap-3 mb-10">
              {METRICS.map((m, i) => (
                <motion.div
                  key={m.label}
                  initial={{ opacity: 0, y: 12 }}
                  animate={isInView ? { opacity: 1, y: 0 } : {}}
                  transition={{ duration: 0.45, delay: 0.2 + i * 0.07 }}
                  style={{
                    padding: '16px 18px',
                    border: '1px solid rgba(255,255,255,0.07)',
                    background: '#111114',
                  }}
                >
                  <div style={{ fontSize: 28, fontWeight: 600, letterSpacing: '-0.03em', color: '#f4f4f5', lineHeight: 1 }}>
                    <AnimatedCounter value={m.value} suffix={m.suffix} decimals={m.decimals} />
                  </div>
                  <div className="font-mono" style={{ fontSize: 10, color: '#3f3f46', letterSpacing: '0.14em', marginTop: 6 }}>
                    {m.label.toUpperCase()}
                  </div>
                </motion.div>
              ))}
            </div>

            {/* Capabilities */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={isInView ? { opacity: 1 } : {}}
              transition={{ duration: 0.5, delay: 0.5 }}
              style={{ display: 'flex', flexDirection: 'column', gap: 10 }}
            >
              {CAPABILITIES.map(cap => (
                <div key={cap} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div style={{ width: 1, height: 12, background: 'rgba(255,255,255,0.2)', flexShrink: 0 }} />
                  <span style={{ fontSize: 13, color: '#71717a' }}>{cap}</span>
                </div>
              ))}
            </motion.div>
          </div>

          {/* Right: architecture SVG */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={isInView ? { opacity: 1 } : {}}
            transition={{ duration: 0.7, delay: 0.15 }}
            style={{ padding: '32px', border: '1px solid rgba(255,255,255,0.07)', background: '#111114' }}
          >
            <div className="font-mono" style={{ fontSize: 10, color: '#3f3f46', letterSpacing: '0.2em', marginBottom: 24 }}>
              SYSTEM TOPOLOGY
            </div>
            <svg viewBox="0 0 1060 420" style={{ width: '100%', overflow: 'visible' }}>
              {/* Edges */}
              {ARCH_EDGES.map(([a, b], i) => {
                const na = nodeMap[a], nb = nodeMap[b]
                const len = Math.sqrt((nb.x-na.x)**2+(nb.y-na.y)**2)
                const toCore = a === 'oracle' || b === 'oracle'
                return (
                  <line
                    key={i}
                    className="obs-line"
                    x1={na.x} y1={na.y} x2={nb.x} y2={nb.y}
                    stroke={toCore ? 'rgba(255,255,255,0.12)' : 'rgba(255,255,255,0.06)'}
                    strokeWidth="0.8"
                    strokeDasharray={`${len} ${len}`}
                    strokeDashoffset={300}
                  />
                )
              })}
              {/* Nodes */}
              {ARCH_NODES.map(n => (
                <g key={n.id} className="obs-node" style={{ transformOrigin: `${n.x}px ${n.y}px` }}>
                  {n.isCore ? (
                    <>
                      <circle cx={n.x} cy={n.y} r={30} fill="#09090b" stroke="rgba(255,255,255,0.2)" strokeWidth="1" />
                      <circle cx={n.x} cy={n.y} r={38} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="0.7" strokeDasharray="3 5" />
                      <text x={n.x} y={n.y+4} textAnchor="middle" fill="#f4f4f5" fontSize="7" fontFamily="'JetBrains Mono',monospace" fontWeight="600" letterSpacing="2.5">{n.label}</text>
                    </>
                  ) : (
                    <>
                      <circle cx={n.x} cy={n.y} r={17} fill="#09090b" stroke="rgba(255,255,255,0.09)" strokeWidth="0.8" />
                      <text x={n.x} y={n.y+4} textAnchor="middle" fill="#71717a" fontSize="6" fontFamily="'JetBrains Mono',monospace" letterSpacing="1">{n.label.toUpperCase()}</text>
                    </>
                  )}
                </g>
              ))}
            </svg>
          </motion.div>
        </div>
      </div>
    </section>
  )
}
