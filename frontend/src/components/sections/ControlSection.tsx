import { useRef } from 'react'
import { motion, useInView } from 'framer-motion'
import AnimatedCounter from '@/components/ui/AnimatedCounter'

const BIG_METRICS = [
  { label: 'Events processed',    value: 2847316, suffix: '',    sub: 'last 30 days',            decimals: 0 },
  { label: 'Incidents resolved',  value: 1284,    suffix: '',    sub: '99.3% auto-resolved',     decimals: 0 },
  { label: 'Mean time to resolve', value: 6.4,    suffix: 'min', sub: '↓ 64% vs baseline',       decimals: 1 },
  { label: 'Security findings',   value: 47,      suffix: '',    sub: '12 critical closed today', decimals: 0 },
]

const SERVICES = [
  { name: 'payments-api',  health: 'ok'   },
  { name: 'auth-service',  health: 'ok'   },
  { name: 'gateway-v2',    health: 'ok'   },
  { name: 'data-pipeline', health: 'warn' },
  { name: 'ml-inference',  health: 'ok'   },
  { name: 'notification',  health: 'ok'   },
  { name: 'scheduler',     health: 'ok'   },
  { name: 'search-idx',    health: 'warn' },
  { name: 'cache-layer',   health: 'ok'   },
  { name: 'cdn-edge',      health: 'ok'   },
  { name: 'billing-svc',   health: 'ok'   },
  { name: 'analytics',     health: 'crit' },
  { name: 'file-storage',  health: 'ok'   },
  { name: 'websocket',     health: 'ok'   },
  { name: 'reporting',     health: 'ok'   },
  { name: 'admin-api',     health: 'ok'   },
  { name: 'user-mgmt',     health: 'ok'   },
  { name: 'audit-log',     health: 'ok'   },
  { name: 'metrics-col',   health: 'ok'   },
  { name: 'alert-mgr',     health: 'ok'   },
]

const EVENTS_LOG = [
  { t: '16:42:41', type: 'RESOLVED',  svc: 'payments-api', msg: 'CVE-2024-4089 patched via PR #2841', col: '#22c55e' },
  { t: '16:39:12', type: 'DEPLOYED',  svc: 'auth-service', msg: 'v3.2.1 → prod · 0 error delta',     col: '#3b82f6' },
  { t: '16:35:08', type: 'INCIDENT',  svc: 'gateway-v2',   msg: 'p99 latency spike · auto-scaled +3', col: '#f59e0b' },
  { t: '16:28:54', type: 'ANALYSIS',  svc: 'ml-inference', msg: 'Model drift detected — retraining',  col: '#a78bfa' },
  { t: '16:18:07', type: 'RESOLVED',  svc: 'billing-svc',  msg: 'INC-4820 closed · MTTR 4m 38s',      col: '#22c55e' },
]

const DEPLOY_DATA = [14,22,18,31,28,9,11]
const DAY_LABELS  = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
const MAX_BAR = Math.max(...DEPLOY_DATA)

const HEALTH_COLOR: Record<string, string> = {
  ok:   '#22c55e',
  warn: '#f59e0b',
  crit: '#ef4444',
}
const HEALTH_OPACITY: Record<string, number> = { ok: 0.35, warn: 0.8, crit: 0.9 }

export default function ControlSection() {
  const ref = useRef<HTMLElement>(null)
  const isInView = useInView(ref, { once: true, margin: '-80px' })

  return (
    <section id="control" ref={ref} className="chapter-section" style={{ background: '#09090b' }}>
      <div className="absolute top-0 inset-x-0 h-px" style={{ background: 'rgba(255,255,255,0.06)' }} />

      <div className="relative max-w-7xl mx-auto px-6 md:px-12">

        {/* Chapter */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.5 }}
          className="flex items-center gap-4 mb-20"
        >
          <span className="font-mono text-[10px] tracking-[0.28em]" style={{ color: '#3f3f46' }}>05 / CONTROL</span>
          <div className="h-px w-12" style={{ background: 'rgba(255,255,255,0.07)' }} />
        </motion.div>

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
            marginBottom: 48,
            maxWidth: 560,
          }}
        >
          The full operational view, always within reach
        </motion.h2>

        {/* ── Big metrics ── */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 mb-4">
          {BIG_METRICS.map((m, i) => (
            <motion.div
              key={m.label}
              initial={{ opacity: 0, y: 16 }}
              animate={isInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.45, delay: 0.15 + i * 0.07 }}
              style={{
                padding: '20px 20px 18px',
                border: '1px solid rgba(255,255,255,0.07)',
                background: '#111114',
                position: 'relative',
                overflow: 'hidden',
              }}
            >
              <div className="font-mono" style={{ fontSize: 9, color: '#3f3f46', letterSpacing: '0.18em', marginBottom: 12 }}>
                {m.label.toUpperCase()}
              </div>
              <div style={{ fontSize: 'clamp(22px,3vw,34px)', fontWeight: 600, letterSpacing: '-0.03em', color: '#f4f4f5', lineHeight: 1, marginBottom: 6 }}>
                <AnimatedCounter value={m.value} suffix={m.suffix} decimals={m.decimals} />
              </div>
              <div style={{ fontSize: 12, color: '#3f3f46' }}>{m.sub}</div>
            </motion.div>
          ))}
        </div>

        {/* ── Bottom 3-col grid ── */}
        <div className="grid md:grid-cols-3 gap-2">

          {/* Service health */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={isInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.5, delay: 0.35 }}
            style={{ padding: '20px', border: '1px solid rgba(255,255,255,0.07)', background: '#111114' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
              <span className="font-mono" style={{ fontSize: 10, color: '#3f3f46', letterSpacing: '0.18em' }}>
                SERVICE HEALTH
              </span>
              <div style={{ display: 'flex', gap: 10 }}>
                {[['ok','#22c55e'],['warn','#f59e0b'],['crit','#ef4444']].map(([s,c]) => (
                  <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <div style={{ width: 6, height: 6, background: c as string, opacity: 0.7 }} />
                    <span className="font-mono" style={{ fontSize: 9, color: '#3f3f46' }}>{s}</span>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 4 }}>
              {SERVICES.map(s => (
                <div
                  key={s.name}
                  title={s.name}
                  style={{
                    aspectRatio: '1',
                    background: HEALTH_COLOR[s.health],
                    opacity: HEALTH_OPACITY[s.health],
                    cursor: 'default',
                  }}
                />
              ))}
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 14 }} className="font-mono">
              <span style={{ fontSize: 10, color: '#22c55e' }}>{SERVICES.filter(s=>s.health==='ok').length} healthy</span>
              <span style={{ fontSize: 10, color: '#f59e0b' }}>{SERVICES.filter(s=>s.health!=='ok').length} issues</span>
            </div>
          </motion.div>

          {/* Deploy bar chart */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={isInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.5, delay: 0.42 }}
            style={{ padding: '20px', border: '1px solid rgba(255,255,255,0.07)', background: '#111114' }}
          >
            <div className="font-mono" style={{ fontSize: 10, color: '#3f3f46', letterSpacing: '0.18em', marginBottom: 18 }}>
              DEPLOYS — 7 DAY
            </div>
            <div style={{ display: 'flex', alignItems: 'flex-end', gap: 8, height: 100, marginBottom: 10 }}>
              {DEPLOY_DATA.map((v, i) => (
                <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, height: '100%', justifyContent: 'flex-end' }}>
                  <motion.div
                    initial={{ scaleY: 0 }}
                    animate={isInView ? { scaleY: 1 } : {}}
                    transition={{ duration: 0.5, delay: 0.55 + i * 0.06, ease: 'easeOut' }}
                    style={{
                      width: '100%',
                      height: `${(v / MAX_BAR) * 88}px`,
                      background: 'rgba(255,255,255,0.12)',
                      transformOrigin: 'bottom',
                    }}
                  />
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              {DAY_LABELS.map(d => (
                <div key={d} style={{ flex: 1, textAlign: 'center' }}
                  className="font-mono">
                  <span style={{ fontSize: 9, color: '#3f3f46' }}>{d.slice(0,1)}</span>
                </div>
              ))}
            </div>
            <div style={{ marginTop: 14, height: 1, background: 'rgba(255,255,255,0.05)' }} />
            <div style={{ marginTop: 12, display: 'flex', justifyContent: 'space-between' }} className="font-mono">
              <span style={{ fontSize: 10, color: '#52525b' }}>{DEPLOY_DATA.reduce((a,b)=>a+b,0)} total</span>
              <span style={{ fontSize: 10, color: '#22c55e' }}>96% success</span>
            </div>
          </motion.div>

          {/* Event log */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={isInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.5, delay: 0.5 }}
            style={{ padding: '20px', border: '1px solid rgba(255,255,255,0.07)', background: '#111114' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
              <span className="font-mono" style={{ fontSize: 10, color: '#3f3f46', letterSpacing: '0.18em' }}>
                EVENT LOG
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#ef4444' }} className="oa-ping" />
                <span className="font-mono" style={{ fontSize: 9, color: '#3f3f46' }}>LIVE</span>
              </div>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {EVENTS_LOG.map((ev, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0 }}
                  animate={isInView ? { opacity: 1 } : {}}
                  transition={{ duration: 0.3, delay: 0.6 + i * 0.07 }}
                  style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}
                >
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: ev.col, flexShrink: 0, marginTop: 4 }} />
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                      <span style={{
                        fontFamily: "'JetBrains Mono',monospace",
                        fontSize: 9, letterSpacing: '0.1em',
                        padding: '1px 5px',
                        background: `${ev.col}12`,
                        color: ev.col,
                        border: `1px solid ${ev.col}22`,
                      }}>{ev.type}</span>
                      <span className="font-mono" style={{ fontSize: 9, color: '#3f3f46' }}>{ev.svc}</span>
                    </div>
                    <div style={{ fontSize: 11, color: '#52525b', lineHeight: 1.5 }}>{ev.msg}</div>
                    <div className="font-mono" style={{ fontSize: 9, color: '#27272a', marginTop: 2 }}>{ev.t}</div>
                  </div>
                </motion.div>
              ))}
            </div>
          </motion.div>
        </div>

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={isInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.55, delay: 0.75 }}
          style={{
            marginTop: 48, paddingTop: 40,
            borderTop: '1px solid rgba(255,255,255,0.06)',
            display: 'flex', flexDirection: 'column',
            gap: 8,
          }}
        >
          <div style={{ fontSize: 'clamp(20px,3vw,32px)', fontWeight: 600, letterSpacing: '-0.02em', color: '#f4f4f5' }}>
            Connect your systems in under 15 minutes.
          </div>
          <div style={{ fontSize: 14, color: '#71717a', marginBottom: 24 }}>
            No agents. No infra changes. One API key per integration.
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="#" style={{
              padding: '10px 22px', fontSize: 13, fontWeight: 500,
              background: '#f4f4f5', color: '#09090b', textDecoration: 'none',
              transition: 'background 0.15s',
            }}
              onMouseEnter={e => (e.currentTarget.style.background = '#e4e4e7')}
              onMouseLeave={e => (e.currentTarget.style.background = '#f4f4f5')}
            >
              Start free trial
            </a>
            <a href="#" style={{
              padding: '10px 22px', fontSize: 13,
              border: '1px solid rgba(255,255,255,0.12)', color: '#71717a', textDecoration: 'none',
              transition: 'border-color 0.15s, color 0.15s',
            }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.22)'; e.currentTarget.style.color = '#a1a1aa' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.12)'; e.currentTarget.style.color = '#71717a' }}
            >
              Book a demo
            </a>
          </div>
        </motion.div>
      </div>
    </section>
  )
}
