import { useEffect, useRef, useState, useCallback } from 'react'
import { useNavigate } from 'react-router'
import { motion } from 'framer-motion'
import { gsap } from 'gsap'
import MagneticButton from '@/components/ui/MagneticButton'

/* ── Minimal schematic network ──────────────────────────────────────────── */
const CX = 460, CY = 230, R = 152

const NODES = [
  { id: 'git',   label: 'Git',      angle: -90, color: '#a1a1aa' },
  { id: 'cicd',  label: 'CI/CD',    angle: -30, color: '#a1a1aa' },
  { id: 'sast',  label: 'SAST',     angle:  30, color: '#a1a1aa' },
  { id: 'cloud', label: 'Cloud',    angle:  90, color: '#a1a1aa' },
  { id: 'teams', label: 'Slack',    angle: 150, color: '#a1a1aa' },
  { id: 'jira',  label: 'Jira',     angle: 210, color: '#a1a1aa' },
]

function nodeXY(angle: number, r = R) {
  const rad = (angle * Math.PI) / 180
  return { x: CX + r * Math.cos(rad), y: CY + r * Math.sin(rad) }
}

function OracleSchematic({ mouseX, mouseY }: { mouseX: number; mouseY: number }) {
  const nodes = NODES.map(n => ({ ...n, ...nodeXY(n.angle) }))
  const px = (mouseX - 0.5) * -8
  const py = (mouseY - 0.5) * -5

  return (
    <svg viewBox="0 0 920 460" className="w-full h-full" aria-hidden>
      <defs>
        <mask id="fade-mask">
          <radialGradient id="fade-grad" cx="50%" cy="50%" r="48%">
            <stop offset="30%" stopColor="white" stopOpacity="1" />
            <stop offset="100%" stopColor="white" stopOpacity="0" />
          </radialGradient>
          <rect width="920" height="460" fill="url(#fade-grad)" />
        </mask>
      </defs>

      <g mask="url(#fade-mask)">
        <g style={{ transform: `translate(${px}px,${py}px)`, transition: 'transform 0.15s ease-out' }}>

          {/* Hex ring between satellites */}
          {nodes.map((n, i) => {
            const next = nodes[(i + 1) % nodes.length]
            return (
              <motion.line
                key={`hex-${n.id}`}
                x1={n.x} y1={n.y} x2={next.x} y2={next.y}
                stroke="rgba(255,255,255,0.05)"
                strokeWidth="0.8"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 1.2, delay: 1.4 + i * 0.06 }}
              />
            )
          })}

          {/* Core → satellite spokes */}
          {nodes.map((n, i) => (
            <motion.line
              key={`spoke-${n.id}`}
              x1={CX} y1={CY} x2={n.x} y2={n.y}
              stroke="rgba(255,255,255,0.1)"
              strokeWidth="0.8"
              initial={{ pathLength: 0 }}
              animate={{ pathLength: 1 }}
              transition={{ duration: 0.9, delay: 0.7 + i * 0.08, ease: 'easeOut' }}
            />
          ))}

          {/* Traveling signal dots */}
          {nodes.map((n, i) =>
            [0, 1.4].map(phase => (
              <motion.circle
                key={`dot-${n.id}-${phase}`}
                r="1.8"
                fill="rgba(255,255,255,0.45)"
                animate={{
                  cx: [CX, n.x, CX],
                  cy: [CY, n.y, CY],
                  opacity: [0, 0.5, 0.5, 0],
                }}
                transition={{
                  duration: 2.8,
                  delay: 2 + phase + i * 0.2,
                  repeat: Infinity,
                  repeatDelay: 1.2,
                  ease: 'linear',
                }}
              />
            ))
          )}

          {/* Outer dashed orbit ring */}
          <motion.circle
            cx={CX} cy={CY} r={R + 22}
            fill="none"
            stroke="rgba(255,255,255,0.05)"
            strokeWidth="0.7"
            strokeDasharray="4 8"
            className="oa-rotate"
            style={{ transformOrigin: `${CX}px ${CY}px` }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.8 }}
          />

          {/* Core */}
          <motion.circle
            cx={CX} cy={CY} r={36}
            fill="#09090b"
            stroke="rgba(255,255,255,0.16)"
            strokeWidth="1"
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ duration: 0.55, delay: 1.2, type: 'spring', stiffness: 220 }}
            style={{ transformOrigin: `${CX}px ${CY}px` }}
          />
          <motion.circle
            cx={CX} cy={CY} r={42}
            fill="none"
            stroke="rgba(255,255,255,0.05)"
            strokeWidth="0.6"
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ duration: 0.55, delay: 1.3, type: 'spring' }}
            style={{ transformOrigin: `${CX}px ${CY}px` }}
          />
          <motion.text
            x={CX} y={CY - 4}
            textAnchor="middle"
            fill="rgba(255,255,255,0.7)"
            fontSize="7"
            fontFamily="'JetBrains Mono',monospace"
            fontWeight="600"
            letterSpacing="3"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 1.8 }}
          >ORACLE</motion.text>
          <motion.text
            x={CX} y={CY + 8}
            textAnchor="middle"
            fill="rgba(255,255,255,0.2)"
            fontSize="4.5"
            fontFamily="'JetBrains Mono',monospace"
            letterSpacing="1.5"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 2 }}
          >CORE</motion.text>

          {/* Satellite nodes */}
          {nodes.map((n, i) => (
            <motion.g
              key={n.id}
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ duration: 0.4, delay: 0.9 + i * 0.1, type: 'spring', stiffness: 200 }}
              style={{ transformOrigin: `${n.x}px ${n.y}px` }}
            >
              <circle cx={n.x} cy={n.y} r={15} fill="#09090b" stroke="rgba(255,255,255,0.1)" strokeWidth="0.8" />
              <text
                x={n.x} y={n.y + 4}
                textAnchor="middle"
                fill="rgba(255,255,255,0.4)"
                fontSize="5.5"
                fontFamily="'JetBrains Mono',monospace"
                fontWeight="500"
                letterSpacing="1.5"
              >
                {n.label.toUpperCase()}
              </text>
            </motion.g>
          ))}
        </g>
      </g>
    </svg>
  )
}

/* ── Hero ────────────────────────────────────────────────────────────────── */
export default function HeroSection() {
  const navigate = useNavigate()
  const [mouse, setMouse] = useState({ x: 0.5, y: 0.5 })

  const handleMouse = useCallback((e: MouseEvent) => {
    setMouse({ x: e.clientX / window.innerWidth, y: e.clientY / window.innerHeight })
  }, [])

  useEffect(() => {
    window.addEventListener('mousemove', handleMouse, { passive: true })
    return () => window.removeEventListener('mousemove', handleMouse)
  }, [handleMouse])

  useEffect(() => {
    const tl = gsap.timeline({ delay: 0.3 })
    tl.fromTo('.hero-badge',   { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.5, ease: 'power2.out' })
      .fromTo('.hero-word',    { opacity: 0, y: 18 }, { opacity: 1, y: 0, duration: 0.65, stagger: 0.12, ease: 'power3.out' }, '-=0.1')
      .fromTo('.hero-tag',     { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.5, ease: 'power2.out' }, '-=0.2')
      .fromTo('.hero-body',    { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.5, ease: 'power2.out' }, '-=0.15')
      .fromTo('.hero-cta',     { opacity: 0, y: 8  }, { opacity: 1, y: 0, duration: 0.4, stagger: 0.07, ease: 'power2.out' }, '-=0.2')
      .fromTo('.hero-diagram', { opacity: 0, y: 24 }, { opacity: 1, y: 0, duration: 1.0, ease: 'power2.out' }, '-=0.3')
      .fromTo('.hero-scroll',  { opacity: 0 },        { opacity: 1, duration: 0.5 }, '-=0.2')
    return () => { tl.kill() }
  }, [])

  return (
    <section
      className="relative min-h-screen flex flex-col overflow-hidden"
      style={{ backgroundColor: '#09090b' }}
    >
      {/* Subtle vignette edges */}
      <div className="absolute inset-0 pointer-events-none" style={{
        background: 'radial-gradient(ellipse 80% 60% at 50% 40%, transparent 40%, rgba(9,9,11,0.6) 100%)'
      }} />

      {/* Bottom fade */}
      <div className="absolute inset-x-0 bottom-0 h-48 pointer-events-none"
        style={{ background: 'linear-gradient(to bottom,transparent,#09090b)' }} />

      {/* ── Text area ── */}
      <div className="relative z-10 max-w-5xl mx-auto w-full px-6 md:px-12 pt-36 pb-4">

        {/* Status badge */}
        <div className="hero-badge opacity-0 flex items-center gap-2.5 mb-10">
          <span className="relative flex h-1.5 w-1.5">
            <span className="oa-ping absolute inset-0 rounded-full" style={{ background: '#22c55e', opacity: 0.5 }} />
            <span className="relative rounded-full h-1.5 w-1.5" style={{ background: '#22c55e' }} />
          </span>
          <span className="font-mono text-[10px] tracking-[0.22em]" style={{ color: '#3f3f46' }}>
            SYSTEM OPERATIONAL · v4.2.1
          </span>
        </div>

        {/* Headline — word by word so each can stagger */}
        <h1 className="overflow-hidden mb-5" style={{ lineHeight: 1 }}>
          {['Enterprise', 'Intelligence', '&', 'Operations', 'Control Plane.'].map((word, i) => (
            <span
              key={i}
              className="hero-word opacity-0 inline-block mr-[0.22em]"
              style={{
                fontFamily: "'Inter', sans-serif",
                fontSize: 'clamp(36px, 6.5vw, 78px)',
                fontWeight: 700,
                letterSpacing: '-0.03em',
                color: ['&'].includes(word) ? '#3f3f46' : '#f4f4f5',
              }}
            >
              {word}
            </span>
          ))}
        </h1>

        {/* Eyebrow tag */}
        <div className="hero-tag opacity-0 flex items-center gap-3 mb-5">
          <span className="font-mono text-[10px] tracking-[0.2em]" style={{ color: '#3f3f46' }}>
            ORACLE
          </span>
          <div className="h-px w-8" style={{ background: 'rgba(255,255,255,0.1)' }} />
          <span className="font-mono text-[10px] tracking-[0.2em]" style={{ color: '#3f3f46' }}>
            ENTERPRISE GRADE
          </span>
        </div>

        {/* Body copy */}
        <p
          className="hero-body opacity-0 mb-10 max-w-md leading-relaxed text-sm"
          style={{ color: '#71717a', fontWeight: 300 }}
        >
          One control plane connecting Git, CI/CD, security, cloud, and teams —
          correlating signals into actionable intelligence across your entire delivery lifecycle.
        </p>

        {/* CTAs */}
        <div className="flex items-center gap-3 flex-wrap">
          <MagneticButton
            className="hero-cta opacity-0"
            variant="primary"
            onClick={() => navigate('/app')}
          >
            Enter Control Plane →
          </MagneticButton>
          <MagneticButton
            className="hero-cta opacity-0"
            variant="ghost"
            onClick={() => {
              document.getElementById('observe')?.scrollIntoView({ behavior: 'smooth' })
            }}
          >
            View architecture ↓
          </MagneticButton>
        </div>
      </div>

      {/* ── Schematic diagram ── */}
      <div
        className="hero-diagram opacity-0 relative z-10 w-full max-w-4xl mx-auto px-6 mt-8"
        style={{ height: 'clamp(260px, 38vw, 420px)' }}
      >
        <OracleSchematic mouseX={mouse.x} mouseY={mouse.y} />
      </div>

      {/* ── Scroll hint ── */}
      <div className="hero-scroll opacity-0 relative z-10 flex flex-col items-center gap-2 pb-10 mt-2">
        <motion.div
          animate={{ y: [0, 6, 0] }}
          transition={{ duration: 2.2, repeat: Infinity, ease: 'easeInOut' }}
          style={{ width: 1, height: 28, background: 'linear-gradient(to bottom,rgba(255,255,255,0.18),transparent)' }}
        />
        <span className="font-mono text-[9px] tracking-[0.25em]" style={{ color: '#3f3f46' }}>
          SCROLL
        </span>
      </div>
    </section>
  )
}
