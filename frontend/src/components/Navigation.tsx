import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { motion, AnimatePresence } from 'framer-motion'

const LINKS = [
  { label: 'Observe',      href: '#observe' },
  { label: 'Connect',      href: '#connect' },
  { label: 'Intelligence', href: '#intelligence' },
  { label: 'Act',          href: '#act' },
  { label: 'Control',      href: '#control' },
]

export default function Navigation() {
  const [scrolled, setScrolled]   = useState(false)
  const [active, setActive]       = useState('')
  const [menuOpen, setMenuOpen]   = useState(false)

  useEffect(() => {
    const fn = () => setScrolled(window.scrollY > 32)
    window.addEventListener('scroll', fn, { passive: true })
    return () => window.removeEventListener('scroll', fn)
  }, [])

  useEffect(() => {
    const ids = LINKS.map(l => document.getElementById(l.href.slice(1)))
    const obs = new IntersectionObserver(
      entries => entries.forEach(e => e.isIntersecting && setActive(e.target.id)),
      { threshold: 0.3 }
    )
    ids.forEach(el => el && obs.observe(el))
    return () => obs.disconnect()
  }, [])

  return (
    <motion.header
      initial={{ y: -56, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
      className="fixed top-0 left-0 right-0 z-[9000]"
      style={{
        height: 56,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 40px',
        background: scrolled ? 'rgba(9,9,11,0.85)' : 'transparent',
        backdropFilter: scrolled ? 'blur(16px) saturate(180%)' : 'none',
        borderBottom: scrolled ? '1px solid rgba(255,255,255,0.07)' : '1px solid transparent',
        transition: 'background 0.35s, border-color 0.35s',
      }}
    >
      {/* Logo */}
      <a href="#" style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none' }}>
        <div style={{
          width: 22, height: 22,
          border: '1px solid rgba(255,255,255,0.18)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <div style={{ width: 8, height: 8, background: '#f4f4f5' }} />
        </div>
        <span className="font-mono" style={{
          fontSize: 12, fontWeight: 600, letterSpacing: '0.18em', color: '#f4f4f5'
        }}>
          ORACLE
        </span>
      </a>

      {/* Desktop links */}
      <nav style={{ display: 'flex', alignItems: 'center', gap: 32 }} className="hidden md:flex">
        {LINKS.map(l => {
          const isActive = active === l.href.slice(1)
          return (
            <a
              key={l.href}
              href={l.href}
              style={{
                fontSize: 13,
                color: isActive ? '#f4f4f5' : '#71717a',
                textDecoration: 'none',
                transition: 'color 0.2s',
                position: 'relative',
              }}
              onMouseEnter={e => { if (!isActive) (e.currentTarget as HTMLElement).style.color = '#a1a1aa' }}
              onMouseLeave={e => { if (!isActive) (e.currentTarget as HTMLElement).style.color = '#71717a' }}
            >
              {l.label}
              {isActive && (
                <motion.span
                  layoutId="nav-dot"
                  style={{
                    position: 'absolute',
                    bottom: -18,
                    left: '50%',
                    transform: 'translateX(-50%)',
                    width: 3,
                    height: 3,
                    borderRadius: '50%',
                    background: '#f4f4f5',
                    display: 'block',
                  }}
                />
              )}
            </a>
          )
        })}
      </nav>

      {/* Right */}
      <div className="hidden md:flex" style={{ alignItems: 'center', gap: 16 }}>
        <Link
          to="/login"
          style={{ fontSize: 13, color: '#71717a', textDecoration: 'none' }}
          onMouseEnter={e => (e.currentTarget.style.color = '#a1a1aa')}
          onMouseLeave={e => (e.currentTarget.style.color = '#71717a')}
        >
          Sign in
        </Link>
        <Link
          to="/app"
          style={{
            fontSize: 12,
            background: '#f4f4f5',
            color: '#09090b',
            padding: '7px 16px',
            textDecoration: 'none',
            fontWeight: 600,
            borderRadius: 6,
            display: 'flex',
            alignItems: 'center',
            gap: 7,
            transition: 'all 0.15s',
          }}
          onMouseEnter={e => (e.currentTarget.style.background = '#e4e4e7')}
          onMouseLeave={e => (e.currentTarget.style.background = '#f4f4f5')}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-ogreen" />
          Control Plane →
        </Link>
      </div>

      {/* Mobile toggle */}
      <button
        className="md:hidden flex flex-col gap-1.5 p-2"
        onClick={() => setMenuOpen(o => !o)}
        aria-label="Menu"
        style={{ background: 'none', border: 'none', cursor: 'pointer' }}
      >
        {[0, 1, 2].map(i => (
          <div key={i} style={{
            width: 20, height: 1,
            background: '#71717a',
            transform:
              menuOpen && i === 0 ? 'rotate(45deg) translate(3px,3px)' :
              menuOpen && i === 1 ? 'scaleX(0)' :
              menuOpen && i === 2 ? 'rotate(-45deg) translate(3px,-3px)' : 'none',
            transition: 'transform 0.25s',
          }} />
        ))}
      </button>

      {/* Mobile menu */}
      <AnimatePresence>
        {menuOpen && (
          <motion.div
            initial={{ opacity: 0, y: -8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.18 }}
            style={{
              position: 'absolute', top: '100%', left: 0, right: 0,
              background: 'rgba(9,9,11,0.97)',
              borderBottom: '1px solid rgba(255,255,255,0.07)',
              backdropFilter: 'blur(16px)',
              padding: '24px 40px',
              display: 'flex', flexDirection: 'column', gap: 20,
            }}
          >
            {LINKS.map(l => (
              <a
                key={l.href}
                href={l.href}
                onClick={() => setMenuOpen(false)}
                style={{ fontSize: 15, color: '#71717a', textDecoration: 'none' }}
              >
                {l.label}
              </a>
            ))}
            <a
              href="#control"
              onClick={() => setMenuOpen(false)}
              style={{ fontSize: 13, color: '#f4f4f5', textDecoration: 'none', marginTop: 8 }}
            >
              Get started →
            </a>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.header>
  )
}
