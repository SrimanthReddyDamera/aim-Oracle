import { motion, useInView } from 'framer-motion'
import { useRef } from 'react'

const COLS = [
  { heading: 'Product',  links: ['Control Plane', 'Intelligence', 'Integrations', 'Workflows', 'Security', 'Changelog'] },
  { heading: 'Platform', links: ['Architecture', 'API Reference', 'SDKs', 'CLI', 'Webhooks', 'Status'] },
  { heading: 'Company',  links: ['About', 'Blog', 'Careers', 'Press', 'Contact'] },
]

export default function OracleFooter() {
  const ref = useRef<HTMLElement>(null)
  const isInView = useInView(ref, { once: true, margin: '-40px' })

  return (
    <footer
      ref={ref}
      style={{
        background: '#09090b',
        borderTop: '1px solid rgba(255,255,255,0.06)',
        paddingBottom: 56,
      }}
    >
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '64px 48px 0' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr', gap: 48 }}
          className="grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">

          {/* Brand */}
          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={isInView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.5 }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
              <div style={{ width: 20, height: 20, border: '1px solid rgba(255,255,255,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <div style={{ width: 7, height: 7, background: '#f4f4f5' }} />
              </div>
              <span className="font-mono" style={{ fontSize: 12, fontWeight: 600, letterSpacing: '0.18em', color: '#f4f4f5' }}>
                ORACLE
              </span>
            </div>
            <p style={{ fontSize: 13, color: '#3f3f46', lineHeight: 1.7, maxWidth: 260, marginBottom: 20 }}>
              Enterprise Intelligence & Operations Control Plane. From code to cloud in one continuous system.
            </p>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
              <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#22c55e' }} />
              <span className="font-mono" style={{ fontSize: 9, color: '#3f3f46', letterSpacing: '0.14em' }}>
                ALL SYSTEMS OPERATIONAL
              </span>
            </div>
          </motion.div>

          {/* Link columns */}
          {COLS.map((col, ci) => (
            <motion.div
              key={col.heading}
              initial={{ opacity: 0, y: 12 }}
              animate={isInView ? { opacity: 1, y: 0 } : {}}
              transition={{ duration: 0.45, delay: 0.08 + ci * 0.06 }}
            >
              <div className="font-mono" style={{ fontSize: 10, color: '#3f3f46', letterSpacing: '0.2em', marginBottom: 20 }}>
                {col.heading.toUpperCase()}
              </div>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 12 }}>
                {col.links.map(l => (
                  <li key={l}>
                    <a
                      href="#"
                      style={{ fontSize: 13, color: '#52525b', textDecoration: 'none', transition: 'color 0.15s' }}
                      onMouseEnter={e => (e.currentTarget.style.color = '#a1a1aa')}
                      onMouseLeave={e => (e.currentTarget.style.color = '#52525b')}
                    >
                      {l}
                    </a>
                  </li>
                ))}
              </ul>
            </motion.div>
          ))}
        </div>

        {/* Bottom */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={isInView ? { opacity: 1 } : {}}
          transition={{ duration: 0.4, delay: 0.35 }}
          style={{
            marginTop: 56, paddingTop: 24,
            borderTop: '1px solid rgba(255,255,255,0.05)',
            display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12,
          }}
        >
          <span className="font-mono" style={{ fontSize: 10, color: '#27272a', letterSpacing: '0.1em' }}>
            © 2026 Oracle Systems Inc.
          </span>
          <div style={{ display: 'flex', gap: 24 }}>
            {['Privacy', 'Terms', 'Security'].map(t => (
              <a key={t} href="#" className="font-mono"
                style={{ fontSize: 10, color: '#27272a', textDecoration: 'none', letterSpacing: '0.1em', transition: 'color 0.15s' }}
                onMouseEnter={e => (e.currentTarget.style.color = '#52525b')}
                onMouseLeave={e => (e.currentTarget.style.color = '#27272a')}
              >
                {t.toUpperCase()}
              </a>
            ))}
          </div>
        </motion.div>
      </div>
    </footer>
  )
}
