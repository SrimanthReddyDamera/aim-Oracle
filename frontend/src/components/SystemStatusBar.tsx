import { useEffect, useState } from 'react'

const BASE = [
  { label: 'Connected',  v: 247,   delta: 2,  suffix: '' },
  { label: 'Events/hr',  v: 1842,  delta: 15, suffix: '' },
  { label: 'Uptime',     v: 99.98, delta: 0,  suffix: '%', dec: 2 },
  { label: 'Workflows',  v: 17,    delta: 1,  suffix: '' },
]

function LiveClock() {
  const [t, setT] = useState('')
  useEffect(() => {
    const tick = () => setT(new Date().toISOString().replace('T',' ').slice(0,19) + ' UTC')
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])
  return <>{t}</>
}

export default function SystemStatusBar() {
  const [vals, setVals] = useState(BASE.map(m => m.v))

  useEffect(() => {
    const id = setInterval(() => {
      setVals(prev => prev.map((v, i) => {
        if (!BASE[i].delta) return v
        const j = (Math.random() - 0.45) * BASE[i].delta
        return Math.max(BASE[i].v - BASE[i].delta * 2, Math.min(BASE[i].v + BASE[i].delta * 2, v + j))
      }))
    }, 3500)
    return () => clearInterval(id)
  }, [])

  return (
    <div
      className="fixed bottom-0 left-0 right-0 z-[8000]"
      style={{
        height: 38,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 24px',
        background: 'rgba(9,9,11,0.9)',
        borderTop: '1px solid rgba(255,255,255,0.06)',
        backdropFilter: 'blur(12px)',
      }}
    >
      {/* Left */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#22c55e' }} />
        <span className="font-mono" style={{ fontSize: 10, color: '#3f3f46', letterSpacing: '0.14em' }}>
          ORACLE
        </span>
      </div>

      {/* Metrics */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 28 }}>
        {BASE.map((m, i) => (
          <div key={m.label} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <span className="font-mono" style={{ fontSize: 9, color: '#3f3f46', letterSpacing: '0.1em' }}
              hidden={false}>
              {m.label.toUpperCase()}
            </span>
            <span className="font-mono" style={{ fontSize: 10, color: '#71717a', fontVariantNumeric: 'tabular-nums' }}>
              {m.dec ? vals[i].toFixed(m.dec) : Math.round(vals[i]).toLocaleString()}{m.suffix}
            </span>
          </div>
        ))}
      </div>

      {/* Right: clock */}
      <div className="font-mono hidden lg:block" style={{ fontSize: 9, color: '#27272a', letterSpacing: '0.1em' }}>
        <LiveClock />
      </div>
    </div>
  )
}
