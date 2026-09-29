import { useEffect, useRef } from 'react'

export default function CustomCursor() {
  const dotRef  = useRef<HTMLDivElement>(null)
  const ringRef = useRef<HTMLDivElement>(null)
  const cur     = useRef({ x: -100, y: -100 })
  const ring    = useRef({ x: -100, y: -100 })
  const raf     = useRef(0)

  useEffect(() => {
    if (window.matchMedia('(pointer: coarse)').matches) return

    const move = (e: MouseEvent) => {
      cur.current = { x: e.clientX, y: e.clientY }
      if (dotRef.current)
        dotRef.current.style.transform = `translate(${e.clientX - 3}px,${e.clientY - 3}px)`
    }

    const tick = () => {
      ring.current.x += (cur.current.x - ring.current.x) * 0.1
      ring.current.y += (cur.current.y - ring.current.y) * 0.1
      if (ringRef.current)
        ringRef.current.style.transform = `translate(${ring.current.x - 14}px,${ring.current.y - 14}px)`
      raf.current = requestAnimationFrame(tick)
    }

    window.addEventListener('mousemove', move)
    raf.current = requestAnimationFrame(tick)

    const over  = () => { if (ringRef.current) ringRef.current.style.opacity = '0.3' }
    const out   = () => { if (ringRef.current) ringRef.current.style.opacity = '1' }
    document.querySelectorAll('a,button').forEach(el => {
      el.addEventListener('mouseenter', over)
      el.addEventListener('mouseleave', out)
    })

    return () => {
      window.removeEventListener('mousemove', move)
      cancelAnimationFrame(raf.current)
    }
  }, [])

  return (
    <>
      <div ref={dotRef} style={{
        position: 'fixed', top: 0, left: 0,
        width: 6, height: 6, borderRadius: '50%',
        background: '#f4f4f5',
        pointerEvents: 'none', zIndex: 99999,
        willChange: 'transform',
      }} />
      <div ref={ringRef} style={{
        position: 'fixed', top: 0, left: 0,
        width: 28, height: 28, borderRadius: '50%',
        border: '1px solid rgba(255,255,255,0.2)',
        pointerEvents: 'none', zIndex: 99998,
        willChange: 'transform',
        transition: 'opacity 0.2s',
      }} />
    </>
  )
}
