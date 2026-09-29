import { useEffect, useRef } from 'react'
import { gsap } from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import Navigation from '@/components/Navigation'
import CustomCursor from '@/components/CustomCursor'
import HeroSection from '@/components/HeroSection'
import SystemStatusBar from '@/components/SystemStatusBar'
import ObserveSection from '@/components/sections/ObserveSection'
import ConnectSection from '@/components/sections/ConnectSection'
import IntelligenceSection from '@/components/sections/IntelligenceSection'
import ActSection from '@/components/sections/ActSection'
import ControlSection from '@/components/sections/ControlSection'
import OracleFooter from '@/components/OracleFooter'

gsap.registerPlugin(ScrollTrigger)

export default function App() {
  const progressRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const ctx = gsap.context(() => {
      gsap.to(progressRef.current, {
        scaleX: 1,
        ease: 'none',
        scrollTrigger: {
          trigger: document.body,
          start: 'top top',
          end: 'bottom bottom',
          scrub: 0.3,
        },
      })
    })
    return () => ctx.revert()
  }, [])

  return (
    <div className="relative" style={{ backgroundColor: '#04060d' }}>
      <div
        ref={progressRef}
        className="fixed top-0 left-0 right-0 h-px z-[9998] origin-left"
        style={{
          background: 'linear-gradient(90deg, #22d3ee, #3b82f6, #8b5cf6)',
          transform: 'scaleX(0)',
        }}
      />
      <CustomCursor />
      <Navigation />
      <main>
        <HeroSection />
        <ObserveSection />
        <ConnectSection />
        <IntelligenceSection />
        <ActSection />
        <ControlSection />
      </main>
      <OracleFooter />
      <SystemStatusBar />
    </div>
  )
}
