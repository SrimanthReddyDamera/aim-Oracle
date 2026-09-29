import { useState, type ReactNode, type ButtonHTMLAttributes } from 'react'
import { motion } from 'framer-motion'

interface MagneticButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'onMouseEnter' | 'onMouseLeave' | 'onMouseMove'> {
  children: ReactNode
  variant?: 'primary' | 'outline' | 'ghost'
  strength?: number
}

export default function MagneticButton({
  children,
  variant = 'outline',
  strength = 0.28,
  className = '',
  style,
  ...props
}: MagneticButtonProps) {
  const [pos, setPos] = useState({ x: 0, y: 0 })

  const base: React.CSSProperties =
    variant === 'primary'
      ? { background: '#f4f4f5', color: '#09090b', border: 'none', fontWeight: 500 }
      : variant === 'outline'
      ? { background: 'transparent', color: '#f4f4f5', border: '1px solid rgba(255,255,255,0.14)' }
      : { background: 'transparent', color: '#71717a', border: 'none' }

  return (
    <motion.button
      animate={{ x: pos.x, y: pos.y }}
      transition={{ type: 'spring', stiffness: 340, damping: 22 }}
      onMouseMove={e => {
        const rect = e.currentTarget.getBoundingClientRect()
        setPos({
          x: (e.clientX - rect.left - rect.width  / 2) * strength,
          y: (e.clientY - rect.top  - rect.height / 2) * strength,
        })
      }}
      onMouseLeave={() => setPos({ x: 0, y: 0 })}
      className={`relative overflow-hidden ${className}`}
      style={{
        ...base,
        ...style,
        padding: '10px 22px',
        fontSize: 13,
        fontFamily: "'Inter', sans-serif",
        letterSpacing: '-0.01em',
        cursor: 'pointer',
        transition: 'background 0.15s, color 0.15s, border-color 0.15s',
      }}
      {...(props as any)}
    >
      {children}
    </motion.button>
  )
}
