import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router'
import { Activity, Check } from 'lucide-react'

const steps = [
  { id: 1, label: 'Connecting to GitHub...', duration: 800 },
  { id: 2, label: 'Connecting to PagerDuty...', duration: 700 },
  { id: 3, label: 'Connecting to Datadog...', duration: 900 },
  { id: 4, label: 'Indexing repositories...', duration: 1200 },
  { id: 5, label: 'Syncing incidents (last 90 days)...', duration: 1100 },
  { id: 6, label: 'Training anomaly detection models...', duration: 1400 },
  { id: 7, label: 'Building service topology...', duration: 800 },
  { id: 8, label: 'ORACLE is ready.', duration: 500 },
]

export default function OracleInitialization() {
  const navigate = useNavigate()
  const [completed, setCompleted] = useState<number[]>([])
  const [current, setCurrent] = useState(0)
  const [done, setDone] = useState(false)

  useEffect(() => {
    let idx = 0
    const run = () => {
      if (idx >= steps.length) {
        setDone(true)
        return
      }
      setCurrent(idx)
      setTimeout(() => {
        setCompleted(c => [...c, steps[idx].id])
        idx++
        run()
      }, steps[idx].duration)
    }
    run()
  }, [])

  return (
    <div className="text-center">
      <div className="relative w-16 h-16 mx-auto mb-8">
        <div className="w-16 h-16 rounded-full border-2 border-oaccent/20 flex items-center justify-center">
          <Activity size={24} className={`text-oaccent ${done ? '' : 'animate-pulse'}`} />
        </div>
        {!done && (
          <div className="absolute inset-0 rounded-full border-2 border-oaccent border-t-transparent animate-spin" />
        )}
        {done && (
          <div className="absolute inset-0 rounded-full bg-oaccent/10 border-2 border-oaccent flex items-center justify-center">
            <Check size={20} className="text-oaccent" />
          </div>
        )}
      </div>

      <h1 className="text-xl font-semibold text-ot1 mb-2">
        {done ? 'ORACLE is ready' : 'Initializing ORACLE'}
      </h1>
      <p className="text-sm text-ot2 mb-8">
        {done
          ? 'Your workspace is configured and ORACLE is monitoring your systems.'
          : 'Connecting integrations and indexing your engineering data…'}
      </p>

      <div className="text-left space-y-2.5 mb-8 max-w-sm mx-auto">
        {steps.map((s, i) => {
          const isDone = completed.includes(s.id)
          const isActive = current === i && !isDone
          return (
            <div key={s.id} className={`flex items-center gap-3 text-sm transition-colors ${
              isDone ? 'text-ot2' : isActive ? 'text-ot1' : 'text-ot3'
            }`}>
              <div className={`w-4 h-4 rounded-full flex items-center justify-center flex-shrink-0 ${
                isDone ? 'bg-oaccent' : isActive ? 'border-2 border-oaccent animate-pulse' : 'border border-oline'
              }`}>
                {isDone && <Check size={9} className="text-white" />}
              </div>
              {s.label}
            </div>
          )
        })}
      </div>

      {done && (
        <button
          onClick={() => navigate('/app')}
          className="px-6 py-2.5 rounded-lg bg-oaccent text-white text-sm font-medium hover:bg-indigo-500 transition-colors">
          Launch Command Center →
        </button>
      )}
    </div>
  )
}
