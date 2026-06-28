/**
 * ThreatGauge — Circular SVG risk score gauge.
 * Score 0–100. Color: green (<33), yellow (33–66), red (>66).
 */
import { motion } from 'framer-motion'
import { clsx } from 'clsx'

interface Props {
  score: number
  size?: number
  strokeWidth?: number
}

export function ThreatGauge({ score, size = 140, strokeWidth = 10 }: Props) {
  const r = (size - strokeWidth) / 2
  const circ = 2 * Math.PI * r
  const offset = circ - (score / 100) * circ

  const color =
    score < 33 ? '#22c55e' :
    score < 66 ? '#f59e0b' :
                 '#ef4444'

  const label =
    score < 33 ? 'Low Risk' :
    score < 66 ? 'Suspicious' :
                 'High Risk'

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        {/* Track */}
        <svg width={size} height={size} className="rotate-[-90deg]">
          <circle
            cx={size / 2} cy={size / 2} r={r}
            fill="none" stroke="#21262d" strokeWidth={strokeWidth}
          />
          <motion.circle
            cx={size / 2} cy={size / 2} r={r}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circ}
            initial={{ strokeDashoffset: circ }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 1, ease: 'easeOut' }}
            style={{ filter: `drop-shadow(0 0 8px ${color}60)` }}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <motion.span
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
            className="text-3xl font-black"
            style={{ color }}
          >
            {score}
          </motion.span>
          <span className="text-xs text-gray-500 font-medium">Risk Score</span>
        </div>
      </div>
      <span className={clsx('text-xs font-semibold px-2 py-0.5 rounded-full', {
        'bg-safe-500/15 text-safe-500': score < 33,
        'bg-suspicious-500/15 text-suspicious-500': score >= 33 && score < 66,
        'bg-threat-500/15 text-threat-500': score >= 66,
      })}>
        {label}
      </span>
    </div>
  )
}
