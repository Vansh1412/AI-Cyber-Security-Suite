/**
 * ShapExplanation — Renders SHAP feature attributions as human-readable reason cards.
 */
import { motion } from 'framer-motion'
import { TrendingUp, TrendingDown, Info } from 'lucide-react'
import { clsx } from 'clsx'
import type { ShapReason } from '@/types'

interface Props {
  reasons: ShapReason[]
  prediction: string
}

const FEATURE_LABELS: Record<string, string> = {
  brand_in_subdomain: 'Brand impersonation in subdomain',
  url_length:         'Abnormally long URL',
  url_entropy:        'High character entropy (obfuscation)',
  https_flag:         'Missing HTTPS',
  num_dots:           'Excessive dots in URL',
  has_ip:             'Raw IP address instead of domain',
  kw_login:           '"login" keyword detected',
  kw_secure:          '"secure" keyword (social engineering)',
  kw_verify:          '"verify" keyword detected',
  kw_paypal:          '"paypal" brand keyword',
  num_subdomains:     'Excessive subdomain nesting',
  suspicious_tld:     'Suspicious TLD (.xyz, .tk, .pw)',
  path_length:        'Unusually long URL path',
  digit_ratio:        'High proportion of digits',
  subdomain_count:    'Multiple subdomain layers',
}

function humanLabel(feature: string): string {
  return FEATURE_LABELS[feature] ?? feature.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

export function ShapExplanation({ reasons, prediction }: Props) {
  const maxImpact = Math.max(...reasons.map(r => Math.abs(r.impact)), 0.01)

  // Only show reasons that contributed positively to the threat (impact > 0) for malicious,
  // or negatively (impact < 0 means it contributed to "legitimate") for safe classification.
  const sorted = [...reasons].sort((a, b) => Math.abs(b.impact) - Math.abs(a.impact)).slice(0, 6)

  return (
    <div>
      <div className="flex items-center gap-2 mb-4">
        <Info size={14} className="text-primary-400" />
        <h4 className="text-sm font-semibold text-gray-300">Why was this detected?</h4>
      </div>
      <div className="space-y-3">
        {sorted.map((r, i) => {
          const absImpact = Math.abs(r.impact)
          const pct = Math.round((absImpact / maxImpact) * 100)
          const isPositiveRisk = r.impact > 0 // Pushes toward threat
          const isSafe = prediction === 'legitimate'

          return (
            <motion.div
              key={r.feature}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.08 }}
              className="space-y-1.5"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {isPositiveRisk && !isSafe
                    ? <TrendingUp size={13} className="text-threat-500 shrink-0" />
                    : <TrendingDown size={13} className="text-safe-500 shrink-0" />
                  }
                  <span className="text-sm text-gray-200">{humanLabel(r.feature)}</span>
                </div>
                <span className={clsx('text-xs font-semibold font-mono shrink-0 ml-2', {
                  'text-threat-500': isPositiveRisk && !isSafe,
                  'text-safe-500':   !isPositiveRisk || isSafe,
                })}>
                  {isPositiveRisk && !isSafe ? '+' : '-'}{(absImpact * 100).toFixed(1)}%
                </span>
              </div>
              {/* Bar */}
              <div className="h-1.5 bg-dark-muted rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${pct}%` }}
                  transition={{ duration: 0.6, delay: i * 0.08, ease: 'easeOut' }}
                  className={clsx('h-full rounded-full', {
                    'bg-threat-500': isPositiveRisk && !isSafe,
                    'bg-safe-500':   !isPositiveRisk || isSafe,
                  })}
                />
              </div>
              {r.description && (
                <p className="text-xs text-gray-500 pl-5">{r.description}</p>
              )}
            </motion.div>
          )
        })}
      </div>
    </div>
  )
}
