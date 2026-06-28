/**
 * ThreatTimeline — Visual decision flow for a scan.
 * Shows which stages triggered in the pipeline.
 */
import { motion } from 'framer-motion'
import { Link2, ShieldOff, Globe, Brain, FileText, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { clsx } from 'clsx'

export type StageStatus = 'triggered' | 'passed' | 'pending' | 'skipped'

export interface TimelineStage {
  id: string
  label: string
  sublabel?: string
  status: StageStatus
  icon: React.ElementType
}

function buildStages(
  prediction: string,
  source?: string,
): TimelineStage[] {
  const isBlacklist = source === 'blacklist'
  const isOpenPhish = source === 'openphish'
  const isVT        = source === 'virustotal'
  const isMl        = !isBlacklist && !isOpenPhish && !isVT

  return [
    {
      id: 'input',
      label: 'URL Received',
      sublabel: 'Request parsed',
      status: 'passed',
      icon: Link2,
    },
    {
      id: 'blacklist',
      label: 'Local Blacklist',
      sublabel: isBlacklist ? 'Match found!' : 'No match',
      status: isBlacklist ? 'triggered' : 'passed',
      icon: ShieldOff,
    },
    {
      id: 'intel',
      label: 'Threat Intel',
      sublabel: isOpenPhish ? 'OpenPhish hit' : isVT ? 'VirusTotal hit' : 'No match',
      status: isOpenPhish || isVT ? 'triggered' : isBlacklist ? 'skipped' : 'passed',
      icon: Globe,
    },
    {
      id: 'ml',
      label: 'ML Inference',
      sublabel: isMl ? 'XGBoost + Calibration' : 'Bypassed',
      status: isMl ? 'triggered' : 'skipped',
      icon: Brain,
    },
    {
      id: 'decision',
      label: 'Verdict Issued',
      sublabel: prediction,
      status: 'triggered',
      icon: FileText,
    },
  ]
}

const STATUS_STYLES: Record<StageStatus, { dot: string; line: string; text: string }> = {
  triggered: { dot: 'bg-primary-600 shadow-glow-primary', line: 'bg-primary-600',  text: 'text-white' },
  passed:    { dot: 'bg-safe-500',                         line: 'bg-safe-500',      text: 'text-white' },
  skipped:   { dot: 'bg-dark-muted',                      line: 'bg-dark-muted',    text: 'text-gray-500' },
  pending:   { dot: 'bg-dark-border',                     line: 'bg-dark-border',   text: 'text-gray-600' },
}

interface Props {
  prediction: string
  source?: string
}

export function ThreatTimeline({ prediction, source }: Props) {
  const stages = buildStages(prediction, source)

  return (
    <div>
      <h4 className="text-sm font-semibold text-gray-300 mb-4">Detection Pipeline</h4>
      <div className="space-y-0">
        {stages.map((stage, i) => {
          const s = STATUS_STYLES[stage.status]
          const Icon = stage.icon
          return (
            <motion.div
              key={stage.id}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.1 }}
              className="flex gap-4"
            >
              {/* Spine */}
              <div className="flex flex-col items-center">
                <div className={clsx('w-3 h-3 rounded-full shrink-0 mt-0.5', s.dot)} />
                {i < stages.length - 1 && (
                  <div className={clsx('w-px flex-1 min-h-6', s.line, 'opacity-40 my-1')} />
                )}
              </div>
              {/* Content */}
              <div className="pb-4 flex items-center gap-3">
                <div className={clsx('w-7 h-7 rounded-lg bg-dark-card border border-dark-border flex items-center justify-center', {
                  'border-primary-600/50': stage.status === 'triggered',
                })}>
                  <Icon size={14} className={stage.status === 'triggered' ? 'text-primary-400' : 'text-gray-500'} />
                </div>
                <div>
                  <p className={clsx('text-sm font-medium', s.text)}>{stage.label}</p>
                  <p className="text-xs text-gray-500 capitalize">{stage.sublabel}</p>
                </div>
                {stage.status === 'triggered' && (
                  <CheckCircle2 size={14} className="text-primary-400 ml-2" />
                )}
                {stage.status === 'skipped' && (
                  <XCircle size={14} className="text-gray-600 ml-2" />
                )}
              </div>
            </motion.div>
          )
        })}
      </div>
    </div>
  )
}
