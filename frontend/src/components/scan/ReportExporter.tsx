/**
 * ReportExporter — Buttons: Copy JSON, Export PDF text, Download CSV.
 */
import { useState } from 'react'
import { Download, Copy, FileText, Check } from 'lucide-react'
import { toast } from 'react-hot-toast'
import type { ExplainResult, ScanResult } from '@/types'

interface Props {
  url: string
  prediction: string
  confidence: number
  threatScore: number
  latencyMs: number | null
  reasons?: Array<{ feature: string; impact: number; description?: string }>
}

export function ReportExporter({ url, prediction, confidence, threatScore, latencyMs, reasons }: Props) {
  const [copied, setCopied] = useState(false)

  const reportData = {
    url,
    prediction,
    confidence: (confidence * 100).toFixed(2) + '%',
    threat_score: threatScore,
    latency_ms: latencyMs,
    reasons: reasons?.map(r => ({
      feature: r.feature,
      impact: (Math.abs(r.impact) * 100).toFixed(1) + '%',
      description: r.description,
    })),
    timestamp: new Date().toISOString(),
    model: 'XGBoost v1.4 (Calibrated)',
  }

  const handleCopyJson = async () => {
    await navigator.clipboard.writeText(JSON.stringify(reportData, null, 2))
    setCopied(true)
    toast.success('Copied to clipboard!')
    setTimeout(() => setCopied(false), 2000)
  }

  const handleDownloadCsv = () => {
    const rows = [
      ['Field', 'Value'],
      ['URL', url],
      ['Prediction', prediction],
      ['Confidence', (confidence * 100).toFixed(2) + '%'],
      ['Threat Score', threatScore.toString()],
      ['Latency (ms)', latencyMs?.toFixed(1) ?? '—'],
      ['Timestamp', new Date().toISOString()],
    ]
    const csv = rows.map(r => r.map(c => `"${c}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
    a.download = `scan-report-${Date.now()}.csv`; a.click()
    toast.success('CSV downloaded!')
  }

  const handleExportText = () => {
    const text = `AI CYBER SECURITY SUITE — SCAN REPORT\n${'='.repeat(44)}\n\n` +
      `URL:          ${url}\n` +
      `Prediction:   ${prediction.toUpperCase()}\n` +
      `Confidence:   ${(confidence * 100).toFixed(2)}%\n` +
      `Threat Score: ${threatScore}/100\n` +
      `Latency:      ${latencyMs?.toFixed(1) ?? '—'}ms\n` +
      `Timestamp:    ${new Date().toISOString()}\n\n` +
      `TOP REASONS:\n` +
      (reasons?.map(r => `  • ${r.feature}: +${(Math.abs(r.impact) * 100).toFixed(1)}%`).join('\n') ?? 'N/A')
    const blob = new Blob([text], { type: 'text/plain' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob)
    a.download = `scan-report-${Date.now()}.txt`; a.click()
    toast.success('Report downloaded!')
  }

  return (
    <div className="flex flex-wrap gap-2">
      <button onClick={handleExportText} className="btn-secondary text-xs py-1.5 px-3">
        <FileText size={13} /> Export Report
      </button>
      <button onClick={handleCopyJson} className="btn-secondary text-xs py-1.5 px-3">
        {copied ? <Check size={13} className="text-safe-500" /> : <Copy size={13} />}
        {copied ? 'Copied!' : 'Copy JSON'}
      </button>
      <button onClick={handleDownloadCsv} className="btn-secondary text-xs py-1.5 px-3">
        <Download size={13} /> CSV
      </button>
    </div>
  )
}
