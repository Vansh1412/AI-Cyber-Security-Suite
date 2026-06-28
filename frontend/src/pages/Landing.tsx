import { useNavigate, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  ShieldAlert, Zap, Brain, Globe, BarChart3,
  Code2, Github, ArrowRight, CheckCircle2, Cpu
} from 'lucide-react'

const features = [
  {
    icon: Zap,
    title: 'Real-time Detection',
    desc: 'Sub-20ms inference powered by a calibrated XGBoost ensemble with cascade thresholds.',
    color: 'text-primary-400',
    bg: 'bg-primary-500/10',
  },
  {
    icon: Globe,
    title: 'Threat Intelligence',
    desc: 'URL waterfall check: Local Blacklist → OpenPhish → VirusTotal before ML inference.',
    color: 'text-accent-400',
    bg: 'bg-accent-500/10',
  },
  {
    icon: Brain,
    title: 'Explainable AI',
    desc: 'SHAP-powered feature attributions tell you exactly why a URL was flagged.',
    color: 'text-purple-400',
    bg: 'bg-purple-500/10',
  },
  {
    icon: Code2,
    title: 'Browser Extension',
    desc: 'Real-time badge and detailed threat report on any web page, automatically.',
    color: 'text-orange-400',
    bg: 'bg-orange-500/10',
  },
  {
    icon: BarChart3,
    title: 'Analytics Dashboard',
    desc: 'Scan history, daily trends, class distribution, and latency analytics.',
    color: 'text-green-400',
    bg: 'bg-green-500/10',
  },
  {
    icon: Cpu,
    title: 'Enterprise API',
    desc: 'FastAPI backend with JWT auth, Redis caching, RBAC, and Prometheus metrics.',
    color: 'text-rose-400',
    bg: 'bg-rose-500/10',
  },
]

const stats = [
  { value: '2.7M', label: 'URLs Trained On' },
  { value: '95%',  label: 'Detection Accuracy' },
  { value: '15ms', label: 'Avg Inference' },
  { value: '63',   label: 'ML Features' },
]

const flowSteps = [
  { label: 'Browser / API', icon: Globe },
  { label: 'Browser Extension', icon: Code2 },
  { label: 'FastAPI Backend', icon: Zap },
  { label: 'Threat Intelligence', icon: ShieldAlert },
  { label: 'XGBoost + SHAP', icon: Brain },
  { label: 'Persistent Database', icon: BarChart3 },
]

export default function Landing() {
  const navigate = useNavigate()

  return (
    <div className="min-h-screen bg-dark-bg text-white overflow-hidden">
      {/* Navbar */}
      <nav className="fixed top-0 inset-x-0 z-50 border-b border-dark-border bg-dark-surface/70 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary-600 to-accent-500 flex items-center justify-center shadow-glow-primary">
              <ShieldAlert size={16} className="text-white" />
            </div>
            <span className="font-bold text-white tracking-tight">CyberSec AI</span>
          </div>
          <div className="flex items-center gap-3">
            <Link to="/login" className="btn-ghost text-sm">Sign In</Link>
            <button onClick={() => navigate('/register')} className="btn-primary text-sm py-2 px-4">
              Get Started <ArrowRight size={14} />
            </button>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="pt-32 pb-24 relative">
        {/* Cyber grid background */}
        <div className="absolute inset-0 cyber-overlay opacity-50" />
        {/* Radial glow */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-primary-600/10 blur-3xl rounded-full" />

        <div className="relative max-w-7xl mx-auto px-6 text-center">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            {/* Badge */}
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-primary-500/10 border border-primary-500/30 text-primary-400 text-sm font-medium mb-8">
              <span className="w-2 h-2 rounded-full bg-primary-400 animate-pulse" />
              AI-Powered Threat Detection Platform
            </div>

            {/* Headline */}
            <h1 className="text-5xl md:text-7xl font-black mb-6 tracking-tight text-balance">
              <span className="text-white">AI Cyber</span>{' '}
              <span className="gradient-text">Security Suite</span>
            </h1>

            <p className="text-lg md:text-xl text-gray-400 max-w-2xl mx-auto mb-10 leading-relaxed text-balance">
              AI-powered phishing detection, real-time threat intelligence,
              and explainable security analytics — built like a production product.
            </p>

            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <button
                onClick={() => navigate('/register')}
                className="btn-primary text-base px-7 py-3"
              >
                Get Started Free <ArrowRight size={16} />
              </button>
              <a
                href="https://github.com"
                target="_blank"
                rel="noreferrer"
                className="btn-secondary text-base px-7 py-3"
              >
                <Github size={16} /> View on GitHub
              </a>
            </div>

            {/* Trust badges */}
            <div className="flex items-center justify-center gap-6 mt-10 text-gray-500 text-sm">
              {['No credit card required', 'Open source', 'Enterprise API'].map(t => (
                <span key={t} className="flex items-center gap-1.5">
                  <CheckCircle2 size={13} className="text-safe-500" /> {t}
                </span>
              ))}
            </div>
          </motion.div>
        </div>
      </section>

      {/* Stats */}
      <section className="py-12 border-y border-dark-border bg-dark-surface/30">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat, i) => (
              <motion.div
                key={stat.label}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="text-center"
              >
                <p className="text-4xl font-black gradient-text mb-1">{stat.value}</p>
                <p className="text-gray-400 text-sm">{stat.label}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="py-24">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Enterprise-grade Security Stack
            </h2>
            <p className="text-gray-400 text-lg max-w-xl mx-auto">
              Every layer designed to match how real security platforms operate.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {features.map((feat, i) => (
              <motion.div
                key={feat.title}
                initial={{ opacity: 0, y: 24 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.08 }}
                className="glass-card p-6 hover:border-primary-600/40 transition-colors group"
              >
                <div className={`w-10 h-10 rounded-xl ${feat.bg} flex items-center justify-center mb-4 group-hover:scale-110 transition-transform`}>
                  <feat.icon size={20} className={feat.color} />
                </div>
                <h3 className="font-semibold text-white mb-2">{feat.title}</h3>
                <p className="text-gray-400 text-sm leading-relaxed">{feat.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Architecture flow */}
      <section className="py-24 bg-dark-surface/30 border-y border-dark-border">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              How It Works
            </h2>
            <p className="text-gray-400 max-w-lg mx-auto">
              Every URL passes through a multi-layer pipeline before a verdict is issued.
            </p>
          </div>
          <div className="flex flex-col md:flex-row items-center justify-center gap-0">
            {flowSteps.map((step, i) => (
              <div key={step.label} className="flex flex-col md:flex-row items-center">
                <motion.div
                  initial={{ opacity: 0, scale: 0.8 }}
                  whileInView={{ opacity: 1, scale: 1 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.1 }}
                  className="flex flex-col items-center gap-3"
                >
                  <div className="w-14 h-14 rounded-2xl bg-dark-card border border-dark-border flex items-center justify-center shadow-card-dark hover:border-primary-600/50 hover:shadow-glow-primary transition-all">
                    <step.icon size={22} className="text-primary-400" />
                  </div>
                  <span className="text-xs text-gray-400 text-center max-w-20 leading-tight">{step.label}</span>
                </motion.div>
                {i < flowSteps.length - 1 && (
                  <motion.div
                    initial={{ scaleX: 0 }}
                    whileInView={{ scaleX: 1 }}
                    viewport={{ once: true }}
                    transition={{ delay: i * 0.1 + 0.2 }}
                    className="hidden md:block w-12 h-px bg-gradient-to-r from-primary-600/50 to-accent-500/50 mx-2 mb-8"
                    style={{ originX: 0 }}
                  />
                )}
                {i < flowSteps.length - 1 && (
                  <div className="md:hidden w-px h-6 bg-gradient-to-b from-primary-600/50 to-accent-500/50 my-1" />
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Footer */}
      <section className="py-24">
        <div className="max-w-3xl mx-auto px-6 text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
          >
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-6">
              Ready to get started?
            </h2>
            <p className="text-gray-400 mb-8">
              Create your free account and start detecting threats instantly.
            </p>
            <button
              onClick={() => navigate('/register')}
              className="btn-primary text-base px-8 py-3.5"
            >
              Create Free Account <ArrowRight size={16} />
            </button>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-dark-border py-8">
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <ShieldAlert size={16} className="text-primary-500" />
            <span className="text-sm text-gray-500">© 2025 AI Cyber Security Suite</span>
          </div>
          <div className="flex items-center gap-6 text-sm text-gray-500">
            <a href="#" className="hover:text-white transition-colors">GitHub</a>
            <a href="#" className="hover:text-white transition-colors">Documentation</a>
            <a href="/v1/docs" className="hover:text-white transition-colors">API</a>
          </div>
        </div>
      </footer>
    </div>
  )
}
