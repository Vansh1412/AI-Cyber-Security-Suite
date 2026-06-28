import { motion } from 'framer-motion'
import { useTheme } from '@/contexts/ThemeContext'
import { Sun, Moon } from 'lucide-react'

export default function Settings() {
  const { theme, toggleTheme } = useTheme()
  return (
    <div className="max-w-xl space-y-5">
      <h2 className="text-2xl font-bold text-white">Settings</h2>
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-6">
        <h3 className="font-semibold text-white mb-4">Appearance</h3>
        <div className="flex items-center justify-between p-4 rounded-xl bg-dark-bg/50">
          <div className="flex items-center gap-3">
            {theme === 'dark' ? <Moon size={18} className="text-primary-400" /> : <Sun size={18} className="text-suspicious-400" />}
            <div>
              <p className="text-sm font-medium text-white">{theme === 'dark' ? 'Dark Mode' : 'Light Mode'}</p>
              <p className="text-xs text-gray-500">Toggle application theme</p>
            </div>
          </div>
          <button
            onClick={toggleTheme}
            className={`relative w-12 h-6 rounded-full transition-colors ${theme === 'dark' ? 'bg-primary-600' : 'bg-gray-300'}`}
          >
            <span className={`absolute top-0.5 w-5 h-5 rounded-full bg-white shadow transition-all ${theme === 'dark' ? 'left-6' : 'left-0.5'}`} />
          </button>
        </div>
      </motion.div>
    </div>
  )
}
