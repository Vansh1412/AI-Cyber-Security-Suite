import { useLocation } from 'react-router-dom'
import { Bell, Sun, Moon, Search } from 'lucide-react'
import { useTheme } from '@/contexts/ThemeContext'

const pageTitles: Record<string, string> = {
  '/dashboard':  'Dashboard',
  '/scan':       'Scan URL',
  '/history':    'Scan History',
  '/analytics':  'Analytics',
  '/profile':    'Profile',
  '/settings':   'Settings',
  '/admin':      'Admin Panel',
}

export function Topbar() {
  const { theme, toggleTheme } = useTheme()
  const { pathname } = useLocation()
  const title = pageTitles[pathname] ?? 'AI Cyber Security Suite'

  return (
    <header className="fixed top-0 right-0 h-16 bg-white/80 border-b border-light-border z-20
                       flex items-center px-6 gap-4
                       backdrop-blur-md
                       dark:bg-dark-surface/80 dark:border-dark-border"
      style={{ left: 260 }}
    >
      {/* Page title */}
      <h1 className="text-base font-semibold text-gray-900 dark:text-white flex-1">
        {title}
      </h1>

      {/* Search */}
      <button className="flex items-center gap-2 px-3 py-1.5 bg-light-card border border-light-border rounded-lg text-sm text-gray-400 hover:border-primary-600/50 transition-colors min-w-48 max-w-64
                         dark:bg-dark-card dark:border-dark-border dark:text-gray-500">
        <Search size={14} />
        <span>Search...</span>
        <kbd className="ml-auto text-xs text-gray-600 font-mono">⌘K</kbd>
      </button>

      {/* Theme toggle */}
      <button
        onClick={toggleTheme}
        className="p-2 rounded-lg text-gray-600 hover:text-gray-900 hover:bg-light-hover transition-colors
                   dark:text-gray-400 dark:hover:text-white dark:hover:bg-dark-hover"
        title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
      >
        {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
      </button>

      {/* Notifications */}
      <button className="relative p-2 rounded-lg text-gray-600 hover:text-gray-900 hover:bg-light-hover transition-colors dark:text-gray-400 dark:hover:text-white dark:hover:bg-dark-hover">
        <Bell size={18} />
        <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-primary-500" />
      </button>
    </header>
  )
}
