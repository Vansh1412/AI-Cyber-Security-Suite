import { NavLink, useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  LayoutDashboard, Search, History, BarChart3, User,
  Settings, Shield, LogOut, ShieldAlert, ChevronRight,
} from 'lucide-react'
import { useAuth } from '@/contexts/AuthContext'
import { clsx } from 'clsx'

const navItems = [
  { to: '/dashboard',  icon: LayoutDashboard, label: 'Dashboard'  },
  { to: '/scan',       icon: Search,           label: 'Scan URL'   },
  { to: '/history',    icon: History,          label: 'History'    },
  { to: '/analytics',  icon: BarChart3,        label: 'Analytics'  },
]

const bottomItems = [
  { to: '/profile',    icon: User,             label: 'Profile'    },
  { to: '/settings',   icon: Settings,         label: 'Settings'   },
]

export function Sidebar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <aside className="fixed left-0 top-0 h-screen w-[260px] bg-white border-r border-light-border flex flex-col z-30
                      dark:bg-dark-surface dark:border-dark-border">

      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-dark-border">
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-primary-600 to-accent-500 flex items-center justify-center shadow-glow-primary">
          <ShieldAlert size={18} className="text-white" />
        </div>
        <div>
          <p className="text-sm font-bold text-white tracking-tight">CyberSec AI</p>
          <p className="text-2xs text-gray-500">Threat Intelligence</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3 space-y-0.5 overflow-y-auto">
        <p className="text-2xs text-gray-500 font-semibold uppercase tracking-widest px-3 mb-2 mt-1">
          Main Menu
        </p>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              clsx('nav-link', isActive && 'active')
            }
          >
            {({ isActive }) => (
              <>
                <item.icon size={17} className={isActive ? 'text-primary-400' : ''} />
                <span className="flex-1">{item.label}</span>
                {isActive && (
                  <motion.span
                    layoutId="sidebar-indicator"
                    className="w-1.5 h-1.5 rounded-full bg-primary-400"
                  />
                )}
              </>
            )}
          </NavLink>
        ))}

        {/* Admin section */}
        {user?.role === 'admin' && (
          <>
            <p className="text-2xs text-gray-500 font-semibold uppercase tracking-widest px-3 mb-2 mt-4">
              Admin
            </p>
            <NavLink
              to="/admin"
              className={({ isActive }) => clsx('nav-link', isActive && 'active')}
            >
              {({ isActive }) => (
                <>
                  <Shield size={17} className={isActive ? 'text-primary-400' : ''} />
                  <span className="flex-1">Admin Panel</span>
                  {isActive && (
                    <motion.span
                      layoutId="sidebar-indicator"
                      className="w-1.5 h-1.5 rounded-full bg-primary-400"
                    />
                  )}
                </>
              )}
            </NavLink>
          </>
        )}

        <p className="text-2xs text-gray-500 font-semibold uppercase tracking-widest px-3 mb-2 mt-4">
          Account
        </p>
        {bottomItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => clsx('nav-link', isActive && 'active')}
          >
            {({ isActive }) => (
              <>
                <item.icon size={17} className={isActive ? 'text-primary-400' : ''} />
                <span className="flex-1">{item.label}</span>
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* User Info + Logout */}
      <div className="p-3 border-t border-dark-border">
        <div className="flex items-center gap-3 px-3 py-2.5 rounded-xl">
          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary-600 to-accent-500 flex items-center justify-center text-xs font-bold text-white shrink-0">
            {user?.email?.[0]?.toUpperCase() ?? 'U'}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-white truncate">{user?.email}</p>
            <p className="text-2xs text-gray-500 capitalize">{user?.role}</p>
          </div>
          <button
            onClick={handleLogout}
            className="p-1.5 rounded-lg text-gray-500 hover:text-threat-500 hover:bg-threat-500/10 transition-colors"
            title="Logout"
          >
            <LogOut size={15} />
          </button>
        </div>
      </div>
    </aside>
  )
}
