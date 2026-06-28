import { useAuth } from '@/contexts/AuthContext'
import { motion } from 'framer-motion'
import { Mail, Shield, Calendar } from 'lucide-react'

export default function Profile() {
  const { user } = useAuth()
  return (
    <div className="max-w-xl space-y-5">
      <h2 className="text-2xl font-bold text-white">Profile</h2>
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-6">
        <div className="flex items-center gap-4 mb-6">
          <div className="w-16 h-16 rounded-full bg-gradient-to-br from-primary-600 to-accent-500 flex items-center justify-center text-2xl font-bold text-white">
            {user?.email?.[0]?.toUpperCase() ?? 'U'}
          </div>
          <div>
            <p className="text-xl font-bold text-white">{user?.email?.split('@')[0]}</p>
            <p className="text-gray-400 text-sm">{user?.email}</p>
          </div>
        </div>
        <div className="space-y-3">
          <div className="flex items-center gap-3 p-3 rounded-xl bg-dark-bg/50">
            <Mail size={16} className="text-gray-500" />
            <div>
              <p className="text-xs text-gray-500">Email</p>
              <p className="text-sm text-white">{user?.email}</p>
            </div>
          </div>
          <div className="flex items-center gap-3 p-3 rounded-xl bg-dark-bg/50">
            <Shield size={16} className="text-gray-500" />
            <div>
              <p className="text-xs text-gray-500">Role</p>
              <p className="text-sm text-white capitalize">{user?.role}</p>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  )
}
