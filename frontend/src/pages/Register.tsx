import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { motion } from 'framer-motion'
import { ShieldAlert, Mail, Lock, Eye, EyeOff, ArrowRight, Loader2, Check } from 'lucide-react'
import { toast } from 'react-hot-toast'
import { useAuth } from '@/contexts/AuthContext'
import { clsx } from 'clsx'

const registerSchema = z.object({
  email:    z.string().email('Invalid email address'),
  password: z.string()
    .min(8, 'Minimum 8 characters')
    .regex(/[A-Z]/, 'Include at least one uppercase letter')
    .regex(/[0-9]/, 'Include at least one number'),
  confirm:  z.string(),
}).refine(d => d.password === d.confirm, {
  message: 'Passwords do not match',
  path: ['confirm'],
})
type RegisterForm = z.infer<typeof registerSchema>

function PasswordStrength({ pw }: { pw: string }) {
  const checks = [
    { label: '8+ characters', ok: pw.length >= 8 },
    { label: 'Uppercase letter', ok: /[A-Z]/.test(pw) },
    { label: 'Number', ok: /[0-9]/.test(pw) },
  ]
  const score = checks.filter(c => c.ok).length
  const colors = ['bg-threat-500', 'bg-suspicious-500', 'bg-safe-500']

  return (
    <div className="mt-2 space-y-2">
      <div className="flex gap-1">
        {[0,1,2].map(i => (
          <div key={i} className={clsx('h-1 flex-1 rounded-full transition-colors', i < score ? colors[score-1] : 'bg-dark-muted')} />
        ))}
      </div>
      <div className="flex gap-3">
        {checks.map(c => (
          <span key={c.label} className={clsx('flex items-center gap-1 text-2xs', c.ok ? 'text-safe-500' : 'text-gray-500')}>
            <Check size={10} />
            {c.label}
          </span>
        ))}
      </div>
    </div>
  )
}

export default function Register() {
  const { register: authRegister } = useAuth()
  const navigate = useNavigate()
  const [showPw, setShowPw] = useState(false)

  const { register, handleSubmit, watch, formState: { errors, isSubmitting } } = useForm<RegisterForm>({
    resolver: zodResolver(registerSchema),
  })

  const password = watch('password', '')

  const onSubmit = async (data: RegisterForm) => {
    try {
      await authRegister(data.email, data.password)
      toast.success('Account created! Welcome aboard.')
      navigate('/dashboard')
    } catch (err: any) {
      const msg = err?.response?.data?.detail ?? 'Registration failed.'
      toast.error(msg)
    }
  }

  return (
    <div className="min-h-screen bg-dark-bg flex items-center justify-center p-8">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md"
      >
        <div className="flex items-center gap-2 mb-8">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-primary-600 to-accent-500 flex items-center justify-center shadow-glow-primary">
            <ShieldAlert size={18} className="text-white" />
          </div>
          <span className="text-lg font-bold">CyberSec AI</span>
        </div>

        <div className="mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">Create account</h2>
          <p className="text-gray-400">Start detecting threats in seconds.</p>
        </div>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
          {/* Email */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Email</label>
            <div className="relative">
              <Mail size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" />
              <input {...register('email')} type="email" placeholder="you@example.com" className="input-field pl-11" />
            </div>
            {errors.email && <p className="mt-1.5 text-xs text-threat-500">{errors.email.message}</p>}
          </div>

          {/* Password */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Password</label>
            <div className="relative">
              <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" />
              <input
                {...register('password')}
                type={showPw ? 'text' : 'password'}
                placeholder="••••••••"
                className="input-field pl-11 pr-11"
              />
              <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300">
                {showPw ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            {password && <PasswordStrength pw={password} />}
            {errors.password && <p className="mt-1.5 text-xs text-threat-500">{errors.password.message}</p>}
          </div>

          {/* Confirm */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Confirm Password</label>
            <div className="relative">
              <Lock size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-500" />
              <input {...register('confirm')} type="password" placeholder="••••••••" className="input-field pl-11" />
            </div>
            {errors.confirm && <p className="mt-1.5 text-xs text-threat-500">{errors.confirm.message}</p>}
          </div>

          <button type="submit" disabled={isSubmitting} className="btn-primary w-full justify-center py-3">
            {isSubmitting ? <Loader2 size={16} className="animate-spin" /> : null}
            {isSubmitting ? 'Creating...' : 'Create Account'}
            {!isSubmitting && <ArrowRight size={16} />}
          </button>
        </form>

        <p className="mt-8 text-center text-sm text-gray-500">
          Already have an account?{' '}
          <Link to="/login" className="text-primary-400 hover:text-primary-300 font-medium">Sign in</Link>
        </p>
      </motion.div>
    </div>
  )
}
