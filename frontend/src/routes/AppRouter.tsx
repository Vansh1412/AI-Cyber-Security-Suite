import { lazy, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { ProtectedRoute, AdminRoute } from './ProtectedRoute'

// Lazy load pages for code splitting
const Landing   = lazy(() => import('@/pages/Landing'))
const Login     = lazy(() => import('@/pages/Login'))
const Register  = lazy(() => import('@/pages/Register'))
const Dashboard             = lazy(() => import('@/pages/Dashboard'))
const Scan                  = lazy(() => import('@/pages/Scan'))
const History               = lazy(() => import('@/pages/History'))
const Analytics             = lazy(() => import('@/pages/Analytics'))
const Profile               = lazy(() => import('@/pages/Profile'))
const Settings              = lazy(() => import('@/pages/Settings'))
const Admin                 = lazy(() => import('@/pages/Admin'))
const ThreatInvestigation   = lazy(() => import('@/pages/ThreatInvestigation'))
const AlertConsole           = lazy(() => import('@/pages/soc/AlertConsole'))
const IncidentManager       = lazy(() => import('@/pages/soc/IncidentManager'))
const MonitoringConsole     = lazy(() => import('@/pages/soc/MonitoringConsole'))

function PageLoader() {
  return (
    <div className="min-h-[60vh] flex items-center justify-center">
      <div className="w-8 h-8 rounded-full border-2 border-primary-600 border-t-transparent animate-spin" />
    </div>
  )
}

function SOCPhasePlaceholder({
  title,
  phase,
  description,
}: {
  title: string
  phase: string
  description: string
}) {
  return (
    <div className="p-8 max-w-4xl mx-auto space-y-6">
      <div className="bg-white dark:bg-dark-surface border border-light-border dark:border-dark-border rounded-2xl p-6 shadow-sm">
        <div className="flex items-center justify-between pb-4 border-b border-light-border dark:border-dark-border">
          <div>
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">{title}</h2>
            <p className="text-sm text-gray-500 mt-1">{description}</p>
          </div>
          <span className="px-3 py-1 rounded-full text-xs font-semibold bg-primary-500/10 text-primary-400 border border-primary-500/20">
            {phase}
          </span>
        </div>
        <div className="py-8 text-center text-gray-500 text-sm">
          Phase 6A foundation initialized. Complete operational UI scheduled for rollout in {phase}.
        </div>
      </div>
    </div>
  )
}

export function AppRouter() {
  return (
    <Suspense fallback={<PageLoader />}>
      <Routes>
        {/* Public */}
        <Route path="/"         element={<Landing />}  />
        <Route path="/login"    element={<Login />}    />
        <Route path="/register" element={<Register />} />

        {/* Protected (requires auth) */}
        <Route element={<ProtectedRoute />}>
          <Route path="/dashboard"    element={<Dashboard />}           />
          <Route path="/scan"         element={<Scan />}                />
          <Route path="/history"      element={<History />}             />
          <Route path="/analytics"    element={<Analytics />}           />
          <Route path="/investigate"  element={<ThreatInvestigation />} />
          <Route path="/profile"      element={<Profile />}             />
          <Route path="/settings"     element={<Settings />}            />

          {/* SOC operational routing */}
          <Route path="/soc/alerts" element={<AlertConsole />} />
          <Route path="/soc/incidents" element={<IncidentManager />} />
          <Route path="/soc/monitoring" element={<MonitoringConsole />} />
          <Route
            path="/soc/containment"
            element={
              <SOCPhasePlaceholder
                title="Threat Containment & SOAR"
                phase="Phase 6D"
                description="Automated containment actions, SOAR playbooks, and Rule 0 allowlist fencing."
              />
            }
          />
          <Route
            path="/soc/notifications"
            element={
              <SOCPhasePlaceholder
                title="Notifications & Webhooks"
                phase="Phase 6D"
                description="In-app notification center and encrypted webhook delivery management."
              />
            }
          />

          {/* Admin only */}
          <Route element={<AdminRoute />}>
            <Route path="/admin" element={<Admin />} />
          </Route>
        </Route>

        {/* Catch all */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  )
}
