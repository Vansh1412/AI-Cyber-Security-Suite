import { lazy, Suspense } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { ProtectedRoute, AdminRoute } from './ProtectedRoute'

// Lazy load pages for code splitting
const Landing   = lazy(() => import('@/pages/Landing'))
const Login     = lazy(() => import('@/pages/Login'))
const Register  = lazy(() => import('@/pages/Register'))
const Dashboard = lazy(() => import('@/pages/Dashboard'))
const Scan      = lazy(() => import('@/pages/Scan'))
const History   = lazy(() => import('@/pages/History'))
const Analytics = lazy(() => import('@/pages/Analytics'))
const Profile   = lazy(() => import('@/pages/Profile'))
const Settings  = lazy(() => import('@/pages/Settings'))
const Admin     = lazy(() => import('@/pages/Admin'))

function PageLoader() {
  return (
    <div className="min-h-[60vh] flex items-center justify-center">
      <div className="w-8 h-8 rounded-full border-2 border-primary-600 border-t-transparent animate-spin" />
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
          <Route path="/dashboard"  element={<Dashboard />} />
          <Route path="/scan"       element={<Scan />}      />
          <Route path="/history"    element={<History />}   />
          <Route path="/analytics"  element={<Analytics />} />
          <Route path="/profile"    element={<Profile />}   />
          <Route path="/settings"   element={<Settings />}  />
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
