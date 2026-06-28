/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // ── Brand Primary (Cyber Blue) ─────────────────────────────────────
        primary: {
          50:  '#eef7ff',
          100: '#d9ecff',
          200: '#bbdeff',
          300: '#8bc8ff',
          400: '#54aaff',
          500: '#2b8aff',
          600: '#0f6aff',
          700: '#0855eb',
          800: '#0d45be',
          900: '#113d95',
          950: '#0b2660',
        },
        // ── Accent (Cyber Teal / Mint) ────────────────────────────────────
        accent: {
          50:  '#effefb',
          100: '#c8fdf4',
          200: '#92fae8',
          300: '#55f0d9',
          400: '#24d9c4',
          500: '#0bbdaa',
          600: '#07978b',
          700: '#0a7870',
          800: '#0d5f5a',
          900: '#0f4e4a',
          950: '#022e2d',
        },
        // ── Success / Safe ────────────────────────────────────────────────
        safe: {
          500: '#22c55e',
          600: '#16a34a',
        },
        // ── Warning / Suspicious ──────────────────────────────────────────
        suspicious: {
          500: '#f59e0b',
          600: '#d97706',
        },
        // ── Danger / Threat ───────────────────────────────────────────────
        threat: {
          500: '#ef4444',
          600: '#dc2626',
        },
        // ── Dark Mode Surfaces ────────────────────────────────────────────
        dark: {
          bg:      '#07080d',
          surface: '#0d1117',
          card:    '#161b22',
          border:  '#21262d',
          hover:   '#1e242d',
          muted:   '#30363d',
        },
        // ── Light Mode Surfaces ───────────────────────────────────────────
        light: {
          bg:      '#f0f4f8',
          surface: '#ffffff',
          card:    '#f6f8fa',
          border:  '#d0d7de',
          hover:   '#eaeef2',
          muted:   '#6e7781',
        },
      },
      fontFamily: {
        sans:  ['Inter', 'system-ui', 'sans-serif'],
        mono:  ['JetBrains Mono', 'Fira Code', 'monospace'],
        display: ['Inter', 'sans-serif'],
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.875rem' }],
      },
      borderRadius: {
        'xl':  '0.75rem',
        '2xl': '1rem',
        '3xl': '1.5rem',
      },
      boxShadow: {
        'glow-primary': '0 0 20px rgba(43, 138, 255, 0.3)',
        'glow-accent':  '0 0 20px rgba(11, 189, 170, 0.3)',
        'glow-safe':    '0 0 20px rgba(34, 197, 94, 0.2)',
        'glow-threat':  '0 0 20px rgba(239, 68, 68, 0.2)',
        'card-dark':    '0 4px 24px rgba(0,0,0,0.4)',
        'card-light':   '0 2px 12px rgba(0,0,0,0.08)',
      },
      animation: {
        'fade-in':     'fadeIn 0.4s ease-out',
        'slide-up':    'slideUp 0.4s ease-out',
        'pulse-slow':  'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line':   'scanLine 2s linear infinite',
      },
      keyframes: {
        fadeIn: {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%':   { opacity: '0', transform: 'translateY(20px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        scanLine: {
          '0%':   { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
      backgroundImage: {
        'gradient-radial':   'radial-gradient(var(--tw-gradient-stops))',
        'cyber-grid':        "url(\"data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%230f6aff' fill-opacity='0.04'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E\")",
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
  ],
}
