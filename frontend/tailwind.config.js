/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Inter"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
      },
      colors: {
        background: '#0B0F19',
        panel: '#151C2C',
        border: '#2A3655',
        primary: '#3B82F6',
        low: '#10B981',
        medium: '#F59E0B',
        high: '#EF4444',
      },
      boxShadow: {
        'glow-high': '0 0 14px rgba(239, 68, 68, 0.5)',
        'glow-medium': '0 0 14px rgba(245, 158, 11, 0.4)',
        'glow-primary': '0 0 14px rgba(59, 130, 246, 0.4)',
      },
      animation: {
        'pulse-fast': 'pulse 1.2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'ripple': 'ripple 1.5s ease-out infinite',
      },
      keyframes: {
        ripple: {
          '0%': { transform: 'scale(0.8)', opacity: '1' },
          '100%': { transform: 'scale(2.2)', opacity: '0' },
        }
      }
    },
  },
  plugins: [],
}
