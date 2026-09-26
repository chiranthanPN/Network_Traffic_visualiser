/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#0B0F19',
        panel: '#151C2C',
        border: '#2A3655',
        primary: '#3B82F6',
        low: '#10B981',
        medium: '#F59E0B',
        high: '#EF4444',
      }
    },
  },
  plugins: [],
}
