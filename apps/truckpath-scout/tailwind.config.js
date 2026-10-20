/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Field-grade high-contrast palette
        ink: '#0f1419',
        panel: '#1a2129',
        edge: '#2c3742',
        hivis: '#ffb400',
        safety: '#ff5a1f',
        go: '#22c55e',
        warn: '#eab308',
        danger: '#ef4444',
        critical: '#b91c1c',
      },
      minHeight: {
        touch: '48px',
      },
      minWidth: {
        touch: '48px',
      },
    },
  },
  plugins: [],
};
