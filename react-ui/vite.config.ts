import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In development, requests to /api go to the live SaytYoxla service.
// The browser only talks to localhost, so there is no cross-site (CORS) problem.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'https://saytyoxla.vercel.app',
        changeOrigin: true,
      },
    },
  },
})
