import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// `npm run build` writes the site into ../web/react, which FastAPI serves (assets under /react/).
// In development, /api requests go to the live SaytYoxla service, so there is no CORS problem.
export default defineConfig({
  plugins: [react()],
  base: '/react/',
  build: {
    outDir: '../web/react',
    emptyOutDir: true,
  },
  server: {
    proxy: {
      '/api': {
        target: 'https://saytyoxla.vercel.app',
        changeOrigin: true,
      },
    },
  },
})
