import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'node:path'

// `python3 make_pages.py && npm run build` writes the site into ../web/react, which FastAPI serves (assets under /react/).
// In development, /api requests go to the live SaytYoxla service, so there is no CORS problem.
export default defineConfig({
  plugins: [react()],
  base: '/react/',
  // Preact runs the same components in a fraction of React's size; the page is one form and a report
  resolve: {
    alias: {
      'react-dom/client': 'preact/compat/client',
      'react-dom': 'preact/compat',
      'react/jsx-runtime': 'preact/jsx-runtime',
      'react/jsx-dev-runtime': 'preact/jsx-runtime',
      react: 'preact/compat',
    },
  },
  build: {
    outDir: '../web/react',
    emptyOutDir: true,
    // one page per language; en/ and ru/ are generated from index.html by make_pages.py
    rollupOptions: {
      input: {
        az: resolve(import.meta.dirname, 'index.html'),
        en: resolve(import.meta.dirname, 'en/index.html'),
        ru: resolve(import.meta.dirname, 'ru/index.html'),
      },
    },
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
