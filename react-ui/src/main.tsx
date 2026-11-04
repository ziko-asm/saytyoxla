import { StrictMode, Suspense, lazy } from 'react'
import { createRoot } from 'react-dom/client'
import './styles.css'
import App from './App.tsx'
import { ErrorBoundary } from './components/ErrorBoundary'
import { LANG, TOOLS_PATH } from './i18n'

// The generators and their texts load only on the Tools page: the home page stays light
const ToolsApp = lazy(() => import('./ToolsApp.tsx'))
const onToolsPage = window.location.pathname === TOOLS_PATH[LANG]

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      {onToolsPage ? <Suspense fallback={null}><ToolsApp /></Suspense> : <App />}
    </ErrorBoundary>
  </StrictMode>,
)
