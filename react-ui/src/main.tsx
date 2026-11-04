import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './styles.css'
import App from './App.tsx'
import ToolsApp from './ToolsApp.tsx'
import { ErrorBoundary } from './components/ErrorBoundary'
import { LANG, TOOLS_PATH } from './i18n'

const onToolsPage = window.location.pathname === TOOLS_PATH[LANG]

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      {onToolsPage ? <ToolsApp /> : <App />}
    </ErrorBoundary>
  </StrictMode>,
)
