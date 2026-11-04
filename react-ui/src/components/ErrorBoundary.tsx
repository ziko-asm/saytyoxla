import { Component } from 'react'
import type { ReactNode } from 'react'
import { t } from '../i18n'

// Without this, an error while rendering removes the whole app and leaves an empty page
export class ErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  render() {
    if (!this.state.failed) return this.props.children
    return (
      <main id="main" className="hero">
        <div className="wrap narrow">
          <p className="form-error" role="alert">{t.genericError}</p>
          <p className="form-hint"><a href={window.location.pathname}>{t.reload}</a></p>
        </div>
      </main>
    )
  }
}
