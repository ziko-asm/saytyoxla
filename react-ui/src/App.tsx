import { useCallback, useEffect, useRef, useState } from 'react'
import { Header } from './components/Header'
import { ScanForm } from './components/ScanForm'
import { Loading } from './components/Loading'
import { ReportView } from './components/ReportView'
import { Guide } from './components/Guide'
import type { Report } from './types'
import { LANG, t } from './i18n'

export default function App() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [report, setReport] = useState<Report | null>(null)
  const [guideOpen, setGuideOpen] = useState(false)
  const [checked, setChecked] = useState('')
  const input = useRef<HTMLInputElement>(null)

  // fresh = true skips the server's 10-minute cache, so a fixed site shows its new result
  const scan = useCallback(async (target: string, fresh = false) => {
    const value = target.trim()
    setError('')
    if (!value) {
      setError(t.emptyUrl)
      input.current?.focus()
      return
    }
    setReport(null)
    setLoading(true)
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: value, lang: LANG, fresh }),
      })
      const data = await res.json()
      if (!res.ok) setError(typeof data.detail === 'string' ? data.detail : t.genericError)
      else {
        setReport(data)
        // The address bar now holds a link to this result: it can be shared, reloaded or opened in another language
        window.history.replaceState(null, '', `${window.location.pathname}?url=${encodeURIComponent(value)}`)
        setChecked(value)
      }
    } catch {
      setError(t.networkError)
    } finally {
      setLoading(false)
    }
  }, [])

  // ?url=example.az starts a scan straight away (ayfar's "Full report" link uses this)
  useEffect(() => {
    const q = new URLSearchParams(window.location.search).get('url')
    if (q) {
      setUrl(q)
      scan(q)
    }
  }, [scan])

  function again() {
    setReport(null)
    setUrl('')
    setChecked('')
    window.history.replaceState(null, '', window.location.pathname)
    window.scrollTo({ top: 0, behavior: 'smooth' })
    input.current?.focus()
  }

  const closeGuide = useCallback(() => setGuideOpen(false), [])

  return (
    <>
      <Header onHelp={() => setGuideOpen(true)} checked={checked} />
      <main id="main">
      <ScanForm
        ref={input}
        url={url}
        onUrlChange={setUrl}
        onSubmit={() => scan(url)}
        loading={loading}
        error={error}
        onHelp={() => setGuideOpen(true)}
      />
      {loading && <Loading />}
      {report && <ReportView report={report} onAgain={again} onRescan={() => scan(report.url, true)} />}
      </main>
      {guideOpen && (
        <Guide
          onClose={closeGuide}
          onStart={() => {
            setGuideOpen(false)
            window.scrollTo({ top: 0, behavior: 'smooth' })
            setTimeout(() => input.current?.focus(), 0)
          }}
        />
      )}
    </>
  )
}
