import { useCallback, useEffect, useRef, useState } from 'react'
import { Header } from './components/Header'
import { ScanForm } from './components/ScanForm'
import { Loading } from './components/Loading'
import { ReportView } from './components/ReportView'
import { Guide } from './components/Guide'
import type { Report } from './types'

export default function App() {
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [report, setReport] = useState<Report | null>(null)
  const [guideOpen, setGuideOpen] = useState(false)
  const input = useRef<HTMLInputElement>(null)

  const scan = useCallback(async (target: string) => {
    const value = target.trim()
    setError('')
    if (!value) {
      setError('Əvvəlcə saytınızın ünvanını yazın. Məsələn: meninsaytim.az')
      input.current?.focus()
      return
    }
    setReport(null)
    setLoading(true)
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: value }),
      })
      const data = await res.json()
      if (!res.ok) setError(data.detail || 'Xəta baş verdi. Bir az sonra yenidən cəhd edin.')
      else setReport(data)
    } catch {
      setError('Serverə qoşulmaq mümkün olmadı. İnternet bağlantınızı yoxlayın.')
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
    window.scrollTo({ top: 0, behavior: 'smooth' })
    input.current?.focus()
  }

  const closeGuide = useCallback(() => setGuideOpen(false), [])

  return (
    <>
      <Header onHelp={() => setGuideOpen(true)} />
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
      {report && <ReportView report={report} onAgain={again} />}
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
