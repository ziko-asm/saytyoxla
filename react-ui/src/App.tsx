import { useState } from 'react'
import './App.css'

// The shape of the JSON that SaytYoxla's /api/scan returns
type Finding = {
  id: string
  title: string
  status: 'ok' | 'warn' | 'fail' | 'info'
  fix: string
}

type Report = {
  final_url: string
  score: number
  grade: string
  summary: string
  findings: Finding[]
}

function App() {
  // 4 pieces of state: what the user typed, waiting, an error, and the result
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [report, setReport] = useState<Report | null>(null)

  async function check(e: React.FormEvent) {
    e.preventDefault() // stop the browser reloading the page
    if (!url.trim()) return
    setLoading(true)
    setError('')
    setReport(null)
    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || 'Yoxlamaq alınmadı')
      setReport(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Bağlantı xətası')
    } finally {
      setLoading(false)
    }
  }

  // Only the findings that need attention
  const problems = report?.findings.filter(
    (f) => f.status === 'fail' || f.status === 'warn',
  )

  return (
    <main className="app">
      <h1>SaytYoxla</h1>
      <p className="lead">Saytınızın təhlükəsizliyini və sürətini yoxlayın</p>

      <form onSubmit={check} className="form">
        <input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="example.az"
          aria-label="Saytın ünvanı"
        />
        <button type="submit" disabled={loading}>
          {loading ? 'Yoxlanılır…' : 'Yoxla'}
        </button>
      </form>

      {error && <p className="error">{error}</p>}

      {report && (
        <section className="result">
          <div className="score">
            <b>{report.grade}</b>
            <span>{report.score} / 100</span>
          </div>
          <p className="host">{report.final_url}</p>
          <p>{report.summary}</p>
          <ul>
            {problems?.map((f) => (
              <li key={f.id} className={f.status}>
                <strong>{f.title}</strong>
                <span>{f.fix}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </main>
  )
}

export default App
