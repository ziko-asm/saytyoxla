import { useCallback, useEffect, useRef, useState } from 'react'
import { FindingItem } from './components/FindingItem'
import { Guide } from './components/Guide'
import { Header } from './components/Header'
import { LANG, t } from './i18n'
import type { Finding } from './types'

// "ssl" and "email" ask /api/tool, which never opens the page, so they work behind bot protection too.
// The others show their part of a full scan.
type ToolId = 'ssl' | 'dmarc' | 'spf' | 'dkim' | 'headers' | 'cookies' | 'google' | 'speed'
type Source = 'ssl' | 'email' | 'scan'
type Facts = { issuer?: string; expires?: string; days_left?: number | null; tls?: string; spf?: string[]; dmarc?: string[]; dmarc_parent?: string; dkim?: string[] }
type Result = { findings: Finding[]; facts?: Facts; benchmarks?: Record<string, number>; host?: string; final_url?: string }

const TOOLS: { id: ToolId; source: Source; findings: string[] }[] = [
  { id: 'ssl', source: 'ssl', findings: ['cert', 'tls'] },
  { id: 'dmarc', source: 'email', findings: ['dmarc'] },
  { id: 'spf', source: 'email', findings: ['spf'] },
  { id: 'dkim', source: 'email', findings: ['dkim'] },
  { id: 'headers', source: 'scan', findings: ['http_redirect', 'hsts', 'framing', 'nosniff', 'csp', 'referrer', 'disclosure', 'mixed'] },
  { id: 'cookies', source: 'scan', findings: ['cookies'] },
  { id: 'google', source: 'scan', findings: ['indexing', 'title', 'description', 'h1', 'lang', 'canonical', 'og', 'sitemap', 'viewport'] },
  { id: 'speed', source: 'scan', findings: ['speed', 'size'] },
]
const ORDER: Record<string, number> = { fail: 0, warn: 1, ok: 2, info: 3 }

function factRows(tool: ToolId, facts: Facts | undefined): [string, string][] {
  if (!facts) return []
  const rows: [string, string | undefined][] = tool === 'ssl'
    ? [[t.factIssuer, facts.issuer], [t.factExpires, facts.expires],
       [t.factDaysLeft, facts.days_left === null || facts.days_left === undefined ? '' : String(facts.days_left)],
       [t.factTls, facts.tls?.replace('TLSv', 'TLS ')]]
    : tool === 'dmarc'
      ? [[t.factRecord, facts.dmarc?.join(' ')], [t.factParent, facts.dmarc_parent]]
      : tool === 'spf'
        ? [[t.factRecord, facts.spf?.join(' ')]]
        : tool === 'dkim' ? [[t.factSelectors, facts.dkim?.join(', ')]] : []
  return rows.filter((row): row is [string, string] => !!row[1])
}

export default function ToolsApp() {
  const params = new URLSearchParams(window.location.search)
  const start = TOOLS.some((x) => x.id === params.get('tool')) ? (params.get('tool') as ToolId) : 'ssl'
  const [tool, setTool] = useState<ToolId>(start)
  const [url, setUrl] = useState(params.get('url') || '')
  const [checked, setChecked] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<Result | null>(null)
  const [guideOpen, setGuideOpen] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  const answers = useRef(new Map<string, Result>())     // switching tools on one address asks the server only once

  const run = useCallback(async (toolId: ToolId, target: string) => {
    const value = target.trim()
    setError('')
    if (!value) {
      setResult(null)
      setError(t.emptyUrl)
      input.current?.focus()
      return
    }
    const source = TOOLS.find((x) => x.id === toolId)!.source
    window.history.replaceState(null, '', `${window.location.pathname}?tool=${toolId}&url=${encodeURIComponent(value)}`)
    const key = `${source}:${value}`
    const known = answers.current.get(key)
    if (known) {
      setResult(known)
      setChecked(value)
      return
    }
    setResult(null)
    setLoading(true)
    try {
      const res = await fetch(source === 'scan' ? '/api/scan' : '/api/tool', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(source === 'scan' ? { url: value, lang: LANG } : { url: value, tool: source, lang: LANG }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(typeof data.detail === 'string' ? data.detail : t.genericError)
      } else {
        answers.current.set(key, data as Result)
        setResult(data)
        setChecked(value)
      }
    } catch {
      setError(t.networkError)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    const first = new URLSearchParams(window.location.search).get('url')
    if (first) run(start, first)
    // only the address the page was opened with
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function choose(next: ToolId) {
    setTool(next)
    setResult(null)
    setError('')
    if (url.trim()) run(next, url)
  }

  const closeGuide = useCallback(() => setGuideOpen(false), [])
  const current = TOOLS.find((x) => x.id === tool)!
  const findings = (result?.findings || [])
    .filter((f) => current.findings.includes(f.id))
    .sort((a, b) => ORDER[a.status] - ORDER[b.status])
  const facts = factRows(tool, result?.facts)
  const host = result?.host || (result?.final_url || checked).replace(/^https?:\/\//, '').replace(/\/.*$/, '')

  return (
    <>
      <Header onHelp={() => setGuideOpen(true)} checked={checked} tools={tool} />
      <main id="main">
        <section className="hero tools-hero">
          <div className="wrap narrow">
            <h1>{t.toolsTitle}</h1>
            <p className="lead">{t.toolsLead}</p>
            <div className="tool-list" role="group" aria-label={t.partTools}>
              {TOOLS.map((x) => (
                <button key={x.id} type="button" className={x.id === tool ? 'tool-tab on' : 'tool-tab'}
                  aria-pressed={x.id === tool} onClick={() => choose(x.id)}>
                  {t.tools[x.id][0]}
                </button>
              ))}
            </div>
            <p className="tool-about">{t.tools[tool][1]}</p>
            <form className="scan" noValidate onSubmit={(e) => { e.preventDefault(); run(tool, url) }}>
              <label htmlFor="url" className="sr">{t.urlLabel}</label>
              <input ref={input} id="url" name="url" type="text" inputMode="url" autoComplete="url" autoCapitalize="off"
                spellCheck={false} maxLength={300} placeholder={t.placeholder} value={url}
                onInput={(e) => setUrl(e.currentTarget.value)} />
              <button className="btn btn-primary" type="submit" disabled={loading}>{loading ? t.scanning : t.scan}</button>
            </form>
            {error && <p className="form-error" role="alert">{error}</p>}
          </div>
        </section>
        <section className="wrap narrow tool-result" aria-live="polite">
          {loading && <div className="spinner" role="status" aria-label={t.scanning}></div>}
          {result && (
            <>
              <h2>{t.tools[tool][0]}: {host}</h2>
              {facts.length > 0 && (
                <dl className="facts">
                  {facts.map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}
                </dl>
              )}
              {findings.map((f) => <FindingItem key={f.id} f={f} benchmark={result.benchmarks?.[f.id]} />)}
              <p className="tool-more"><a href={`${window.location.pathname.replace(/[^/]+\/$/, '')}?url=${encodeURIComponent(checked)}`}>{t.toolsFull}</a></p>
            </>
          )}
        </section>
      </main>
      {guideOpen && <Guide onClose={closeGuide} onStart={() => { setGuideOpen(false); input.current?.focus() }} />}
    </>
  )
}
