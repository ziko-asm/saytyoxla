import { useCallback, useEffect, useRef, useState } from 'react'
import { Icon } from '../Icon'
import { FindingItem } from './FindingItem'
import { ReportPreview } from './ReportPreview'
import { ScoreRing } from './ScoreRing'
import type { Finding, Report } from '../types'
import { LANG, LOCALE, t } from '../i18n'
import { downloadReportPdf, reportPageImages } from '../pdf'

const WA_NUMBER = '994772172358'
const GRADE_COLOR: Record<string, string> = { A: '#047857', B: '#15803d', C: '#b45309', D: '#c2410c', F: '#b91c1c' }
// Category order follows the checks: security, e-mail, speed, mobile & search
const ORDER = ['https', 'cert', 'spf', 'speed', 'viewport']
const isProblem = (f: Finding) => f.status === 'fail' || f.status === 'warn'

export function ReportView({ report, onAgain, onRescan }: { report: Report; onAgain: () => void; onRescan: () => void }) {
  const box = useRef<HTMLElement>(null)
  useEffect(() => {
    box.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [report])

  // Ctrl+P prints the whole report too, not only the button below
  useEffect(() => {
    const openAll = () => box.current?.querySelectorAll('details').forEach((d) => (d.open = true))
    window.addEventListener('beforeprint', openAll)
    return () => window.removeEventListener('beforeprint', openAll)
  }, [])

  const color = GRADE_COLOR[report.grade] || '#047857'
  const host = (report.display_url || report.final_url).replace(/^https?:\/\//, '').replace(/\/$/, '')
  const [copied, setCopied] = useState(false)
  const [pdfState, setPdfState] = useState<'idle' | 'saving' | 'opening' | 'failed'>('idle')
  const [pages, setPages] = useState<string[] | null>(null)
  const closePreview = useCallback(() => setPages(null), [])
  const c = report.counts || {}
  const clean = !c.fail && !c.warn

  // Group the findings by category, in a fixed order
  const rank = (cat: string) => {
    const ids = report.findings.filter((f) => f.category === cat).map((f) => ORDER.indexOf(f.id))
    return Math.max(...ids)
  }
  const categories = [...new Set(report.findings.map((f) => f.category))].sort((a, b) => rank(a) - rank(b))

  const waText = t.waText(host, report.score, report.grade, clean, !!c.fail)
  const when = new Date(report.scanned_at).toLocaleString(LOCALE[LANG], { timeZoneName: 'short' })

  async function savePdf() {
    setPdfState('saving')
    try {
      await downloadReportPdf(report, host, color, categories, when)
      setPdfState('idle')
    } catch {
      setPdfState('failed')
    }
  }

  async function viewReport() {
    setPdfState('opening')
    try {
      setPages(await reportPageImages(report, host, color, categories, when))
      setPdfState('idle')
    } catch {
      setPdfState('failed')
    }
  }

  async function copyLink() {
    try {
      await navigator.clipboard.writeText(window.location.href)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      window.prompt(t.copyLink, window.location.href)     // the browser refused the clipboard
    }
  }

  const pdfBusy = pdfState === 'saving' || pdfState === 'opening'

  return (
    <section className="report wrap" ref={box}>
      {pages && <ReportPreview host={host} pages={pages} saving={pdfState === 'saving'} onSave={savePdf} onClose={closePreview} />}
      <p className="print-head">SaytYoxla <span>{window.location.host}</span></p>
      <div className="rep-head">
        <ScoreRing score={report.score} color={color} />
        <div className="rep-meta">
          <span className="grade" style={{ background: color }}>{t.grade}: {report.grade}</span>
          <h2>{host}</h2>
          <p>{report.summary}</p>
          {report.score_note && <p className="score-note">{report.score_note}</p>}
          <div className="chips">
            {!!c.fail && <span className="chip fail">{t.chipFail(c.fail)}</span>}
            {!!c.warn && <span className="chip warn">{t.chipWarn(c.warn)}</span>}
            <span className="chip ok">{t.chipOk(c.ok || 0)}</span>
          </div>
          <div className="rep-actions">
            <button className="btn btn-primary" type="button" onClick={savePdf} disabled={pdfBusy}>{pdfState === 'saving' ? t.pdfBusy : t.pdf}</button>
            <button className="btn btn-ghost" type="button" onClick={viewReport} disabled={pdfBusy}>{pdfState === 'opening' ? t.pdfBusy : t.view}</button>
            <button className="btn btn-ghost" type="button" onClick={copyLink} aria-live="polite">{copied ? t.linkCopied : t.copyLink}</button>
            <button className="btn btn-ghost" type="button" onClick={onRescan} title={t.rescanHint}>{t.rescan}</button>
            <button className="btn btn-ghost" type="button" onClick={onAgain}>{t.again}</button>
          </div>
          {pdfState === 'failed' && <p className="form-error" role="alert">{t.pdfError}</p>}
        </div>
      </div>

      <div className="legend" aria-label={t.legend}>
        <span><i className="dot fail"></i>{t.status.fail}</span>
        <span><i className="dot warn"></i>{t.status.warn}</span>
        <span><i className="dot ok"></i>{t.status.ok}</span>
        <span><i className="dot info"></i>{t.status.info}</span>
      </div>

      <div>
        {categories.map((cat) => {
          const items = report.findings.filter((f) => f.category === cat)
          const bad = items.filter(isProblem)
          const rest = items.filter((f) => !isProblem(f))
          return (
            <div className="group" key={cat}>
              <h3>{cat} <small>{bad.length ? t.issues(bad.length) : rest.every((f) => f.status === 'info') ? t.infoOnly : t.allGood}</small></h3>
              {bad.map((f) => <FindingItem key={f.id} f={f} benchmark={report.benchmarks?.[f.id]} />)}
              {rest.length > 0 && (bad.length ? (
                <details className="ok-list">
                  <summary>{t.showOk(rest.length)}</summary>
                  {rest.map((f) => <FindingItem key={f.id} f={f} />)}
                </details>
              ) : rest.map((f) => <FindingItem key={f.id} f={f} />))}
            </div>
          )
        })}
      </div>

      <div className="cta-card">
        <div>
          <h3>{clean ? t.ctaCleanTitle : t.ctaTitle}</h3>
          <p>{clean ? t.ctaClean : t.cta}</p>
        </div>
        <a className="btn btn-wa" href={`https://wa.me/${WA_NUMBER}?text=${encodeURIComponent(waText)}`} target="_blank" rel="noopener">
          <Icon name="i-wa" />{t.wa}
        </a>
      </div>
      <p className="muted small">
        {t.scannedAt(when)}
        {report.cached ? ' ' + t.cachedNote : ''}
      </p>
    </section>
  )
}
