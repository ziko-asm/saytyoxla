import { useEffect, useRef } from 'react'
import { Icon } from '../Icon'
import { FindingItem } from './FindingItem'
import { ScoreRing } from './ScoreRing'
import type { Finding, Report } from '../types'

const WA_NUMBER = '994772172358'
const GRADE_COLOR: Record<string, string> = { A: '#059669', B: '#16a34a', C: '#d97706', D: '#ea580c', F: '#dc2626' }
const ORDER = ['Təhlükəsizlik', 'E-poçt', 'Sürət', 'Mobil və Google']
const isProblem = (f: Finding) => f.status === 'fail' || f.status === 'warn'

export function ReportView({ report, onAgain }: { report: Report; onAgain: () => void }) {
  const box = useRef<HTMLElement>(null)
  useEffect(() => {
    box.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [report])

  const color = GRADE_COLOR[report.grade] || '#059669'
  const host = report.final_url.replace(/^https?:\/\//, '').replace(/\/$/, '')
  const c = report.counts || {}
  const clean = !c.fail && !c.warn

  // Group the findings by category, in a fixed order
  const categories = [...new Set(report.findings.map((f) => f.category))].sort(
    (a, b) => ORDER.indexOf(a) - ORDER.indexOf(b),
  )

  const waText =
    `Salam! SaytYoxla-da ${host} saytını yoxladım: ${report.score}/100 (${report.grade}). ` +
    (clean ? 'Sizinlə əməkdaşlıq barədə danışmaq istəyirəm.' : 'Problemləri düzəltməyə kömək lazımdır.')

  function print() {
    box.current?.querySelectorAll('details').forEach((d) => (d.open = true))
    window.print()
  }

  return (
    <section className="report wrap" ref={box}>
      <div className="rep-head">
        <ScoreRing score={report.score} color={color} />
        <div className="rep-meta">
          <span className="grade" style={{ background: color }}>Qiymət: {report.grade}</span>
          <h2>{host}</h2>
          <p>{report.summary}</p>
          <div className="chips">
            {!!c.fail && <span className="chip fail">{c.fail} ciddi problem</span>}
            {!!c.warn && <span className="chip warn">{c.warn} tövsiyə</span>}
            <span className="chip ok">{c.ok || 0} qaydasında</span>
          </div>
          <div className="rep-actions">
            <button className="btn btn-ghost" type="button" onClick={print}><Icon name="i-print" />Hesabatı çap et / PDF</button>
            <button className="btn btn-ghost" type="button" onClick={onAgain}>Başqa sayt yoxla</button>
          </div>
        </div>
      </div>

      <div className="legend" aria-label="Rənglərin mənası">
        <span><i className="dot fail"></i>Ciddi problem</span>
        <span><i className="dot warn"></i>Tövsiyə</span>
        <span><i className="dot ok"></i>Qaydasındadır</span>
        <span><i className="dot info"></i>Məlumat</span>
      </div>

      <div>
        {categories.map((cat) => {
          const items = report.findings.filter((f) => f.category === cat)
          const bad = items.filter(isProblem)
          const rest = items.filter((f) => !isProblem(f))
          return (
            <div className="group" key={cat}>
              <h3>{cat} <small>{bad.length ? `${bad.length} məsələ` : 'hər şey qaydasındadır'}</small></h3>
              {bad.map((f) => <FindingItem key={f.id} f={f} />)}
              {rest.length > 0 && (bad.length ? (
                <details className="ok-list">
                  <summary>+ {rest.length} qaydasında olan yoxlamanı göstər</summary>
                  {rest.map((f) => <FindingItem key={f.id} f={f} />)}
                </details>
              ) : rest.map((f) => <FindingItem key={f.id} f={f} />))}
            </div>
          )
        })}
      </div>

      <div className="cta-card">
        <div>
          <h3>{clean ? 'Saytınız əla vəziyyətdədir!' : 'Problemləri özünüz düzəldə bilmirsiniz?'}</h3>
          <p>{clean
            ? 'Yeni sayt, dizayn yeniləməsi və ya saytın mütəmadi izlənməsi lazımdırsa, yazın.'
            : 'Hesabatı göndərin, nəyin necə düzəldiləcəyini izah edək və ya özümüz düzəldək.'}</p>
        </div>
        <a className="btn btn-wa" href={`https://wa.me/${WA_NUMBER}?text=${encodeURIComponent(waText)}`} target="_blank" rel="noopener">
          <Icon name="i-wa" />WhatsApp-a yazın
        </a>
      </div>
      <p className="muted small">
        Yoxlama vaxtı: {new Date(report.scanned_at).toLocaleString('az-AZ')}. Nəticə yalnız açıq məlumatlara əsaslanır.
      </p>
    </section>
  )
}
