import { Icon } from '../Icon'
import { snippetsFor } from '../fixes'
import type { Finding } from '../types'
import { t } from '../i18n'

const ICON = { fail: 'i-x', warn: 'i-warn', ok: 'i-check', info: 'i-info' } as const

export function FindingItem({ f, benchmark, sites }: { f: Finding; benchmark?: number; sites?: number }) {
  const snippets = f.fix ? snippetsFor(f.id) : []
  return (
    <div className={`f ${f.status}`}>
      <span className="si" aria-hidden="true"><Icon name={ICON[f.status]} /></span>
      <div className="f-body">
        <h4>{f.title}<span className="lbl">{t.status[f.status]}</span></h4>
        <p>{f.detail}</p>
        {f.fix && <div className="fix"><strong>{t.howToFix}</strong>{f.fix}</div>}
        {f.fix && benchmark !== undefined && !!sites && <p className="bench">{t.benchmark(benchmark, sites)}</p>}
        {snippets.length > 0 && (
          <details className="snips">
            <summary>{t.showCode}</summary>
            {snippets.map((s) => (
              <div className="snip" key={s.platform}>
                <span>{s.platform}</span>
                <pre tabIndex={0}><code>{s.code}</code></pre>
              </div>
            ))}
          </details>
        )}
      </div>
    </div>
  )
}
