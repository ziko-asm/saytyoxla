import { Icon } from '../Icon'
import type { Finding } from '../types'
import { t } from '../i18n'

const ICON = { fail: 'i-x', warn: 'i-warn', ok: 'i-check', info: 'i-info' } as const

export function FindingItem({ f }: { f: Finding }) {
  return (
    <div className={`f ${f.status}`}>
      <span className="si" aria-hidden="true"><Icon name={ICON[f.status]} /></span>
      <div>
        <h4>{f.title}<span className="lbl">{t.status[f.status]}</span></h4>
        <p>{f.detail}</p>
        {f.fix && <div className="fix"><strong>{t.howToFix}</strong>{f.fix}</div>}
      </div>
    </div>
  )
}
