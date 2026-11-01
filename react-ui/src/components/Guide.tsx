import { useEffect, useRef } from 'react'
import { Icon } from '../Icon'
import { t } from '../i18n'

const LEGEND = ['fail', 'warn', 'ok', 'info']

export function Guide({ onClose, onStart }: { onClose: () => void; onStart: () => void }) {
  const closeBtn = useRef<HTMLButtonElement>(null)

  // While open: focus the close button, lock page scroll, close on Escape
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null
    closeBtn.current?.focus()
    document.body.style.overflow = 'hidden'
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', onKey)
    return () => {
      document.body.style.overflow = ''
      document.removeEventListener('keydown', onKey)
      before?.focus()
    }
  }, [onClose])

  return (
    <div className="guide" role="dialog" aria-modal="true" aria-labelledby="guideTitle"
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="guide-box">
        <div className="guide-top">
          <h2 id="guideTitle">{t.help}</h2>
          <button ref={closeBtn} className="close" type="button" aria-label={t.close} onClick={onClose}><Icon name="i-x" /></button>
        </div>
        <ol className="guide-steps">
          {t.guide.map(([title, text], i) => (
            <li key={i}><b>{i + 1}</b><div><h3>{title}</h3>
              {text ? <p>{text}</p> : (
                <ul className="g-legend">
                  {t.guideLegend.map(([name, meaning], j) => (
                    <li key={j}><i className={`dot ${LEGEND[j]}`}></i><span><strong>{name}</strong> — {meaning}</span></li>
                  ))}
                </ul>
              )}
            </div></li>
          ))}
        </ol>
        <button className="btn btn-primary wide" type="button" onClick={onStart}>{t.guideStart}</button>
      </div>
    </div>
  )
}
