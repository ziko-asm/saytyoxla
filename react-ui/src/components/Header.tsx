import { Icon } from '../Icon'
import { HOME, LANG, t, type Lang } from '../i18n'

const NAMES: [Lang, string, string][] = [['az', 'AZ', 'Azərbaycanca'], ['en', 'EN', 'English'], ['ru', 'RU', 'Русский']]

export function Header({ onHelp }: { onHelp: () => void }) {
  return (
    <header className="top">
      <div className="wrap">
        <a className="brand" href={HOME[LANG]} aria-label={t.homeLabel}>
          <span className="mark"><Icon name="i-check" /></span>
          <span>Sayt<b>Yoxla</b></span>
        </a>
        <div className="top-right">
          <nav className="langs" aria-label={t.langLabel}>
            {NAMES.map(([code, short, name]) => (
              <a key={code} href={HOME[code]} hrefLang={code} lang={code} title={name}
                aria-current={code === LANG ? 'page' : undefined}>{short}</a>
            ))}
          </nav>
          <button className="btn btn-help" type="button" onClick={onHelp}>
            <Icon name="i-help" />
            <span>{t.help}</span>
          </button>
        </div>
      </div>
    </header>
  )
}
