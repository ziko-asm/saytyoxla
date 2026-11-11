import { Icon } from '../Icon'
import { GLOSSARY, HOME, LANG, TOOLS_PATH, t, type Lang } from '../i18n'

const NAMES: [Lang, string, string][] = [['az', 'AZ', 'Azərbaycanca'], ['en', 'EN', 'English'], ['ru', 'RU', 'Русский']]

type Props = {
  onHelp: () => void
  checked?: string     // the address on screen: changing the language keeps the result instead of losing it
  tools?: string       // the chosen tool, on the Tools part of the site
}

export function Header({ onHelp, checked = '', tools = '' }: Props) {
  const query = checked ? `?url=${encodeURIComponent(checked)}` : ''
  const pages = tools ? TOOLS_PATH : HOME
  const langQuery = tools ? `?tool=${tools}${checked ? `&url=${encodeURIComponent(checked)}` : ''}` : query
  return (
    <>
      <a className="skip" href="#main">{t.skip}</a>
      <header className="top">
        <div className="wrap">
          <a className="brand" href={HOME[LANG]} aria-label={t.homeLabel}>
            <span className="mark"><Icon name="i-check" /></span>
            <span>Sayt<b>Yoxla</b></span>
          </a>
          <div className="top-right">
            <nav className="langs" aria-label={t.langLabel}>
              {NAMES.map(([code, short, name]) => (
                <a key={code} href={pages[code] + langQuery} hrefLang={code} lang={code} title={name}
                  aria-current={code === LANG ? 'page' : undefined}>{short}</a>
              ))}
            </nav>
            <button className="btn btn-help" type="button" onClick={onHelp}>
              <Icon name="i-help" />
              <span>{t.help}</span>
            </button>
            <nav className="parts" aria-label={t.partsLabel}>
              <a href={HOME[LANG] + query} aria-current={tools ? undefined : 'page'}>{t.partScan}</a>
              <a href={TOOLS_PATH[LANG] + query} aria-current={tools ? 'page' : undefined}>{t.partTools}</a>
            </nav>
            <a className="glos-btn" href={GLOSSARY[LANG][0]}>{GLOSSARY[LANG][1]}</a>
          </div>
        </div>
      </header>
    </>
  )
}
