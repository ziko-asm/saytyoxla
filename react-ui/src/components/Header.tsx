import { Icon } from '../Icon'

export function Header({ onHelp }: { onHelp: () => void }) {
  return (
    <header className="top">
      <div className="wrap">
        <a className="brand" href="/" aria-label="SaytYoxla — əsas səhifə">
          <span className="mark"><Icon name="i-check" /></span>
          <span>Sayt<b>Yoxla</b></span>
        </a>
        <button className="btn btn-help" type="button" onClick={onHelp}>
          <Icon name="i-help" />
          <span>Saytı necə işlətməli?</span>
        </button>
      </div>
    </header>
  )
}
