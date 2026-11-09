import { t } from '../i18n'

type Props = {
  sites: string[]
  disabled: boolean
  onPick: (site: string) => void
  onClear: () => void
}

// The last checked sites under the form; a click scans that site again
export function RecentSites({ sites, disabled, onPick, onClear }: Props) {
  if (!sites.length) return null
  return (
    <div className="recent wrap narrow">
      <p className="recent-title" id="recent-title">{t.recentTitle}</p>
      <ul className="recent-list" aria-labelledby="recent-title">
        {sites.map((site) => (
          <li key={site}>
            <button className="chip-btn" type="button" disabled={disabled} onClick={() => onPick(site)}>{site}</button>
          </li>
        ))}
      </ul>
      <button className="link" type="button" onClick={onClear}>{t.recentClear}</button>
    </div>
  )
}
