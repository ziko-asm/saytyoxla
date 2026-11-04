import { forwardRef } from 'react'
import { Icon } from '../Icon'
import { t } from '../i18n'

type Props = {
  url: string
  onUrlChange: (value: string) => void
  onSubmit: () => void
  loading: boolean
  error: string
  onHelp: () => void
}

// forwardRef lets the parent move keyboard focus into the input
export const ScanForm = forwardRef<HTMLInputElement, Props>(function ScanForm(
  { url, onUrlChange, onSubmit, loading, error, onHelp },
  inputRef,
) {
  return (
    <section className="hero">
      <div className="wrap narrow">
        <h1>{t.h1a}<span>{t.h1b}</span>{t.h1c}</h1>
        <p className="lead">{t.lead}</p>

        <form
          className="scan"
          noValidate
          onSubmit={(e) => {
            e.preventDefault()
            onSubmit()
          }}
        >
          <label htmlFor="url" className="sr">{t.urlLabel}</label>
          <input
            ref={inputRef}
            id="url"
            name="url"
            type="text"
            inputMode="url"
            autoComplete="url"
            autoCapitalize="off"
            spellCheck={false}
            maxLength={300}
            placeholder={t.placeholder}
            value={url}
            onChange={(e) => onUrlChange(e.target.value)}
          />
          <button className="btn btn-primary" type="submit" disabled={loading}>
            {loading ? t.scanning : t.scan}
          </button>
        </form>
        <p className="form-hint">{t.hint}</p>
        {error && <p className="form-error" role="alert">{error}</p>}

        <div className="howto">
          <div className="howto-head">
            <h2><Icon name="i-help" />{t.help}</h2>
            <button className="link" type="button" onClick={onHelp}>{t.guideLink}</button>
          </div>
          <ol className="howto-steps">
            {t.steps.map(([title, text], i) => (
              <li key={i}><b>{i + 1}</b><span><strong>{title}</strong>{text}</span></li>
            ))}
          </ol>
        </div>
      </div>
    </section>
  )
})
