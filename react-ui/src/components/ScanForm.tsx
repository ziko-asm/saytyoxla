import { forwardRef } from 'react'
import { Icon } from '../Icon'

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
        <h1>Saytınız nə qədər <span>təhlükəsiz</span> və sağlamdır?</h1>
        <p className="lead">Saytınızın ünvanını yazın — 30 saniyəyə pulsuz yoxlayaq və nəticəni sadə dildə izah edək.</p>

        <form
          className="scan"
          noValidate
          onSubmit={(e) => {
            e.preventDefault()
            onSubmit()
          }}
        >
          <label htmlFor="url" className="sr">Saytın ünvanı</label>
          <input
            ref={inputRef}
            id="url"
            name="url"
            type="text"
            inputMode="url"
            autoComplete="url"
            autoCapitalize="off"
            spellCheck={false}
            placeholder="məsələn: meninsaytim.az"
            value={url}
            onChange={(e) => onUrlChange(e.target.value)}
          />
          <button className="btn btn-primary" type="submit" disabled={loading}>
            {loading ? 'Yoxlanılır…' : 'Yoxla'}
          </button>
        </form>
        <p className="form-hint">http:// və ya www yazmağa ehtiyac yoxdur. Pulsuzdur, qeydiyyat tələb olunmur.</p>
        {error && <p className="form-error" role="alert">{error}</p>}

        <div className="howto">
          <div className="howto-head">
            <h2><Icon name="i-help" />Saytı necə işlətməli?</h2>
            <button className="link" type="button" onClick={onHelp}>Ətraflı bələdçi →</button>
          </div>
          <ol className="howto-steps">
            <li><b>1</b><span><strong>Ünvanı yazın</strong>Yuxarıdakı xanaya saytınızın adını yazın.</span></li>
            <li><b>2</b><span><strong>«Yoxla» basın</strong>10–30 saniyə gözləyin, səhifəni bağlamayın.</span></li>
            <li><b>3</b><span><strong>Balınıza baxın</strong>100-ə yaxın bal — yaxşı. Aşağı bal — diqqət.</span></li>
            <li><b>4</b><span><strong>Qırmızıları düzəldin</strong>Hər problemin altında necə düzəldiləcəyi yazılıb.</span></li>
          </ol>
        </div>
      </div>
    </section>
  )
})
