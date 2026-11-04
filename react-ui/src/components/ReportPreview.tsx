import { Icon } from '../Icon'
import { t } from '../i18n'
import { useDialog } from './Guide'

type Props = {
  host: string
  pages: string[]
  saving: boolean
  onSave: () => void
  onClose: () => void
}

// "View": the report's pages on screen, with no file saved
export function ReportPreview({ host, pages, saving, onSave, onClose }: Props) {
  const closeBtn = useDialog(onClose)

  return (
    <div className="guide" role="dialog" aria-modal="true" aria-labelledby="previewTitle"
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}>
      <div className="guide-box preview-box">
        <div className="guide-top">
          <h2 id="previewTitle">{host}</h2>
          <button ref={closeBtn} className="close" type="button" aria-label={t.close} onClick={onClose}><Icon name="i-x" /></button>
        </div>
        {pages.map((src, i) => (
          <img key={i} className="preview-page" src={src} alt={t.pageOf(i + 1, pages.length)} />
        ))}
        <button className="btn btn-primary wide" type="button" onClick={onSave} disabled={saving}>{saving ? t.pdfBusy : t.pdf}</button>
      </div>
    </div>
  )
}
