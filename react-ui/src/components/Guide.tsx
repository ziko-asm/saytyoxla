import { useEffect, useRef } from 'react'
import { Icon } from '../Icon'

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
          <h2 id="guideTitle">Saytı necə işlətməli?</h2>
          <button ref={closeBtn} className="close" type="button" aria-label="Bağla" onClick={onClose}><Icon name="i-x" /></button>
        </div>
        <ol className="guide-steps">
          <li><b>1</b><div><h3>Saytınızın ünvanını yazın</h3><p>Səhifənin yuxarısındakı ağ xanaya saytınızın adını yazın. Məsələn: <code>meninsaytim.az</code>. «http://» və ya «www» yazmağa ehtiyac yoxdur.</p></div></li>
          <li><b>2</b><div><h3>«Yoxla» düyməsinə basın</h3><p>Biz saytınızı yoxlamağa başlayırıq. Bu, 10–30 saniyə çəkir. Bu vaxt səhifəni bağlamayın.</p></div></li>
          <li><b>3</b><div><h3>Balınıza baxın</h3><p>Yuxarıda 0-dan 100-ə qədər bal və hərf (A, B, C, D, F) görəcəksiniz. <strong>A</strong> — əla, <strong>F</strong> — təcili diqqət lazımdır.</p></div></li>
          <li><b>4</b><div><h3>Rənglərə baxın</h3>
            <ul className="g-legend">
              <li><i className="dot fail"></i><span><strong>Qırmızı ✕</strong> — ciddi problem, ilk növbədə düzəldin.</span></li>
              <li><i className="dot warn"></i><span><strong>Sarı !</strong> — tövsiyə, düzəltmək yaxşı olar.</span></li>
              <li><i className="dot ok"></i><span><strong>Yaşıl ✓</strong> — hər şey qaydasındadır.</span></li>
              <li><i className="dot info"></i><span><strong>Boz i</strong> — sadəcə məlumat, bala təsir etmir.</span></li>
            </ul></div></li>
          <li><b>5</b><div><h3>«Necə düzəltmək» hissəsini oxuyun</h3><p>Hər problemin altında nə edilməli olduğu sadə dillə yazılıb. Bunu saytınızı quran şəxsə göstərin.</p></div></li>
          <li><b>6</b><div><h3>Hesabatı saxlayın və ya göndərin</h3><p>«Hesabatı çap et / PDF» düyməsi ilə hesabatı kağıza çap edə və ya PDF kimi saxlaya bilərsiniz. Kömək lazımdırsa, «WhatsApp-a yazın» düyməsini basın.</p></div></li>
        </ol>
        <button className="btn btn-primary wide" type="button" onClick={onStart}>Başa düşdüm, yoxlamaya başla</button>
      </div>
    </div>
  )
}
