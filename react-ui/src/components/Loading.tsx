import { useEffect, useRef, useState } from 'react'
import { t } from '../i18n'

const STEPS = t.loadingSteps

export function Loading() {
  const [step, setStep] = useState(0)
  const box = useRef<HTMLElement>(null)

  // useEffect runs after the component appears; the returned function cleans up when it disappears
  useEffect(() => {
    box.current?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    const timer = setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), 2500)
    return () => clearInterval(timer)
  }, [])

  return (
    <section className="loading wrap narrow" ref={box} aria-live="polite">
      <div className="spinner" aria-hidden="true"></div>
      <p>{STEPS[step]}</p>
      <p className="muted">{t.loadingNote}</p>
    </section>
  )
}
