import { useEffect, useRef, useState } from 'react'

const STEPS = [
  'Sayta qoşuluruq…',
  'Sertifikat yoxlanılır…',
  'Təhlükəsizlik ayarları yoxlanılır…',
  'E-poçt qorumasına baxılır…',
  'Hesabat hazırlanır…',
]

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
      <p className="muted">Bu, adətən 10–30 saniyə çəkir. Səhifəni bağlamayın.</p>
    </section>
  )
}
