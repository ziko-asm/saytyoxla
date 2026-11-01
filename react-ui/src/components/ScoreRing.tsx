import { useEffect, useState } from 'react'

// Counts the ring up from 0 to the score; the CSS draws it from the --p and --c variables
export function ScoreRing({ score, color }: { score: number; color: string }) {
  const [shown, setShown] = useState(0)

  useEffect(() => {
    let frame = 0
    let start: number | null = null
    const tick = (t: number) => {
      if (start === null) start = t
      const p = Math.min(1, (t - start) / 900)
      setShown(Math.round(score * p))
      if (p < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [score])

  return (
    <div className="score" style={{ '--p': shown, '--c': color } as React.CSSProperties}>
      <div><b>{score}</b><small>/100</small></div>
    </div>
  )
}
