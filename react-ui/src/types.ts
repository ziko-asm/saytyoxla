// The JSON returned by POST /api/scan (see scanner/models.py)
export type Status = 'ok' | 'warn' | 'fail' | 'info'

export type Finding = {
  id: string
  category: string
  title: string
  status: Status
  detail: string
  fix: string
  weight: number
}

export type Report = {
  url: string
  final_url: string
  display_url?: string // final_url as people write it: münchen.de, not xn--mnchen-3ya.de
  score: number
  grade: string
  summary: string
  score_note?: string // why the score was held below what the points alone would give
  findings: Finding[]
  counts: { fail?: number; warn?: number; ok?: number }
  benchmarks?: Record<string, number> // check id -> % of surveyed Azerbaijani sites that pass it
  benchmark_sites?: number // how many sites that survey covers
  scanned_at: string
  cached?: boolean // true when the server answered from its 10-minute result cache
}
