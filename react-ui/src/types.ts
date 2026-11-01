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
  score: number
  grade: string
  summary: string
  findings: Finding[]
  counts: { fail?: number; warn?: number; ok?: number }
  scanned_at: string
}
