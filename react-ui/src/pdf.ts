// Builds the report as a PDF file in the visitor's browser and downloads it. Nothing goes through the
// system print dialog (phones need a "printer" chosen there) and nothing is sent to a server.
// Each page is drawn on a canvas and stored as a JPEG, so every letter (ə, ş, я) looks as it does on screen
// and no font has to be embedded.

import type { Finding, Report, Status } from './types'
import { LANG, t } from './i18n'

const W = 1240, H = 1754            // A4 at 150 dpi
const PT_W = 595.28, PT_H = 841.89  // A4 in PDF points
const M = 80, BOTTOM = H - 110
const FONT = 'Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
const INK = '#0f1b2d', INK2 = '#3d4b60', MUTED = '#5b6779', LINE = '#e3e8f0'
const COLOR: Record<Status, string> = { fail: '#dc2626', warn: '#b45309', ok: '#047857', info: '#64748b' }

type Ctx = CanvasRenderingContext2D

function setFont(c: Ctx, weight: number, size: number, color = INK) {
  c.font = `${weight} ${size}px ${FONT}`
  c.fillStyle = color
}

// Lines that fit maxWidth; a word too long for one line (an address) is cut
function wrap(c: Ctx, text: string, maxWidth: number): string[] {
  const lines: string[] = []
  let line = ''
  for (const word of text.split(/\s+/).filter(Boolean)) {
    let rest = word
    let candidate = line ? `${line} ${rest}` : rest
    if (c.measureText(candidate).width <= maxWidth) { line = candidate; continue }
    if (line) lines.push(line)
    line = ''
    while (c.measureText(rest).width > maxWidth) {
      let n = rest.length - 1
      while (n > 1 && c.measureText(rest.slice(0, n)).width > maxWidth) n--
      lines.push(rest.slice(0, n))
      rest = rest.slice(n)
    }
    candidate = rest
    line = candidate
  }
  if (line) lines.push(line)
  return lines
}

function drawLines(c: Ctx, lines: string[], x: number, y: number, height: number) {
  lines.forEach((l, i) => c.fillText(l, x, y + i * height))
  return y + lines.length * height
}

function roundRect(c: Ctx, x: number, y: number, w: number, h: number, r: number, fill: string, stroke?: string) {
  c.beginPath()
  c.roundRect(x, y, w, h, r)
  c.fillStyle = fill
  c.fill()
  if (stroke) { c.strokeStyle = stroke; c.lineWidth = 2; c.stroke() }
}

function statusIcon(c: Ctx, status: Status, cx: number, cy: number) {
  c.beginPath()
  c.arc(cx, cy, 18, 0, Math.PI * 2)
  c.fillStyle = COLOR[status]
  c.fill()
  c.strokeStyle = '#fff'
  c.lineWidth = 4
  c.lineCap = 'round'
  c.beginPath()
  if (status === 'ok') { c.moveTo(cx - 8, cy); c.lineTo(cx - 2, cy + 7); c.lineTo(cx + 9, cy - 6) }
  else if (status === 'fail') { c.moveTo(cx - 7, cy - 7); c.lineTo(cx + 7, cy + 7); c.moveTo(cx + 7, cy - 7); c.lineTo(cx - 7, cy + 7) }
  else if (status === 'warn') { c.moveTo(cx, cy - 9); c.lineTo(cx, cy + 3); c.moveTo(cx, cy + 9); c.lineTo(cx, cy + 9) }
  else { c.moveTo(cx, cy - 9); c.lineTo(cx, cy - 9); c.moveTo(cx, cy - 2); c.lineTo(cx, cy + 9) }
  c.stroke()
}

class Pages {
  canvases: HTMLCanvasElement[] = []
  c!: Ctx
  y = M

  constructor() { this.add() }

  add() {
    const canvas = document.createElement('canvas')
    canvas.width = W
    canvas.height = H
    const c = canvas.getContext('2d')
    if (!c) throw new Error('no canvas')
    c.fillStyle = '#fff'
    c.fillRect(0, 0, W, H)
    c.textBaseline = 'top'
    this.canvases.push(canvas)
    this.c = c
    this.y = M
  }

  need(height: number) {
    if (this.y + height > BOTTOM) this.add()
  }
}

function drawHead(p: Pages, report: Report, host: string, color: string) {
  const c = p.c
  setFont(c, 800, 34)
  c.fillText('Sayt', M, p.y)
  const sayt = c.measureText('Sayt').width
  setFont(c, 800, 34, '#1d4ed8')
  c.fillText('Yoxla', M + sayt, p.y)
  p.y += 70

  const top = p.y
  const cx = M + 100, cy = top + 100
  c.lineWidth = 22
  c.lineCap = 'butt'
  c.strokeStyle = LINE
  c.beginPath(); c.arc(cx, cy, 88, 0, Math.PI * 2); c.stroke()
  c.strokeStyle = color
  c.beginPath(); c.arc(cx, cy, 88, -Math.PI / 2, -Math.PI / 2 + (Math.PI * 2 * report.score) / 100); c.stroke()
  c.textAlign = 'center'
  setFont(c, 800, 58)
  c.fillText(String(report.score), cx, cy - 42)
  setFont(c, 600, 22, MUTED)
  c.fillText('/100', cx, cy + 22)
  c.textAlign = 'left'

  const x = M + 240, width = W - M - x
  const label = `${t.grade}: ${report.grade}`
  setFont(c, 800, 24, '#fff')
  const pill = c.measureText(label).width + 40
  roundRect(c, x, top, pill, 44, 22, color)
  setFont(c, 800, 24, '#fff')
  c.fillText(label, x + 20, top + 10)

  let y = top + 58
  setFont(c, 800, 34)
  y = drawLines(c, wrap(c, host, width), x, y, 42) + 6
  setFont(c, 400, 26, INK2)
  y = drawLines(c, wrap(c, report.summary, width), x, y, 36)
  if (report.score_note) {
    setFont(c, 600, 23, '#92400e')
    y = drawLines(c, wrap(c, report.score_note, width), x, y + 6, 32)
  }
  p.y = Math.max(y, top + 200) + 40
}

function findingHeight(c: Ctx, f: Finding, width: number) {
  setFont(c, 700, 26)
  let h = 28 + wrap(c, `${f.title}   ${t.status[f.status]}`, width).length * 36
  setFont(c, 400, 24)
  h += wrap(c, f.detail, width).length * 33
  if (f.fix) {
    setFont(c, 400, 23)
    h += 74 + wrap(c, f.fix, width - 40).length * 31
  }
  return h + 18
}

function drawFinding(p: Pages, f: Finding) {
  const c = p.c
  const x = M + 82, width = W - M - x - 28
  const height = findingHeight(c, f, width)
  p.need(height + 14)
  const q = p.c
  const top = p.y
  roundRect(q, M, top, W - 2 * M, height, 14, '#fff', LINE)
  q.fillStyle = COLOR[f.status]
  q.beginPath(); q.roundRect(M, top, 9, height, [14, 0, 0, 14]); q.fill()
  statusIcon(q, f.status, M + 46, top + 44)

  let y = top + 24
  setFont(q, 700, 26)
  const title = wrap(q, f.title, width)
  y = drawLines(q, title, x, y, 36)
  const lastWidth = q.measureText(title[title.length - 1]).width
  const label = t.status[f.status].toLocaleUpperCase(LANG)     // Azerbaijani: i -> İ
  setFont(q, 700, 19, COLOR[f.status])
  if (lastWidth + 20 + q.measureText(label).width <= width) q.fillText(label, x + lastWidth + 16, y - 31)
  else { q.fillText(label, x, y); y += 30 }

  setFont(q, 400, 24, INK2)
  y = drawLines(q, wrap(q, f.detail, width), x, y, 33)
  if (f.fix) {
    setFont(q, 400, 23)
    const fix = wrap(q, f.fix, width - 40)
    const box = 56 + fix.length * 31
    roundRect(q, x, y + 10, width, box, 12, f.status === 'fail' ? '#fef2f2' : '#fffbeb')
    setFont(q, 800, 18, f.status === 'fail' ? '#7f1d1d' : '#5b3b04')
    q.fillText(t.howToFix.toLocaleUpperCase(LANG), x + 20, y + 24)
    setFont(q, 400, 23, f.status === 'fail' ? '#7f1d1d' : '#5b3b04')
    drawLines(q, fix, x + 20, y + 52, 31)
  }
  p.y = top + height + 14
}

function drawPages(report: Report, host: string, color: string, categories: string[], when: string) {
  const p = new Pages()
  drawHead(p, report, host, color)
  for (const cat of categories) {
    const items = report.findings.filter((f) => f.category === cat)
    p.need(60 + findingHeight(p.c, items[0], W - 2 * M - 110))
    setFont(p.c, 800, 30)
    p.c.fillText(cat, M, p.y + 8)
    p.y += 56
    items.forEach((f) => drawFinding(p, f))
    p.y += 14
  }
  setFont(p.c, 400, 21, MUTED)
  const note = wrap(p.c, t.scannedAt(when), W - 2 * M)
  p.need(note.length * 30 + 10)
  setFont(p.c, 400, 21, MUTED)
  drawLines(p.c, note, M, p.y + 6, 30)

  p.canvases.forEach((canvas, i) => {
    const c = canvas.getContext('2d') as Ctx
    setFont(c, 400, 20, MUTED)
    c.fillText(`SaytYoxla · ${window.location.host}`, M, H - 70)
    const page = `${i + 1} / ${p.canvases.length}`
    c.fillText(page, W - M - c.measureText(page).width, H - 70)
  })
  return p.canvases
}

function jpegOf(canvas: HTMLCanvasElement): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (!blob) { reject(new Error('no image')); return }
      blob.arrayBuffer().then((b) => resolve(new Uint8Array(b)), reject)
    }, 'image/jpeg', 0.9)
  })
}

// A minimal PDF: one page per image (objects: 1 catalog, 2 page list, then page + content + image for each)
export function buildPdf(images: Uint8Array[], width = W, height = H): Uint8Array {
  const parts: Uint8Array[] = []
  const offsets: number[] = []
  const encoder = new TextEncoder()
  let size = 0
  const put = (data: string | Uint8Array) => {
    const bytes = typeof data === 'string' ? encoder.encode(data) : data
    parts.push(bytes)
    size += bytes.length
  }
  const object = (n: number, write: () => void) => {
    offsets[n] = size
    put(`${n} 0 obj\n`)
    write()
    put('\nendobj\n')
  }

  put('%PDF-1.4\n')
  const kids = images.map((_, i) => `${3 + i * 3} 0 R`).join(' ')
  object(1, () => put('<< /Type /Catalog /Pages 2 0 R >>'))
  object(2, () => put(`<< /Type /Pages /Kids [${kids}] /Count ${images.length} >>`))
  images.forEach((image, i) => {
    const page = 3 + i * 3
    const content = `q ${PT_W} 0 0 ${PT_H} 0 0 cm /Im0 Do Q`
    object(page, () => put(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PT_W} ${PT_H}] `
      + `/Resources << /XObject << /Im0 ${page + 2} 0 R >> >> /Contents ${page + 1} 0 R >>`))
    object(page + 1, () => put(`<< /Length ${content.length} >>\nstream\n${content}\nendstream`))
    object(page + 2, () => {
      put(`<< /Type /XObject /Subtype /Image /Width ${width} /Height ${height} /ColorSpace /DeviceRGB `
        + `/BitsPerComponent 8 /Filter /DCTDecode /Length ${image.length} >>\nstream\n`)
      put(image)
      put('\nendstream')
    })
  })

  const count = 3 + images.length * 3
  const xref = size
  put(`xref\n0 ${count}\n0000000000 65535 f \n`)
  for (let n = 1; n < count; n++) put(`${String(offsets[n]).padStart(10, '0')} 00000 n \n`)
  put(`trailer\n<< /Size ${count} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`)

  const out = new Uint8Array(size)
  let at = 0
  for (const part of parts) { out.set(part, at); at += part.length }
  return out
}

function saveFile(file: File) {
  const link = document.createElement('a')
  link.href = URL.createObjectURL(file)
  link.download = file.name
  document.body.append(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(link.href), 60_000)
}

async function renderPages(report: Report, host: string, color: string, categories: string[], when: string) {
  try {
    await Promise.all(['400 24px Inter', '600 24px Inter', '700 24px Inter', '800 24px Inter'].map((f) => document.fonts.load(f, 'əşğ')))
  } catch { /* the system font is good enough */ }
  return drawPages(report, host, color, categories, when)
}

// The same pages for showing on screen. Phones often turn an opened PDF into a download, so "View" uses images.
export async function reportPageImages(report: Report, host: string, color: string, categories: string[], when: string) {
  const pages = await renderPages(report, host, color, categories, when)
  return pages.map((canvas) => canvas.toDataURL('image/jpeg', 0.9))
}

export async function downloadReportPdf(report: Report, host: string, color: string, categories: string[], when: string) {
  const images = await Promise.all((await renderPages(report, host, color, categories, when)).map(jpegOf))
  const name = `saytyoxla-${host.replace(/[^\p{L}\p{N}.-]+/gu, '-')}.pdf`
  const file = new File([buildPdf(images) as BlobPart], name, { type: 'application/pdf' })

  // Browsers inside apps (Instagram, Facebook) ignore downloads but can pass a file to the share sheet
  const inApp = /; wv\)|Instagram|FBAN|FBAV/.test(navigator.userAgent)
  if (inApp && navigator.canShare?.({ files: [file] })) {
    try {
      await navigator.share({ files: [file], title: name })
      return
    } catch (e) {
      if (e instanceof DOMException && e.name === 'AbortError') return     // the visitor closed the share sheet
    }
  }
  saveFile(file)
}
