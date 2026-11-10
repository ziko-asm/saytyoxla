// Builds the report as a PDF file in the visitor's browser and downloads it. Nothing goes through the
// system print dialog (phones need a "printer" chosen there) and nothing is sent to a server.
// Each page is drawn on a canvas and stored as a JPEG, so every letter (ə, ş, я) looks as it does on screen.
// Over the picture lies the same text, invisible: it is what makes the report searchable, selectable and
// readable by a screen reader. Its font has no shapes (nothing is ever drawn with it), so it is 620 bytes.

import type { Finding, Report, Status } from './types'
import { LANG, t } from './i18n'

export const W = 1240, H = 1754            // A4 at 150 dpi
const PT_W = 595.28, PT_H = 841.89  // A4 in PDF points
export const M = 80, BOTTOM = H - 110
const FONT = 'Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif'
export const INK = '#0f1b2d', INK2 = '#3d4b60', MUTED = '#5b6779', LINE = '#e3e8f0'
export const COLOR: Record<Status, string> = { fail: '#dc2626', warn: '#b45309', ok: '#047857', info: '#64748b' }

export type Ctx = CanvasRenderingContext2D

export function setFont(c: Ctx, weight: number, size: number, color = INK) {
  c.font = `${weight} ${size}px ${FONT}`
  c.fillStyle = color
}

// Lines that fit maxWidth; a word too long for one line (an address) is cut
export function wrap(c: Ctx, text: string, maxWidth: number): string[] {
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

export function drawLines(c: Ctx, lines: string[], x: number, y: number, height: number) {
  lines.forEach((l, i) => c.fillText(l, x, y + i * height))
  return y + lines.length * height
}

export function roundRect(c: Ctx, x: number, y: number, w: number, h: number, r: number, fill: string, stroke?: string) {
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

// One string as it was drawn: where (canvas pixels, left end of the baseline), how tall and how wide
export type TextRun = { text: string; x: number; y: number; size: number; width: number }
const RUNS = new WeakMap<HTMLCanvasElement, TextRun[]>()
export const runsOf = (canvas: HTMLCanvasElement) => RUNS.get(canvas) || []
const BASELINE: Record<string, number> = { top: 0.8, hanging: 0.8, middle: 0.3, alphabetic: 0, ideographic: -0.1, bottom: -0.2 }

// Every fillText on this canvas is also written down. getContext returns the same object each time,
// so text added later (page numbers, the table of contents) is recorded too.
function recordText(canvas: HTMLCanvasElement, c: Ctx) {
  const runs: TextRun[] = []
  RUNS.set(canvas, runs)
  const draw = c.fillText.bind(c)
  c.fillText = (text: string, x: number, y: number, maxWidth?: number) => {
    if (maxWidth === undefined) draw(text, x, y)
    else draw(text, x, y, maxWidth)
    const size = parseFloat(/(\d+(?:\.\d+)?)px/.exec(c.font)?.[1] || '0')
    const width = c.measureText(text).width
    if (!text.trim() || !size || !width) return
    const left = c.textAlign === 'center' ? x - width / 2 : c.textAlign === 'right' || c.textAlign === 'end' ? x - width : x
    runs.push({ text, x: left, y: y + size * (BASELINE[c.textBaseline] ?? 0), size, width })
  }
}

export class Pages {
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
    recordText(canvas, c)
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

export function drawFinding(p: Pages, f: Finding) {
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
  numberPages(p.canvases)
  return p.canvases
}

export function numberPages(canvases: HTMLCanvasElement[]) {
  canvases.forEach((canvas, i) => {
    const c = canvas.getContext('2d') as Ctx
    setFont(c, 400, 20, MUTED)
    c.fillText(`SaytYoxla · ${window.location.host}`, M, H - 70)
    const page = `${i + 1} / ${canvases.length}`
    c.fillText(page, W - M - c.measureText(page).width, H - 70)
  })
}

function jpegOf(canvas: HTMLCanvasElement): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (!blob) { reject(new Error('no image')); return }
      blob.arrayBuffer().then((b) => resolve(new Uint8Array(b)), reject)
    }, 'image/jpeg', 0.9)
  })
}

// A font with no shapes: two empty glyphs, every character 500 units wide (react-ui/README.md says how it was made)
const BLANK_FONT = 'AAEAAAAKAIAAAwAgT1MvMkUAQ7AAAAEoAAAAYGNtYXAADABzAAABkAAAADRnbHlmAAAAAAAAAcwAAAABaGVhZC1IbloAAACsAAAANmhoZWEDIgEuAAAA5AAAACRobXR4AfQAAAAAAYgAAAAGbG9jYQAAAAAAAAHEAAAABm1heHAAAwACAAABCAAAACBuYW1lItMETgAAAdAAAABycG9zdAAHAAAAAAJEAAAAJgABAAAAAQAAcQktBl8PPPUAAwPoAAAAAOcZFr0AAAAA5xkWvQAAAAAAAAAAAAAAAwACAAAAAAAAAAEAAAMg/zgAAAH0AAAAAAAAAAEAAAAAAAAAAAAAAAAAAAABAAEAAAACAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAwH0AZAABQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAPz8/PwAAACAAIAMg/zgAAAMgAMgAAAAAAAAAAAAAAAAAAAAgAAAB9AAAAAAAAAAAAAIAAAADAAAAFAADAAEAAAAUAAQAIAAAAAQABAABAAAAIP//AAAAIP///+EAAQAAAAAAAAAAAAAAAAAAAAAAAAAEADYAAQAAAAAAAQANAAAAAQAAAAAAAgAHAA0AAwABBAkAAQAaABQAAwABBAkAAgAOAC5TYXl0WW94bGFUZXh0UmVndWxhcgBTAGEAeQB0AFkAbwB4AGwAYQBUAGUAeAB0AFIAZQBnAHUAbABhAHIAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAADAAA='
const TEXT_WIDTH = 0.5      // of the font size, per UTF-16 unit: what the blank font says

const hex16 = (text: string) => [...text].flatMap((ch) => [...Array(ch.length)].map((_, i) => ch.charCodeAt(i).toString(16).padStart(4, '0'))).join('').toUpperCase()
const num = (n: number) => String(Math.round(n * 100) / 100)

// The invisible text of one page, in PDF units (points, y upwards). Each run is stretched to the width it has in the picture.
export function textLayer(runs: TextRun[], scale: number, pageHeight: number) {
  if (!runs.length) return ''
  const lines = runs.map((r) => {
    const size = r.size * scale
    const stretch = 100 * r.width * scale / (r.text.length * TEXT_WIDTH * size)
    return `/F0 ${num(size)} Tf ${num(stretch)} Tz 1 0 0 1 ${num(r.x * scale)} ${num(pageHeight - r.y * scale)} Tm <${hex16(r.text)}> Tj`
  })
  return `\nBT 3 Tr\n${lines.join('\n')}\nET`
}

export type PdfInfo = { title?: string; lang?: string }

// A minimal PDF: one page per image (objects: 1 catalog, 2 page list, then page + content + image for each).
// With `texts` (the strings drawn on each page) five more objects follow: the blank font and its tables.
export function buildPdf(images: Uint8Array[], width = W, height = H, texts: TextRun[][] = [], info: PdfInfo = {}): Uint8Array {
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
  const stream = (dict: string, body: string | Uint8Array) => {
    put(`<< ${dict}/Length ${typeof body === 'string' ? encoder.encode(body).length : body.length} >>\nstream\n`)
    put(body)
    put('\nendstream')
  }

  const hasText = texts.some((runs) => runs.length)
  const font = 3 + images.length * 3          // first of the font's five objects
  const infoAt = font + (hasText ? 5 : 0)
  const hasInfo = !!info.title
  put('%PDF-1.4\n')
  const kids = images.map((_, i) => `${3 + i * 3} 0 R`).join(' ')
  object(1, () => put(`<< /Type /Catalog /Pages 2 0 R${info.lang ? ` /Lang (${info.lang.replace(/[^A-Za-z-]/g, '')})` : ''} >>`))
  object(2, () => put(`<< /Type /Pages /Kids [${kids}] /Count ${images.length} >>`))
  images.forEach((image, i) => {
    const page = 3 + i * 3
    const content = `q ${PT_W} 0 0 ${PT_H} 0 0 cm /Im0 Do Q` + textLayer(texts[i] || [], PT_W / width, PT_H)
    object(page, () => put(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PT_W} ${PT_H}] `
      + `/Resources << /XObject << /Im0 ${page + 2} 0 R >>${hasText ? ` /Font << /F0 ${font} 0 R >>` : ''} >> /Contents ${page + 1} 0 R >>`))
    object(page + 1, () => stream('', content))
    object(page + 2, () => stream(`/Type /XObject /Subtype /Image /Width ${width} /Height ${height} /ColorSpace /DeviceRGB `
      + '/BitsPerComponent 8 /Filter /DCTDecode ', image))
  })
  if (hasText) {
    const file = Uint8Array.from(atob(BLANK_FONT), (ch) => ch.charCodeAt(0))
    // Codes are UTF-16 units, so the map back to characters is one range: each code means itself
    const toUnicode = '/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n'
      + '/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n'
      + '1 beginbfrange\n<0000> <FFFF> <0000>\nendbfrange\nendcmap\nCMapName currentdict /CMap defineresource pop\nend\nend'
    object(font, () => put(`<< /Type /Font /Subtype /Type0 /BaseFont /SaytYoxlaText /Encoding /Identity-H /DescendantFonts [${font + 1} 0 R] /ToUnicode ${font + 4} 0 R >>`))
    object(font + 1, () => put('<< /Type /Font /Subtype /CIDFontType2 /BaseFont /SaytYoxlaText /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> '
      + `/FontDescriptor ${font + 2} 0 R /DW ${TEXT_WIDTH * 1000} /CIDToGIDMap /Identity >>`))
    object(font + 2, () => put('<< /Type /FontDescriptor /FontName /SaytYoxlaText /Flags 4 /FontBBox [0 -200 500 800] /ItalicAngle 0 /Ascent 800 /Descent -200 '
      + `/CapHeight 700 /StemV 80 /FontFile2 ${font + 3} 0 R >>`))
    object(font + 3, () => stream(`/Length1 ${file.length} `, file))
    object(font + 4, () => stream('', toUnicode))
  }
  if (hasInfo) object(infoAt, () => put(`<< /Title <FEFF${hex16(info.title || '')}> /Producer (SaytYoxla) >>`))

  const count = infoAt + (hasInfo ? 1 : 0)
  const xref = size
  put(`xref\n0 ${count}\n0000000000 65535 f \n`)
  for (let n = 1; n < count; n++) put(`${String(offsets[n]).padStart(10, '0')} 00000 n \n`)
  put(`trailer\n<< /Size ${count} /Root 1 0 R${hasInfo ? ` /Info ${infoAt} 0 R` : ''} >>\nstartxref\n${xref}\n%%EOF\n`)

  const out = new Uint8Array(size)
  let at = 0
  for (const part of parts) { out.set(part, at); at += part.length }
  return out
}

export function saveFile(file: File) {
  const link = document.createElement('a')
  link.href = URL.createObjectURL(file)
  link.download = file.name
  document.body.append(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(link.href), 60_000)
}

export async function loadFonts() {
  try {
    await Promise.all(['400 24px Inter', '600 24px Inter', '700 24px Inter', '800 24px Inter'].map((f) => document.fonts.load(f, 'əşğ')))
  } catch { /* the system font is good enough */ }
}

async function renderPages(report: Report, host: string, color: string, categories: string[], when: string) {
  await loadFonts()
  return drawPages(report, host, color, categories, when)
}

// The same pages for showing on screen. Phones often turn an opened PDF into a download, so "View" uses images.
export async function reportPageImages(report: Report, host: string, color: string, categories: string[], when: string) {
  const pages = await renderPages(report, host, color, categories, when)
  return pages.map((canvas) => canvas.toDataURL('image/jpeg', 0.9))
}

export async function downloadReportPdf(report: Report, host: string, color: string, categories: string[], when: string) {
  await deliverPdf(await renderPages(report, host, color, categories, when), `saytyoxla-${host.replace(/[^\p{L}\p{N}.-]+/gu, '-')}.pdf`)
}

export async function deliverPdf(canvases: HTMLCanvasElement[], name: string) {
  const images = await Promise.all(canvases.map(jpegOf))
  const info = { title: name.replace(/\.pdf$/, ''), lang: LANG }
  const file = new File([buildPdf(images, W, H, canvases.map(runsOf), info) as BlobPart], name, { type: 'application/pdf' })

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
