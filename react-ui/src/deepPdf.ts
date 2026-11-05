// The deep analysis as its own PDF, drawn in the visitor's browser like the ordinary report (pdf.ts).
// Nothing here is new information: every line comes from an answer of /api/deep, an unanswered part says so,
// and the report never claims that a site is safe.

import { actionPlan } from './chains'
import type { Changes, Chain, DeepItem, Level } from './chains'
import { d, fill } from './deepText'
import { LANG, t } from './i18n'
import { BOTTOM, COLOR, H, INK2, LINE, M, MUTED, Pages, W, drawFinding, drawLines, loadFonts, numberPages, roundRect, setFont, wrap } from './pdf'
import type { Ctx } from './pdf'
import type { Finding } from './types'

export const PUBLIC = ['surface', 'mail', 'tech', 'tls', 'reputation'] as const
export type ModuleId = typeof PUBLIC[number] | 'active'
export type DeepHost = { host: string; live: boolean; cname: string; flag: '' | 'takeover' | 'dangling' | 'sensitive' | 'private' }
export type DeepData = {
  hosts?: DeepHost[]; total?: number; software?: { name: string; version: string }[]; csp?: boolean | null; hsts?: boolean | null
  nameservers?: string[]; apex?: string; issuer?: string; checked?: string[]; safe_browsing?: string
  records?: { spf?: string[]; dmarc?: string[]; dmarc_parent?: string; mx?: string[] }
  checked_files?: number; checked_ports?: number
}
export type DeepResult = { module: ModuleId; host: string; items: DeepItem[]; data: DeepData }
export type DeepPart = { state: 'loading' | 'done' | 'error'; result?: DeepResult; error?: string }
export type DeepParts = Partial<Record<ModuleId, DeepPart>>
export type DeepReport = { host: string; when: string; parts: DeepParts; chains: Chain[]; changes: Changes | null }

const ORDER: Record<string, number> = { fail: 0, warn: 1, ok: 2, info: 3 }
const LEVEL_COLOR: Record<Level | 'none', string> = { critical: COLOR.fail, high: '#ea580c', medium: COLOR.warn, none: COLOR.ok }
// A part that answered, but with one of these inside, was not fully checked
const UNKNOWN = ['surface_unavailable', 'surface_partial', 'dns_unavailable', 'page_unavailable', 'page_blocked', 'osv_unavailable', 'https_unavailable', 'rep_unknown', 'mail_platform']

export const sortedItems = (items: DeepItem[]) => [...items].sort((a, b) => ORDER[a.status] - ORDER[b.status])

// On screen a note gives no fix; the report is the place for all of it
export function itemToFinding(item: DeepItem, allFixes = false): Finding {
  const words = d.items[item.id] || [item.id, '']
  const showFix = allFixes || item.status === 'fail' || item.status === 'warn'
  return { id: `deep-${item.id}`, status: item.status, title: fill(words[0], item.params), detail: fill(words[1], item.params), fix: showFix ? fill(words[2] || '', item.params) : '' } as Finding
}

export function problemTitle(key: string) {
  const [id, params] = key.split(/\|(.*)/s)
  const words = d.items[id]
  try {
    return words ? fill(words[0], JSON.parse(params)) : id
  } catch {
    return id
  }
}

export function factRows(result: DeepResult, detailed = false): [string, string][] {
  const { data } = result
  const rows: [string, string][] = []
  if (data.software?.length) rows.push([d.ui.software, data.software.map((s) => `${s.name}${s.version ? ` ${s.version}` : ''}`).join(', ')])
  if (data.records?.spf?.length) rows.push(['SPF', data.records.spf.join(' ')])
  if (data.records?.dmarc?.length) rows.push(['DMARC', data.records.dmarc.join(' ')])
  if (data.records?.mx?.length) rows.push(['MX', data.records.mx.join(', ')])
  if (data.nameservers?.length) rows.push([d.ui.nameservers, data.nameservers.join(', ')])
  if (data.checked?.length) rows.push([d.ui.lists, data.checked.join(', ')])
  if (detailed) {
    const word = (on: boolean) => (on ? d.pdf.yes : d.pdf.no)
    if (typeof data.csp === 'boolean') rows.push(['CSP', word(data.csp)])
    if (typeof data.hsts === 'boolean') rows.push(['HSTS', word(data.hsts)])
    if (data.apex) rows.push([d.pdf.apex, data.apex])
    if (data.issuer) rows.push([d.pdf.issuer, data.issuer])
    if (data.checked_files) rows.push([d.pdf.filesChecked, String(data.checked_files)])
    if (data.checked_ports) rows.push([d.pdf.portsChecked, String(data.checked_ports)])
  }
  return rows
}

export function partState(part: DeepPart | undefined): 'done' | 'partial' | 'failed' | 'notRun' {
  if (!part) return 'notRun'
  if (part.state !== 'done' || !part.result) return 'failed'
  return part.result.items.some((x) => UNKNOWN.includes(x.id)) ? 'partial' : 'done'
}

// ---------------------------------------------------------------- drawing
function paragraph(p: Pages, text: string, weight = 400, size = 24, color = INK2, x = M) {
  setFont(p.c, weight, size, color)
  const lines = wrap(p.c, text, W - M - x)
  const height = Math.round(size * 1.38)
  p.need(lines.length * height + 8)
  setFont(p.c, weight, size, color)
  p.y = drawLines(p.c, lines, x, p.y, height) + 8
}

function subheading(p: Pages, text: string) {
  p.need(90)
  setFont(p.c, 800, 26)
  p.c.fillText(text, M, p.y + 10)
  p.y += 52
}

function factTable(p: Pages, rows: [string, string][]) {
  const nameWidth = 270, x = M + nameWidth + 40, width = W - M - x - 24
  for (const [name, value] of rows) {
    setFont(p.c, 600, 22)
    const lines = wrap(p.c, value, width)
    const height = lines.length * 30 + 22
    p.need(height)
    const c = p.c
    roundRect(c, M, p.y, W - 2 * M, height, 8, '#f8fafc')
    setFont(c, 400, 21, MUTED)
    c.fillText(wrap(c, name, nameWidth)[0], M + 20, p.y + 12)
    setFont(c, 600, 22)
    drawLines(c, lines, x, p.y + 11, 30)
    p.y += height + 6
  }
  p.y += 10
}

function hostTable(p: Pages, hosts: DeepHost[]) {
  const columns = [M + 14, M + 500, M + 860]
  const widths = [472, 346, 200]
  const header = () => {
    const c = p.c
    roundRect(c, M, p.y, W - 2 * M, 42, 8, '#e8edf5')
    setFont(c, 700, 20, INK2)
    ;[d.pdf.hostName, d.pdf.pointsTo, d.pdf.state].forEach((text, i) => c.fillText(text, columns[i], p.y + 11))
    p.y += 46
  }
  p.need(100)
  header()
  for (const h of hosts) {
    const state = h.flag ? d.ui.flags[h.flag] : h.live ? d.pdf.working : d.ui.offline
    setFont(p.c, 400, 20)
    const name = wrap(p.c, h.host, widths[0])
    const target = wrap(p.c, h.cname || '–', widths[1])
    setFont(p.c, 700, 20)
    const label = wrap(p.c, state, widths[2])
    const height = Math.max(name.length, target.length, label.length) * 27 + 14
    if (p.y + height > BOTTOM) { p.add(); header() }
    const c = p.c
    setFont(c, 400, 20, h.live ? '#0f1b2d' : MUTED)
    drawLines(c, name, columns[0], p.y + 7, 27)
    setFont(c, 400, 20, MUTED)
    drawLines(c, target, columns[1], p.y + 7, 27)
    setFont(c, h.flag ? 700 : 400, 20, h.flag === 'takeover' ? COLOR.fail : h.flag ? COLOR.warn : MUTED)
    drawLines(c, label, columns[2], p.y + 7, 27)
    p.y += height
    c.strokeStyle = LINE
    c.lineWidth = 1
    c.beginPath(); c.moveTo(M, p.y); c.lineTo(W - M, p.y); c.stroke()
  }
  p.y += 20
}

function chainHeight(c: Ctx, chain: Chain, width: number) {
  const words = d.chains[chain.id]
  let h = 58
  setFont(c, 800, 27)
  h += wrap(c, fill(words.title, chain.params), width - 170).length * 36
  setFont(c, 400, 24)
  for (const text of [words.fact, words.could, words.fix]) h += 36 + wrap(c, fill(text, chain.params), width).length * 33
  return h
}

function drawChain(p: Pages, chain: Chain) {
  const words = d.chains[chain.id]
  if (!words) return
  const width = W - 2 * M - 60
  const height = chainHeight(p.c, chain, width)
  p.need(height + 16)
  const c = p.c, top = p.y, x = M + 34
  roundRect(c, M, top, W - 2 * M, height, 14, '#fff', LINE)
  c.fillStyle = LEVEL_COLOR[chain.level]
  c.beginPath(); c.roundRect(M, top, 10, height, [14, 0, 0, 14]); c.fill()
  setFont(c, 800, 27)
  let y = drawLines(c, wrap(c, fill(words.title, chain.params), width - 170), x, top + 24, 36)
  const level = d.ui.levels[chain.level].toLocaleUpperCase(LANG)
  setFont(c, 800, 19, LEVEL_COLOR[chain.level])
  c.fillText(level, W - M - 26 - c.measureText(level).width, top + 30)
  y += 10
  for (const [label, text] of [[d.ui.fact, words.fact], [d.ui.could, words.could], [d.ui.fix, words.fix]]) {
    setFont(c, 700, 19, MUTED)
    c.fillText(label, x, y + 6)
    setFont(c, 400, 24, INK2)
    y = drawLines(c, wrap(c, fill(text, chain.params), width), x, y + 32, 33) + 4
  }
  p.y = top + height + 16
}

function drawStep(p: Pages, number: number, title: string, fix: string, label: string, color: string) {
  const x = M + 66, width = W - M - x
  setFont(p.c, 700, 25)
  const heading = wrap(p.c, title, width - 150)
  setFont(p.c, 400, 23)
  const lines = fix ? wrap(p.c, fix, width) : []
  p.need(heading.length * 34 + lines.length * 31 + 28)
  const c = p.c, top = p.y
  c.beginPath(); c.arc(M + 24, top + 22, 22, 0, Math.PI * 2); c.fillStyle = color; c.fill()
  c.textAlign = 'center'
  setFont(c, 800, 22, '#fff')
  c.fillText(String(number), M + 24, top + 10)
  c.textAlign = 'left'
  setFont(c, 700, 25)
  let y = drawLines(c, heading, x, top + 4, 34)
  setFont(c, 800, 17, color)
  c.fillText(label, W - M - c.measureText(label).width, top + 12)
  setFont(c, 400, 23, INK2)
  y = drawLines(c, lines, x, y + 2, 31)
  p.y = y + 20
}

function drawCover(p: Pages, report: DeepReport, counts: Record<string, number>) {
  const c = p.c
  setFont(c, 800, 34)
  c.fillText('Sayt', M, p.y)
  const sayt = c.measureText('Sayt').width
  setFont(c, 800, 34, '#1d4ed8')
  c.fillText('Yoxla', M + sayt, p.y)
  p.y += 74
  setFont(c, 800, 50)
  p.y = drawLines(c, wrap(c, d.pdf.title, W - 2 * M), M, p.y, 62) + 8
  setFont(c, 700, 32, '#1d4ed8')
  p.y = drawLines(c, wrap(c, report.host, W - 2 * M), M, p.y, 42) + 6
  setFont(c, 400, 23, MUTED)
  c.fillText(`${d.pdf.date}: ${report.when}`, M, p.y)
  p.y += 52

  const level = (report.chains.length ? report.chains[0].level : 'none') as Level | 'none'
  const missing = PUBLIC.filter((id) => partState(report.parts[id]) === 'failed' || partState(report.parts[id]) === 'partial')
  const text = d.pdf.verdicts[level]
  const width = W - 2 * M - 60
  setFont(c, 600, 26)
  const lines = wrap(c, text, width)
  setFont(c, 400, 22)
  const extra = missing.length ? wrap(c, d.pdf.incomplete, width) : []
  const box = 76 + lines.length * 36 + extra.length * 31 + (extra.length ? 10 : 0)
  roundRect(c, M, p.y, W - 2 * M, box, 14, level === 'none' ? '#f0fdf4' : level === 'medium' ? '#fffbeb' : '#fef2f2')
  c.fillStyle = LEVEL_COLOR[level]
  c.beginPath(); c.roundRect(M, p.y, 10, box, [14, 0, 0, 14]); c.fill()
  setFont(c, 800, 19, LEVEL_COLOR[level])
  c.fillText(d.pdf.verdictTitle.toLocaleUpperCase(LANG), M + 34, p.y + 20)
  setFont(c, 600, 26)
  let y = drawLines(c, lines, M + 34, p.y + 52, 36)
  setFont(c, 400, 22, INK2)
  if (extra.length) y = drawLines(c, extra, M + 34, y + 8, 31)
  p.y += box + 22

  const statuses = ['fail', 'warn', 'ok', 'info'] as const
  const gap = 16, cell = (W - 2 * M - 3 * gap) / 4
  statuses.forEach((status, i) => {
    const x = M + i * (cell + gap)
    roundRect(c, x, p.y, cell, 106, 12, '#fff', LINE)
    setFont(c, 800, 42, COLOR[status])
    c.fillText(String(counts[status] || 0), x + 20, p.y + 14)
    setFont(c, 400, 19, MUTED)
    c.fillText(wrap(c, t.status[status], cell - 36)[0], x + 20, p.y + 70)
  })
  p.y += 130

  setFont(c, 800, 24)
  c.fillText(d.pdf.scope, M, p.y)
  p.y += 40
  for (const id of [...PUBLIC, 'active'] as ModuleId[]) {
    const state = partState(report.parts[id])
    setFont(c, 400, 23, INK2)
    c.fillText(d.ui.modules[id], M, p.y)
    const word = d.pdf.states[state]
    setFont(c, 700, 21, state === 'done' ? COLOR.ok : state === 'notRun' ? MUTED : COLOR.warn)
    c.fillText(word, W - M - c.measureText(word).width, p.y + 2)
    p.y += 35
  }
  p.y += 22
}

function drawContents(canvas: HTMLCanvasElement, top: number, entries: [string, number][]) {
  const c = canvas.getContext('2d') as Ctx
  let y = top
  setFont(c, 800, 24)
  c.fillText(d.pdf.contents, M, y)
  y += 40
  for (const [title, page] of entries) {
    setFont(c, 400, 23, INK2)
    c.fillText(title, M, y)
    const number = String(page)
    c.fillText(number, W - M - c.measureText(number).width, y)
    const from = M + c.measureText(title).width + 14, to = W - M - c.measureText(number).width - 14
    c.strokeStyle = LINE
    c.lineWidth = 2
    c.setLineDash([2, 8])
    c.beginPath(); c.moveTo(from, y + 22); c.lineTo(to, y + 22); c.stroke()
    c.setLineDash([])
    y += 35
  }
  setFont(c, 400, 20, MUTED)
  drawLines(c, wrap(c, d.pdf.confidential, W - 2 * M), M, y + 14, 28)
}

export function drawDeepReport(report: DeepReport): HTMLCanvasElement[] {
  const { parts, chains } = report
  const results = (Object.values(parts) as (DeepPart | undefined)[]).map((x) => x?.result).filter((r): r is DeepResult => !!r)
  const items = results.flatMap((r) => r.items)
  const counts = items.reduce<Record<string, number>>((all, x) => ({ ...all, [x.status]: (all[x.status] || 0) + 1 }), {})

  const p = new Pages()
  const entries: [string, number][] = []
  drawCover(p, report, counts)
  const contentsTop = p.y

  const section = (title: string) => {
    p.add()
    entries.push([title, p.canvases.length])
    setFont(p.c, 800, 36)
    p.y = drawLines(p.c, wrap(p.c, title, W - 2 * M), M, p.y, 46) + 12
    p.c.strokeStyle = '#1d4ed8'
    p.c.lineWidth = 4
    p.c.beginPath(); p.c.moveTo(M, p.y); p.c.lineTo(M + 90, p.y); p.c.stroke()
    p.y += 22
  }

  section(d.pdf.plan)
  const steps = actionPlan(chains, items)
  paragraph(p, steps.length ? d.pdf.planLead : d.pdf.planEmpty)
  p.y += 12
  steps.forEach((step, i) => {
    if ('chain' in step) {
      const words = d.chains[step.chain.id]
      if (words) drawStep(p, i + 1, fill(words.title, step.chain.params), fill(words.fix, step.chain.params), d.ui.levels[step.chain.level].toLocaleUpperCase(LANG), LEVEL_COLOR[step.chain.level])
    } else {
      const words = d.items[step.item.id]
      if (words) drawStep(p, i + 1, fill(words[0], step.item.params), fill(words[2] || '', step.item.params), t.status[step.item.status].toLocaleUpperCase(LANG), COLOR[step.item.status])
    }
  })

  if (chains.length) {
    section(d.pdf.scenarios)
    paragraph(p, d.pdf.scenariosLead)
    p.y += 10
    chains.forEach((chain) => drawChain(p, chain))
  }

  if (report.changes) {
    const { since, newHosts, newProblems, solved } = report.changes
    p.y += 10
    subheading(p, d.ui.since(since))
    if (!newHosts.length && !newProblems.length && !solved.length) paragraph(p, d.ui.noChange)
    if (newHosts.length) paragraph(p, `${d.ui.newHosts}: ${newHosts.join(', ')}`)
    if (newProblems.length) paragraph(p, `${d.ui.newProblems}: ${newProblems.map(problemTitle).join('; ')}`)
    if (solved.length) paragraph(p, `${d.ui.solved}: ${solved.map(problemTitle).join('; ')}`)
  }

  for (const id of [...PUBLIC, 'active'] as ModuleId[]) {
    const part = parts[id]
    section(d.ui.modules[id])
    paragraph(p, d.pdf.intro[id], 400, 24, MUTED)
    p.y += 10
    if (id === 'active' && !part) { paragraph(p, d.pdf.activeNotRun, 600); continue }
    if (!part?.result) { paragraph(p, d.pdf.partFailed, 600, 24, COLOR.warn); continue }
    const rows = factRows(part.result, true)
    if (rows.length) factTable(p, rows)
    if (part.result.data.hosts?.length) {
      subheading(p, `${d.ui.hosts} (${part.result.data.hosts.length})`)
      hostTable(p, part.result.data.hosts)
    }
    sortedItems(part.result.items).forEach((item) => drawFinding(p, itemToFinding(item, true)))
    if (part.result.data.safe_browsing) {
      p.y += 8
      paragraph(p, d.ui.safeBrowsing, 600)
      paragraph(p, part.result.data.safe_browsing, 400, 21, '#1d4ed8')
    }
  }

  section(d.pdf.method)
  subheading(p, d.pdf.sourcesTitle)
  d.pdf.sources.forEach((text) => paragraph(p, `•  ${text}`))
  p.y += 10
  subheading(p, d.pdf.limitsTitle)
  d.pdf.limits.forEach((text) => paragraph(p, `•  ${text}`))

  section(d.pdf.glossary)
  for (const [term, meaning] of d.pdf.terms) {
    setFont(p.c, 400, 23)
    p.need(wrap(p.c, meaning, W - 2 * M).length * 32 + 52)
    setFont(p.c, 800, 24)
    p.c.fillText(term, M, p.y)
    p.y += 34
    paragraph(p, meaning, 400, 23)
    p.y += 6
  }

  // Last, because only now is it known where each section begins. drawCover left room for it on the first page.
  if (contentsTop + 40 + entries.length * 35 + 60 < H - 110) drawContents(p.canvases[0], contentsTop, entries)
  numberPages(p.canvases)
  return p.canvases
}

export function deepPdfName(host: string) {
  return `saytyoxla-${d.pdf.fileName}-${host.replace(/[^\p{L}\p{N}.-]+/gu, '-')}.pdf`
}

export async function renderDeepReport(report: DeepReport) {
  await loadFonts()
  return drawDeepReport(report)
}
