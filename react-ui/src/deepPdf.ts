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
export type ModuleId = typeof PUBLIC[number] | 'active' | 'crawl' | 'probe'
export type DeepHost = { host: string; live: boolean; cname: string; ips?: string[]; flag: '' | 'takeover' | 'dangling' | 'dead' | 'sensitive' | 'private' }
export type DeepData = {
  hosts?: DeepHost[]; total?: number; software?: { name: string; version: string }[]; csp?: boolean | null; hsts?: boolean | null
  nameservers?: string[]; apex?: string; issuer?: string; checked?: string[]; safe_browsing?: string
  records?: { spf?: string[]; dmarc?: string[]; dmarc_parent?: string; mx?: string[] }
  checked_files?: number; checked_ports?: number
  certs?: { count: number; active: number; first: string; last: string; next_expiry: string; issuers: string[] }
  spf_lookups?: number; spf_limit?: number; spf_steps?: { domain: string; depth: number; lookups: number }[]; dmarc_tags?: Record<string, string>
  dkim?: { selector: string; bits: number | null }[]; mx_hosts?: { priority: number; host: string; ips: string[] }[]; mta_sts?: string | null; tls_rpt?: string
  headers?: { name: string; value: string }[]; cookies?: { name: string; secure: boolean; httponly: boolean; samesite: string }[]
  libs?: { name: string; version: string; known: boolean; count: number; high: number; ids: string[]; fixed: string }[]
  page?: { final_url: string; status: number; ms: number; bytes: number; redirects: number }
  cert?: { subject?: string; issuer?: string; issuer_cn?: string; from?: string; to?: string; days_left?: number; names?: string[]; cipher?: string; bits?: number }
  protocols?: Record<string, boolean | null>; addresses?: string[]; addresses6?: string[]; soa?: { primary?: string; serial?: number }; caa?: string[]; dnssec?: boolean
  domain_record?: { registrar: string; created: string; updated: string; expires: string; status: string[] }
  ip_record?: { ip: string; network: string; country: string; ptr: string }
  table?: { list: string; target: string; state: 'clean' | 'listed' | 'unavailable' }[]
  cves?: { name: string; version: string; count: number; high: number; ids: string[] }[]
  plugins?: { slug: string; version: string; latest: string; updated: string; closed: boolean; vulns: number | null }[]
  theme?: string; wp_latest?: string; outside?: string[]; unsigned?: string[]; forms?: { total: number; passwords: number }; security_txt?: boolean
  pages?: { path: string; status: number; ms: number }[]; cut_short?: boolean
}
export type DeepResult = { module: ModuleId; host: string; items: DeepItem[]; data: DeepData }
export type DeepPart = { state: 'loading' | 'done' | 'error'; result?: DeepResult; error?: string }
export type DeepParts = Partial<Record<ModuleId, DeepPart>>
export type DeepReport = { host: string; when: string; parts: DeepParts; chains: Chain[]; changes: Changes | null }

const ORDER: Record<string, number> = { fail: 0, warn: 1, ok: 2, info: 3 }
const LEVEL_COLOR: Record<Level | 'none', string> = { critical: COLOR.fail, high: '#ea580c', medium: COLOR.warn, none: COLOR.ok }
// A part that answered, but with one of these inside, was not fully checked
const UNKNOWN = ['active_partial', 'surface_unavailable', 'surface_partial', 'dns_unavailable', 'page_unavailable', 'page_blocked', 'osv_unavailable', 'https_unavailable', 'rep_unknown', 'mail_platform']

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

export function factRows(result: DeepResult): [string, string][] {
  const { data } = result
  const rows: [string, string][] = []
  if (data.software?.length) rows.push([d.ui.software, data.software.map((s) => `${s.name}${s.version ? ` ${s.version}` : ''}`).join(', ')])
  if (data.records?.spf?.length) rows.push(['SPF', data.records.spf.join(' ')])
  if (data.records?.dmarc?.length) rows.push(['DMARC', data.records.dmarc.join(' ')])
  if (data.records?.mx?.length) rows.push(['MX', data.records.mx.join(', ')])
  if (data.nameservers?.length) rows.push([d.ui.nameservers, data.nameservers.join(', ')])
  if (data.checked?.length) rows.push([d.ui.lists, data.checked.join(', ')])
  return rows
}

// Ready-made records, built from what this site's own answers say
export type ReadyFix = { id: string; where: string; code: string }
const CAA_OF: [RegExp, string][] = [[/let'?s encrypt/i, 'letsencrypt.org'], [/google trust/i, 'pki.goog'], [/digicert/i, 'digicert.com'], [/sectigo|zerossl/i, 'sectigo.com'], [/globalsign/i, 'globalsign.com'], [/amazon/i, 'amazon.com']]
const HEADER_FIX: Record<string, string> = {
  'strict-transport-security': 'Strict-Transport-Security: max-age=31536000',
  'content-security-policy': "Content-Security-Policy-Report-Only: default-src 'self'",
  'x-frame-options': 'X-Frame-Options: SAMEORIGIN',
  'x-content-type-options': 'X-Content-Type-Options: nosniff',
  'referrer-policy': 'Referrer-Policy: strict-origin-when-cross-origin',
  'permissions-policy': 'Permissions-Policy: camera=(), microphone=(), geolocation=()',
}

// The owner's DMARC reports already go to a box that exists; an invented address may not
const reportBox = (rua: unknown) => String(rua || '').split(',').map((x) => x.trim()).find((x) => /^mailto:[^\s@!]+@[^\s@!]+$/i.test(x)) || ''

export function readyFixes(parts: DeepParts): ReadyFix[] {
  const fixes: ReadyFix[] = []
  const mail = parts.mail?.result
  const has = (result: DeepResult | undefined, id: string) => !!result?.items.some((x) => x.id === id)
  if (mail) {
    const domain = mail.host
    const tags = mail.data.dmarc_tags || {}
    const open = has(mail, 'spoof_open'), partial = has(mail, 'spoof_partial')
    if (open || partial || has(mail, 'dmarc_no_reports')) {
      // Without reports nobody can see whose own mail a stricter policy would stop, so reports come first
      const policy = !tags.p ? 'none' : open && tags.rua ? 'quarantine' : tags.p
      const owner = mail.data.records?.dmarc_parent || domain
      fixes.push({ id: 'dmarc', where: fill(d.pdf.x.dnsTxt, { name: `_dmarc.${owner}` }), code: `v=DMARC1; p=${policy}; rua=${tags.rua || `mailto:dmarc@${owner}`}` })
    }
    const spf = mail.data.records?.spf?.[0]
    if (spf && (has(mail, 'spf_pass_all') || has(mail, 'spf_neutral'))) fixes.push({ id: 'spf', where: fill(d.pdf.x.dnsTxt, { name: domain }), code: spf.replace(/\S+$/, '~all') })
    else if (mail.items.some((x) => x.id === 'spf_missing' && x.status === 'fail')) fixes.push({ id: 'spf', where: fill(d.pdf.x.dnsTxt, { name: domain }), code: 'v=spf1 mx ~all' })
    if (has(mail, 'tls_rpt_missing')) fixes.push({ id: 'tlsRpt', where: fill(d.pdf.x.dnsTxt, { name: `_smtp._tls.${domain}` }), code: `v=TLSRPTv1; rua=${reportBox(tags.rua) || `mailto:tlsrpt@${domain}`}` })
  }
  const tls = parts.tls?.result
  if (tls && has(tls, 'caa_missing')) {
    const known = CAA_OF.find(([pattern]) => pattern.test(tls.data.cert?.issuer || tls.data.issuer || ''))
    if (known) fixes.push({ id: 'caa', where: fill(d.pdf.x.dnsCaa, { name: tls.data.apex || tls.host }), code: `0 issue "${known[1]}"` })
  }
  for (const header of parts.tech?.result?.data.headers || []) {
    if (!header.value && HEADER_FIX[header.name]) fixes.push({ id: header.name, where: d.pdf.x.header, code: HEADER_FIX[header.name] })
  }
  return fixes
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

function factTable(p: Pages, title: string, rows: [string, string | undefined][]) {
  const known = rows.filter((row): row is [string, string] => !!row[1])
  if (!known.length) return
  subheading(p, title)
  const nameWidth = 300, x = M + nameWidth + 34, width = W - M - x - 20
  for (const [name, value] of known) {
    setFont(p.c, 600, 22)
    const lines = wrap(p.c, value, width)
    setFont(p.c, 400, 21)
    const names = wrap(p.c, name, nameWidth)
    const height = Math.max(lines.length * 30, names.length * 28) + 18
    p.need(height)
    const c = p.c
    roundRect(c, M, p.y, W - 2 * M, height, 8, '#f8fafc')
    setFont(c, 400, 21, MUTED)
    drawLines(c, names, M + 18, p.y + 10, 28)
    setFont(c, 600, 22)
    drawLines(c, lines, x, p.y + 9, 30)
    p.y += height + 5
  }
  p.y += 12
}

type Cell = string | { text: string; color?: string; weight?: number }

function table(p: Pages, title: string, headers: string[], widths: number[], rows: Cell[][]) {
  if (!rows.length) return
  const total = widths.reduce((a, b) => a + b, 0)
  const columns = widths.map((_, i) => M + 14 + (W - 2 * M - 14) * widths.slice(0, i).reduce((a, b) => a + b, 0) / total)
  const room = widths.map((width) => (W - 2 * M - 14) * width / total - 16)
  const header = () => {
    const c = p.c
    roundRect(c, M, p.y, W - 2 * M, 42, 8, '#e8edf5')
    setFont(c, 700, 20, INK2)
    headers.forEach((text, i) => c.fillText(wrap(c, text, room[i])[0], columns[i], p.y + 11))
    p.y += 46
  }
  if (title) subheading(p, title)
  p.need(110)
  header()
  for (const row of rows) {
    const cells = row.map((cell) => (typeof cell === 'string' ? { text: cell } : cell))
    const lines = cells.map((cell, i) => {
      setFont(p.c, cell.weight || 400, 21)
      return wrap(p.c, cell.text || '–', room[i])
    })
    const height = Math.max(...lines.map((x) => x.length)) * 28 + 14
    if (p.y + height > BOTTOM) { p.add(); header() }
    const c = p.c
    cells.forEach((cell, i) => {
      setFont(c, cell.weight || 400, 21, cell.color || '#0f1b2d')
      drawLines(c, lines[i], columns[i], p.y + 7, 28)
    })
    p.y += height
    c.strokeStyle = LINE
    c.lineWidth = 1
    c.beginPath(); c.moveTo(M, p.y); c.lineTo(W - M, p.y); c.stroke()
  }
  p.y += 22
}

const good = (text: string): Cell => ({ text, color: COLOR.ok, weight: 700 })
const bad = (text: string): Cell => ({ text, color: COLOR.fail, weight: 700 })
const soft = (text: string): Cell => ({ text, color: COLOR.warn, weight: 700 })
const dim = (text: string): Cell => ({ text, color: MUTED })

function hostTable(p: Pages, hosts: DeepHost[]) {
  table(p, `${d.ui.hosts} (${hosts.length})`, [d.pdf.hostName, d.pdf.pointsTo, d.pdf.state], [46, 34, 20], hosts.map((h) => [
    h.live ? h.host : dim(h.host),
    dim(h.cname || h.ips?.join(', ') || ''),
    h.flag === 'takeover' ? bad(d.ui.flags.takeover) : h.flag ? soft(d.ui.flags[h.flag]) : h.live ? good(d.pdf.working) : dim(d.ui.offline),
  ]))
}

function drawFix(p: Pages, fix: ReadyFix) {
  const words = d.pdf.fixes[fix.id]
  if (!words) return
  const width = W - 2 * M - 40
  setFont(p.c, 400, 22)
  const why = wrap(p.c, words[1], W - 2 * M)
  p.c.font = '500 22px Consolas, Menlo, monospace'
  const code = wrap(p.c, fix.code, width)
  p.need(44 + why.length * 30 + 32 + code.length * 30 + 44)
  const c = p.c
  setFont(c, 700, 25)
  c.fillText(words[0], M, p.y)
  p.y += 36
  setFont(c, 400, 22, INK2)
  p.y = drawLines(c, why, M, p.y, 30) + 2
  setFont(c, 600, 19, MUTED)
  c.fillText(fix.where, M, p.y + 2)
  p.y += 30
  roundRect(c, M, p.y, W - 2 * M, code.length * 30 + 24, 10, '#f1f5f9', LINE)
  c.font = '500 22px Consolas, Menlo, monospace'
  c.fillStyle = '#0f1b2d'
  p.y = drawLines(c, code, M + 20, p.y + 12, 30) + 34
}

function moduleDetails(p: Pages, id: ModuleId, result: DeepResult) {
  const { data } = result
  const x = d.pdf.x
  if (id === 'surface') {
    const certs = data.certs
    if (certs) {
      factTable(p, x.certLog, [[x.certCount, String(certs.count)], [x.certActive, String(certs.active)], [x.certFirst, certs.first], [x.certLast, certs.last], [x.certNext, certs.next_expiry], [x.certIssuers, certs.issuers.join(', ')]])
    }
    if (data.hosts?.length) hostTable(p, data.hosts)
    else if (certs) paragraph(p, x.hostsNone)
  }
  if (id === 'mail') {
    factTable(p, d.pdf.x.mailExtras, [['SPF', data.records?.spf?.join(' ')], ['DMARC', data.records?.dmarc?.join(' ')], [x.mtaSts, data.mx_hosts?.length ? data.mta_sts || x.absent : undefined], [x.tlsRpt, data.mx_hosts?.length ? data.tls_rpt || x.absent : undefined]])
    table(p, data.spf_lookups === undefined ? '' : `${x.spfTree}. ${fill(x.spfTotal, { count: data.spf_lookups, limit: data.spf_limit })}`, [x.spfDomain, x.spfOwn], [80, 20],
      (data.spf_steps || []).map((step) => [`${'— '.repeat(step.depth)}${step.domain}`, String(step.lookups)]))
    table(p, x.dmarcTable, [x.tag, x.value, x.meaning], [12, 30, 58], Object.entries(data.dmarc_tags || {}).map(([tag, value]) => [{ text: tag, weight: 700 }, value, dim(d.pdf.tags[tag] || '')]))
    table(p, x.dkimTable, [x.selector, x.keySize], [60, 40], (data.dkim || []).map((key) => [key.selector, key.bits === null ? x.unknown : key.bits <= 1024 ? soft(`${key.bits} bit`) : good(`${key.bits} bit`)]))
    table(p, x.mxTable, [x.priority, x.server, x.address], [12, 50, 38], (data.mx_hosts || []).map((mx) => [String(mx.priority), mx.host, dim(mx.ips.join(', '))]))
  }
  if (id === 'tech') {
    const page = data.page
    if (page) factTable(p, x.pageTable, [[x.finalUrl, page.final_url], [x.status, String(page.status)], [x.time, `${page.ms} ms`], [x.size, `${Math.round(page.bytes / 1024)} KB`], [x.redirects, String(page.redirects)], [d.ui.software, data.software?.map((s) => `${s.name}${s.version ? ` ${s.version}` : ''}`).join(', ')]])
    table(p, x.headersTable, [x.headerName, d.pdf.state, x.meaning], [38, 14, 48], (data.headers || []).map((h) => [h.name, h.value ? good(x.present) : soft(x.absent), dim(d.pdf.headerDesc[h.name] || '')]))
    if (data.headers) {
      if (data.cookies?.length) table(p, x.cookiesTable, [x.cookie, 'Secure', 'HttpOnly', 'SameSite'], [46, 16, 18, 20], data.cookies.map((k) => [k.name, k.secure ? good(d.pdf.yes) : soft(d.pdf.no), k.httponly ? good(d.pdf.yes) : soft(d.pdf.no), k.samesite || dim('–')]))
      else { subheading(p, x.cookiesTable); paragraph(p, x.cookiesNone) }
    }
    factTable(p, x.formsLine, [[x.formsLine, data.forms ? fill(x.formsValue, data.forms) : ''], [x.securityTxt, data.security_txt === undefined ? '' : data.security_txt ? d.pdf.yes : d.pdf.no], [x.theme, data.theme], [x.wpLatest, data.wp_latest]])
    table(p, x.cveTable, [x.program, x.version, x.cveCount, x.examples], [20, 14, 18, 48], (data.cves || []).map((row) => [row.name, row.version, row.high ? bad(`${row.count} (${row.high})`) : soft(`${row.count} (0)`), dim(row.ids.join(', '))]))
    table(p, x.pluginsTable, [x.plugin, x.version, x.latest, x.updated, d.pdf.state], [34, 14, 14, 18, 20], (data.plugins || []).map((row) => [
      row.slug, row.version || '–', row.latest || '–', dim(row.updated || '–'),
      row.closed ? bad(x.closed) : row.vulns ? bad(`CVE ${row.vulns}`) : row.version && row.latest && row.version !== row.latest ? soft(row.version) : good('OK'),
    ]))
    table(p, x.outsideTable, [x.server, x.signed], [70, 30], (data.outside || []).map((host) => [host, data.unsigned?.includes(host) ? soft(d.pdf.no) : good(d.pdf.yes)]))
    if (data.libs?.length) {
      table(p, x.libsTable, [x.library, x.version, x.weaknesses, x.fixedIn], [30, 18, 30, 22], data.libs.map((lib) => [lib.name, lib.version, !lib.known ? dim(x.notAsked) : lib.count ? (lib.high ? bad : soft)(`${lib.count} (${lib.high})`) : good('0'), lib.fixed || '–']))
    } else if (data.headers) { subheading(p, x.libsTable); paragraph(p, x.libsNone) }
  }
  if (id === 'tls') {
    const cert = data.cert
    if (cert?.subject || cert?.to) {
      factTable(p, x.certTable, [[x.certSubject, cert.subject], [x.certBy, [cert.issuer, cert.issuer_cn].filter(Boolean).join(', ')], [x.certFrom, cert.from], [x.certTo, cert.to], [x.certDays, cert.days_left === undefined ? '' : String(cert.days_left)], [x.certNames, cert.names?.join(', ')], [x.certCipher, cert.cipher ? `${cert.cipher} (${cert.bits} bit)` : '']])
    } else if (cert) { subheading(p, x.certTable); paragraph(p, x.certNone) }
    table(p, x.protoTable, [x.protocol, d.pdf.state], [50, 50], Object.entries(data.protocols || {}).sort().map(([name, on]) => {
      const old = name === 'TLS 1.0' || name === 'TLS 1.1'
      return [name, on === null ? dim(x.unknown) : on ? (old ? soft(x.accepted) : good(x.accepted)) : (old ? good(x.refused) : dim(x.refused))]
    }))
    factTable(p, x.dnsTable, [['A', data.addresses?.join(', ')], ['AAAA', data.addresses6?.join(', ')], ['NS', data.nameservers?.join(', ')], ['SOA', data.soa?.primary ? `${data.soa.primary}, ${data.soa.serial}` : ''], ['CAA', data.caa?.join(', ')], ['DNSSEC', data.dnssec === undefined ? '' : data.dnssec ? d.pdf.yes : d.pdf.no], [x.ptr, data.ip_record?.ptr], [x.network, data.ip_record?.network], [x.country, data.ip_record?.country]])
    const reg = data.domain_record
    if (reg?.expires || reg?.registrar) factTable(p, x.regTable, [[x.registrar, reg.registrar], [x.created, reg.created], [x.updated, reg.updated], [x.expires, reg.expires], [x.regStatus, reg.status.join(', ')]])
    else if (reg) { subheading(p, x.regTable); paragraph(p, x.regNone) }
  }
  if (id === 'reputation') {
    table(p, x.repTable, [x.listName, x.target, x.result], [40, 34, 26], (data.table || []).map((row) => [row.list, dim(row.target), row.state === 'clean' ? good(x.clean) : row.state === 'listed' ? bad(x.listed) : dim(x.unavailable)]))
  }
  if (id === 'crawl') {
    table(p, `${x.pagesTable} (${data.pages?.length || 0})`, [x.path, x.status, x.time], [66, 16, 18], (data.pages || []).map((page) => [page.path, page.status >= 500 ? bad(String(page.status)) : page.status >= 400 ? soft(String(page.status)) : good(String(page.status)), dim(`${page.ms} ms`)]))
    if (data.cut_short) paragraph(p, x.cutShort, 400, 22, MUTED)
  }
  if (id === 'active') {
    factTable(p, d.ui.modules.active, [[d.pdf.filesChecked, data.checked_files ? String(data.checked_files) : ''], [d.pdf.portsChecked, data.checked_ports ? String(data.checked_ports) : '']])
  }
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
  for (const id of [...PUBLIC, 'active', 'crawl', 'probe'] as ModuleId[]) {
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

  // Sections follow each other on the page: a report with few findings must not be mostly white paper
  const section = (title: string, fresh = false) => {
    if (fresh) p.add()
    else { p.y += 34; p.need(300) }
    entries.push([title, p.canvases.length])
    setFont(p.c, 800, 36)
    p.y = drawLines(p.c, wrap(p.c, title, W - 2 * M), M, p.y, 46) + 12
    p.c.strokeStyle = '#1d4ed8'
    p.c.lineWidth = 4
    p.c.beginPath(); p.c.moveTo(M, p.y); p.c.lineTo(M + 90, p.y); p.c.stroke()
    p.y += 22
  }

  section(d.pdf.plan, true)
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

  const fixes = readyFixes(parts)
  if (fixes.length) {
    section(d.pdf.x.ready)
    paragraph(p, d.pdf.x.readyLead)
    p.y += 12
    fixes.forEach((fix) => drawFix(p, fix))
  }

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

  for (const id of [...PUBLIC, 'active', 'crawl', 'probe'] as ModuleId[]) {
    const part = parts[id]
    if ((id === 'crawl' || id === 'probe') && !part) continue
    section(d.ui.modules[id])
    paragraph(p, d.pdf.intro[id], 400, 24, MUTED)
    if (id === 'active' && !part) { paragraph(p, d.pdf.activeNotRun, 600); continue }
    if (!part?.result) { paragraph(p, d.pdf.partFailed, 600, 24, COLOR.warn); continue }
    const count = (status: string) => part.result!.items.filter((x) => x.status === status).length
    paragraph(p, fill(d.pdf.x.summary, { fail: count('fail'), warn: count('warn'), ok: count('ok'), info: count('info') }), 700, 23)
    p.y += 8
    moduleDetails(p, id, part.result)
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
    p.need(wrap(p.c, meaning, W - 2 * M).length * 32 + 44)
    setFont(p.c, 800, 24)
    p.c.fillText(term, M, p.y)
    p.y += 32
    paragraph(p, meaning, 400, 23)
    p.y += 2
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
