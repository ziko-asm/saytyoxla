// What the generators on the Tools page produce. Pure functions, all in the visitor's browser: nothing is sent anywhere.

export type Output = { label: string; code: string }

const oneLine = (s: string) => s.replace(/[\r\n]+/g, ' ').trim()
const listOf = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)
const attr = (s: string) => oneLine(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
const xml = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;')
const mailto = (s: string) => listOf(s).map((a) => (a.startsWith('mailto:') ? a : `mailto:${a}`)).join(',')

// ---------------------------------------------------------------- DMARC
export type DmarcOptions = { policy: string; subdomains: string; percent: number; reports: string; forensic: string; strict: boolean }

export function dmarcRecord(o: DmarcOptions): string {
  const tags = ['v=DMARC1', `p=${o.policy}`]
  if (o.subdomains && o.subdomains !== o.policy) tags.push(`sp=${o.subdomains}`)
  if (o.percent < 100) tags.push(`pct=${Math.max(0, Math.round(o.percent))}`)
  if (o.reports.trim()) tags.push(`rua=${mailto(o.reports)}`)
  if (o.forensic.trim()) tags.push(`ruf=${mailto(o.forensic)}`)
  if (o.strict) tags.push('adkim=s', 'aspf=s')
  return tags.join('; ')
}

// ---------------------------------------------------------------- SPF
export const SPF_PROVIDERS: { id: string; name: string; include: string }[] = [
  { id: 'google', name: 'Google Workspace / Gmail', include: '_spf.google.com' },
  { id: 'microsoft', name: 'Microsoft 365 / Outlook', include: 'spf.protection.outlook.com' },
  { id: 'zoho', name: 'Zoho Mail', include: 'zohomail.com' },
  { id: 'yandex', name: 'Yandex 360', include: '_spf.yandex.net' },
  { id: 'mailru', name: 'Mail.ru', include: '_spf.mail.ru' },
  { id: 'mailgun', name: 'Mailgun', include: 'mailgun.org' },
  { id: 'sendgrid', name: 'SendGrid', include: 'sendgrid.net' },
]
export const SPF_LOOKUP_LIMIT = 10

export type SpfOptions = { providers: string[]; mx: boolean; a: boolean; ips: string; extra: string; ending: string }

export function spfRecord(o: SpfOptions): { record: string; lookups: number } {
  const includes = [
    ...SPF_PROVIDERS.filter((p) => o.providers.includes(p.id)).map((p) => p.include),
    ...listOf(o.extra).map((x) => x.replace(/^include:/, '')),
  ]
  const ips = listOf(o.ips).map((ip) => (ip.includes(':') ? `ip6:${ip}` : `ip4:${ip}`))
  const parts = ['v=spf1', ...(o.a ? ['a'] : []), ...(o.mx ? ['mx'] : []), ...ips, ...includes.map((x) => `include:${x}`), o.ending]
  // Only what this record asks for: an include can ask for more, which only a look at DNS would show
  return { record: parts.join(' '), lookups: includes.length + (o.a ? 1 : 0) + (o.mx ? 1 : 0) }
}

// ---------------------------------------------------------------- headers
export type HeaderOptions = { hsts: boolean; hstsDays: number; subdomains: boolean; frame: string; nosniff: boolean; referrer: string; permissions: boolean; csp: string }

export function headerList(o: HeaderOptions): [string, string][] {
  const out: [string, string][] = []
  if (o.hsts) out.push(['Strict-Transport-Security', `max-age=${Math.round(o.hstsDays * 86400)}${o.subdomains ? '; includeSubDomains' : ''}`])
  if (o.frame) out.push(['X-Frame-Options', o.frame])
  if (o.nosniff) out.push(['X-Content-Type-Options', 'nosniff'])
  if (o.referrer) out.push(['Referrer-Policy', o.referrer])
  if (o.permissions) out.push(['Permissions-Policy', 'camera=(), microphone=(), geolocation=()'])
  if (o.csp.trim()) out.push(['Content-Security-Policy-Report-Only', oneLine(o.csp)])
  return out
}

export function headerConfigs(headers: [string, string][]): Output[] {
  if (!headers.length) return []
  const json = JSON.stringify({ headers: [{ source: '/(.*)', headers: headers.map(([key, value]) => ({ key, value })) }] }, null, 2)
  const quoted = (v: string) => v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
  return [
    { label: 'Nginx', code: headers.map(([k, v]) => `add_header ${k} "${quoted(v)}" always;`).join('\n') },
    { label: 'Apache (.htaccess)', code: `<IfModule mod_headers.c>\n${headers.map(([k, v]) => `  Header always set ${k} "${quoted(v)}"`).join('\n')}\n</IfModule>` },
    { label: 'Vercel (vercel.json)', code: json },
    { label: 'Netlify (_headers)', code: `/*\n${headers.map(([k, v]) => `  ${k}: ${v}`).join('\n')}` },
  ]
}

// ---------------------------------------------------------------- CSP
export type CspOptions = { scripts: string; styles: string; images: string; fonts: string; connect: string; frames: string; inlineStyles: boolean; embed: string }

export function cspPolicy(o: CspOptions): string {
  const self = (extra: string, ...more: string[]) => ["'self'", ...more, ...listOf(extra)].join(' ')
  return [
    "default-src 'self'",
    `script-src ${self(o.scripts)}`,
    `style-src ${self(o.styles, ...(o.inlineStyles ? ["'unsafe-inline'"] : []))}`,
    `img-src ${self(o.images, 'data:')}`,
    `font-src ${self(o.fonts)}`,
    `connect-src ${self(o.connect)}`,
    ...(listOf(o.frames).length ? [`frame-src ${listOf(o.frames).join(' ')}`] : []),
    `frame-ancestors ${o.embed === 'none' ? "'none'" : "'self'"}`,
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
  ].join('; ')
}

// ---------------------------------------------------------------- robots.txt
export const AI_BOTS = ['GPTBot', 'ClaudeBot', 'Google-Extended', 'PerplexityBot', 'CCBot']
export type RobotsOptions = { blockAll: boolean; paths: string; blockAi: boolean; sitemap: string }

export function robotsTxt(o: RobotsOptions): string {
  const lines = ['User-agent: *']
  if (o.blockAll) lines.push('Disallow: /')
  else {
    const paths = listOf(o.paths).map((p) => (p.startsWith('/') ? p : `/${p}`))
    lines.push(...(paths.length ? paths.map((p) => `Disallow: ${p}`) : ['Allow: /']))
  }
  if (o.blockAi) for (const bot of AI_BOTS) lines.push('', `User-agent: ${bot}`, 'Disallow: /')
  if (oneLine(o.sitemap)) lines.push('', `Sitemap: ${oneLine(o.sitemap)}`)
  return lines.join('\n') + '\n'
}

// ---------------------------------------------------------------- meta tags
export type MetaOptions = { title: string; description: string; url: string; image: string; siteName: string }

export function metaTags(o: MetaOptions): string {
  const tag = (name: string, value: string, key = 'property') => (value.trim() ? [`<meta ${key}="${name}" content="${attr(value)}">`] : [])
  return [
    ...(o.title.trim() ? [`<title>${attr(o.title)}</title>`] : []),
    ...tag('description', o.description, 'name'),
    ...(o.url.trim() ? [`<link rel="canonical" href="${attr(o.url)}">`] : []),
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    ...tag('og:type', o.title.trim() ? 'website' : ''),
    ...tag('og:title', o.title),
    ...tag('og:description', o.description),
    ...tag('og:url', o.url),
    ...tag('og:image', o.image),
    ...tag('og:site_name', o.siteName),
    ...tag('twitter:card', o.image.trim() ? 'summary_large_image' : '', 'name'),
  ].join('\n')
}

// ---------------------------------------------------------------- sitemap.xml
export function sitemapXml(urls: string, lastmod: string): string {
  const rows = urls.split(/\r?\n/).map((u) => u.trim()).filter(Boolean).map((u) =>
    `  <url>\n    <loc>${xml(u)}</loc>\n${lastmod ? `    <lastmod>${xml(lastmod)}</lastmod>\n` : ''}  </url>`)
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${rows.join('\n')}\n</urlset>\n`
}

// ---------------------------------------------------------------- security.txt (RFC 9116)
export function securityTxt(contact: string, expires: string, languages: string, policy: string): string {
  const contacts = listOf(contact).map((c) => (/^(https?:|mailto:|tel:)/.test(c) ? c : `mailto:${c}`))
  return [
    ...contacts.map((c) => `Contact: ${c}`),
    `Expires: ${expires}T00:00:00.000Z`,
    ...(listOf(languages).length ? [`Preferred-Languages: ${listOf(languages).join(', ')}`] : []),
    ...(oneLine(policy) ? [`Policy: ${oneLine(policy)}`] : []),
  ].join('\n') + '\n'
}

// ---------------------------------------------------------------- redirects
export function redirectConfigs(rawDomain: string, mode: string): Output[] {
  const domain = oneLine(rawDomain).replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '') || 'example.az'
  const www = `www.${domain}`
  const target = mode === 'www' ? www : domain
  const other = mode === 'www' ? domain : www
  const escaped = other.replace(/\./g, '\\.')
  return [
    { label: 'Nginx', code: `server {\n  listen 80;\n  server_name ${domain} ${www};\n  return 301 https://${target}$request_uri;\n}\nserver {\n  listen 443 ssl;\n  server_name ${other};\n  # ssl_certificate ...;\n  return 301 https://${target}$request_uri;\n}` },
    { label: 'Apache (.htaccess)', code: `RewriteEngine On\nRewriteCond %{HTTPS} off [OR]\nRewriteCond %{HTTP_HOST} ^${escaped}$ [NC]\nRewriteRule ^ https://${target}%{REQUEST_URI} [L,R=301]` },
    { label: 'Vercel (vercel.json)', code: JSON.stringify({ redirects: [{ source: '/:path*', has: [{ type: 'host', value: other }], destination: `https://${target}/:path*`, permanent: true }] }, null, 2) },
    { label: 'Netlify (_redirects)', code: `https://${other}/*  https://${target}/:splat  301!\nhttp://${other}/*  https://${target}/:splat  301!\nhttp://${target}/*  https://${target}/:splat  301!` },
  ]
}

// ---------------------------------------------------------------- record explainer
export type Explained = { token: string; key: string; value?: string }
export type Explanation = { kind: 'spf' | 'dmarc' | 'unknown'; items: Explained[]; lookups: number }

export function explainRecord(raw: string): Explanation {
  const text = oneLine(raw).replace(/^["']|["']$/g, '')
  const low = text.toLowerCase()
  if (low.startsWith('v=dmarc1')) {
    const items = text.split(';').map((p) => p.trim()).filter(Boolean).map((token): Explained => {
      const [k, v = ''] = token.split('=').map((x) => x.trim())
      const key = k.toLowerCase()
      const value = v.toLowerCase()
      if (key === 'p' || key === 'sp') return { token, key: `dmarc.${key}.${value}`, value }
      if (key === 'adkim' || key === 'aspf') return { token, key: `dmarc.${key}.${value === 's' ? 's' : 'r'}`, value }
      return { token, key: `dmarc.${key}`, value: v }
    })
    return { kind: 'dmarc', items, lookups: 0 }
  }
  if (low.startsWith('v=spf1')) {
    let lookups = 0
    const items = text.split(/\s+/).map((token): Explained => {
      const low2 = token.toLowerCase()
      const qualifier = /^[-~+?]/.test(low2) ? low2[0] : '+'
      const body = low2.replace(/^[-~+?]/, '')
      const value = token.includes(':') ? token.slice(token.indexOf(':') + 1) : ''
      if (body === 'v=spf1') return { token, key: 'spf.version' }
      if (body === 'all') return { token, key: `spf.all.${qualifier}` }
      const mech = body.split(/[:/=]/)[0]
      if (['a', 'mx', 'include', 'exists', 'ptr'].includes(mech)) lookups += 1
      if (mech === 'redirect') { lookups += 1; return { token, key: 'spf.redirect', value: token.slice(token.indexOf('=') + 1) } }
      if (['a', 'mx', 'include', 'ip4', 'ip6', 'exists', 'ptr'].includes(mech)) return { token, key: `spf.${mech}`, value }
      return { token, key: 'unknownPart' }
    })
    return { kind: 'spf', items, lookups }
  }
  return { kind: 'unknown', items: [], lookups: 0 }
}

// ---------------------------------------------------------------- SSL reminder
const icsDate = (d: Date) => d.toISOString().slice(0, 10).replace(/-/g, '')
const icsText = (s: string) => s.replace(/\\/g, '\\\\').replace(/;/g, '\\;').replace(/,/g, '\\,').replace(/\r?\n/g, '\\n')

export const REMINDER_DAYS = 14

// A calendar file: the visitor's own phone reminds them, so no server has to remember anything
export function sslReminder(host: string, expires: string, title: string, description: string, now = new Date()): string {
  const end = new Date(`${expires}T00:00:00Z`)
  const wanted = new Date(end.getTime() - REMINDER_DAYS * 86400000)
  const start = wanted > now ? wanted : now
  return [
    'BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//SaytYoxla//SSL reminder//EN', 'CALSCALE:GREGORIAN', 'BEGIN:VEVENT',
    `UID:ssl-${host}-${expires}@saytyoxla`,
    `DTSTAMP:${now.toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '')}`,
    `DTSTART;VALUE=DATE:${icsDate(start)}`,
    `DTEND;VALUE=DATE:${icsDate(new Date(start.getTime() + 86400000))}`,
    `SUMMARY:${icsText(title)}`,
    `DESCRIPTION:${icsText(description)}`,
    'BEGIN:VALARM', 'ACTION:DISPLAY', 'TRIGGER:PT9H', `DESCRIPTION:${icsText(title)}`, 'END:VALARM',
    'END:VEVENT', 'END:VCALENDAR', '',
  ].join('\r\n')
}
