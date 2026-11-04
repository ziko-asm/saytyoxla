import { describe, expect, it } from 'vitest'
import {
  cspPolicy, dmarcRecord, explainRecord, headerConfigs, headerList, metaTags, redirectConfigs, robotsTxt, securityTxt,
  sitemapXml, spfRecord, sslReminder,
} from './generators'

describe('dmarcRecord', () => {
  const base = { policy: 'quarantine', subdomains: '', percent: 100, reports: '', forensic: '', strict: false }
  it('is valid with only a policy', () => expect(dmarcRecord(base)).toBe('v=DMARC1; p=quarantine'))
  it('adds only what differs from the default', () => {
    expect(dmarcRecord({ ...base, subdomains: 'quarantine' })).toBe('v=DMARC1; p=quarantine')
    expect(dmarcRecord({ ...base, subdomains: 'reject', percent: 50 })).toBe('v=DMARC1; p=quarantine; sp=reject; pct=50')
  })
  it('turns addresses into mailto links', () => {
    expect(dmarcRecord({ ...base, reports: 'a@x.az, mailto:b@x.az', strict: true }))
      .toBe('v=DMARC1; p=quarantine; rua=mailto:a@x.az,mailto:b@x.az; adkim=s; aspf=s')
  })
})

describe('spfRecord', () => {
  const base = { providers: [], mx: false, a: false, ips: '', extra: '', ending: '~all' }
  it('always starts with the version and ends with the choice', () => {
    expect(spfRecord(base)).toEqual({ record: 'v=spf1 ~all', lookups: 0 })
    expect(spfRecord({ ...base, ending: '-all' }).record).toBe('v=spf1 -all')
  })
  it('combines every source and counts the lookups', () => {
    const r = spfRecord({ ...base, providers: ['google', 'mailgun'], mx: true, ips: '1.2.3.4 2001:db8::1', extra: 'include:x.az y.az' })
    expect(r.record).toBe('v=spf1 mx ip4:1.2.3.4 ip6:2001:db8::1 include:_spf.google.com include:mailgun.org include:x.az include:y.az ~all')
    expect(r.lookups).toBe(5)
  })
})

describe('headers', () => {
  const base = { hsts: true, hstsDays: 365, subdomains: false, frame: 'SAMEORIGIN', nosniff: true, referrer: 'no-referrer', permissions: false, csp: '' }
  it('computes HSTS in seconds', () => {
    expect(headerList(base)[0]).toEqual(['Strict-Transport-Security', 'max-age=31536000'])
    expect(headerList({ ...base, subdomains: true })[0][1]).toBe('max-age=31536000; includeSubDomains')
  })
  it('never turns a new CSP on for real: it starts report-only', () => {
    expect(headerList({ ...base, csp: "default-src 'self'" }).at(-1)?.[0]).toBe('Content-Security-Policy-Report-Only')
  })
  it('a line break cannot inject another header', () => {
    expect(headerList({ ...base, csp: "default-src 'self'\r\nX-Evil: 1" }).at(-1)?.[1]).not.toMatch(/[\r\n]/)
  })
  it('gives valid JSON for Vercel and a line per header elsewhere', () => {
    const out = headerConfigs(headerList(base))
    const vercel = JSON.parse(out.find((x) => x.label.startsWith('Vercel'))!.code)
    expect(vercel.headers[0].headers).toHaveLength(4)
    expect(out.find((x) => x.label === 'Nginx')!.code.split('\n')).toHaveLength(4)
    expect(headerConfigs([])).toEqual([])
  })
})

describe('cspPolicy', () => {
  const base = { scripts: '', styles: '', images: '', fonts: '', connect: '', frames: '', inlineStyles: false, embed: 'none' }
  it('is strict by default and never allows inline scripts', () => {
    const p = cspPolicy(base)
    expect(p).toContain("script-src 'self'")
    expect(p).toContain("frame-ancestors 'none'")
    expect(p).toContain("object-src 'none'")
    expect(cspPolicy({ ...base, inlineStyles: true, scripts: 'https://a.az' })).toContain("script-src 'self' https://a.az;")
  })
  it('adds outside sources where they belong', () => {
    const p = cspPolicy({ ...base, styles: 'https://f.az', inlineStyles: true, frames: 'https://y.az', embed: 'self' })
    expect(p).toContain("style-src 'self' 'unsafe-inline' https://f.az")
    expect(p).toContain('frame-src https://y.az')
    expect(p).toContain("frame-ancestors 'self'")
  })
})

describe('robotsTxt', () => {
  const base = { blockAll: false, paths: '', blockAi: false, sitemap: '' }
  it('allows everyone by default', () => expect(robotsTxt(base)).toBe('User-agent: *\nAllow: /\n'))
  it('blocks paths, AI crawlers and names the sitemap', () => {
    const t = robotsTxt({ ...base, paths: 'admin /private', blockAi: true, sitemap: 'https://a.az/sitemap.xml' })
    expect(t).toContain('Disallow: /admin\nDisallow: /private')
    expect(t).toContain('User-agent: GPTBot\nDisallow: /')
    expect(t.endsWith('Sitemap: https://a.az/sitemap.xml\n')).toBe(true)
  })
  it('can close the whole site', () => expect(robotsTxt({ ...base, blockAll: true, paths: 'x' })).toBe('User-agent: *\nDisallow: /\n'))
})

describe('metaTags', () => {
  it('escapes what people type', () => {
    const t = metaTags({ title: 'A "B" <C>', description: '', url: '', image: '', siteName: '' })
    expect(t).toContain('<title>A &quot;B&quot; &lt;C&gt;</title>')
    expect(t).toContain('content="A &quot;B&quot; &lt;C&gt;"')
    expect(t).not.toContain('<C>')
  })
  it('leaves out what is empty', () => {
    const t = metaTags({ title: '', description: '', url: '', image: '', siteName: '' })
    expect(t).toBe('<meta name="viewport" content="width=device-width, initial-scale=1">')
  })
  it('uses the large card only with an image', () => {
    expect(metaTags({ title: 'A', description: 'B', url: 'https://a.az/', image: 'https://a.az/i.png', siteName: '' })).toContain('summary_large_image')
  })
})

describe('sitemapXml', () => {
  it('lists every address and escapes it', () => {
    const t = sitemapXml('https://a.az/\n\n  https://a.az/?x=1&y=2 \n', '2026-11-05')
    expect(t.match(/<loc>/g)).toHaveLength(2)
    expect(t).toContain('<loc>https://a.az/?x=1&amp;y=2</loc>')
    expect(t).toContain('<lastmod>2026-11-05</lastmod>')
    expect(sitemapXml('https://a.az/', '')).not.toContain('lastmod')
  })
})

describe('securityTxt', () => {
  it('has the two required fields', () => {
    const t = securityTxt('a@x.az https://x.az/report', '2027-11-05', 'az en', '')
    expect(t).toContain('Contact: mailto:a@x.az\nContact: https://x.az/report')
    expect(t).toContain('Expires: 2027-11-05T00:00:00.000Z')
    expect(t).toContain('Preferred-Languages: az, en')
  })
})

describe('redirectConfigs', () => {
  it('cleans the address and points at the chosen form', () => {
    const out = redirectConfigs('https://www.mansia.az/page', 'www')
    expect(out[0].code).toContain('return 301 https://www.mansia.az$request_uri')
    const bare = redirectConfigs('mansia.az', 'bare')
    expect(bare[1].code).toContain('https://mansia.az%{REQUEST_URI}')
    expect(bare[1].code).toContain('^www\\.mansia\\.az$')
    expect(JSON.parse(bare[2].code).redirects[0].destination).toBe('https://mansia.az/:path*')
  })
})

describe('explainRecord', () => {
  it('explains each part of a DMARC record', () => {
    const e = explainRecord('"v=DMARC1; p=reject; sp=none; rua=mailto:a@x.az; adkim=s"')
    expect(e.kind).toBe('dmarc')
    expect(e.items.map((i) => i.key)).toEqual(['dmarc.v', 'dmarc.p.reject', 'dmarc.sp.none', 'dmarc.rua', 'dmarc.adkim.s'])
  })
  it('explains and counts an SPF record', () => {
    const e = explainRecord('v=spf1 a mx ip4:1.2.3.4 include:_spf.google.com -all')
    expect(e.kind).toBe('spf')
    expect(e.items.map((i) => i.key)).toEqual(['spf.version', 'spf.a', 'spf.mx', 'spf.ip4', 'spf.include', 'spf.all.-'])
    expect(e.lookups).toBe(3)
    expect(e.items[4].value).toBe('_spf.google.com')
  })
  it('does not count addresses and flags what it does not know', () => {
    const e = explainRecord('v=spf1 ip4:1.2.3.4 what -all')
    expect(e.lookups).toBe(0)
    expect(e.items[2].key).toBe('unknownPart')
    expect(explainRecord('hello').kind).toBe('unknown')
  })
})

describe('sslReminder', () => {
  const now = new Date('2026-11-05T10:00:00Z')
  const lines = (t: string) => t.split('\r\n')
  it('is a calendar file due two weeks before the end', () => {
    const t = sslReminder('a.az', '2027-01-27', 'Title, with; marks', 'Text', now)
    expect(t.startsWith('BEGIN:VCALENDAR\r\n')).toBe(true)
    expect(lines(t)).toContain('DTSTART;VALUE=DATE:20270113')
    expect(lines(t)).toContain('DTEND;VALUE=DATE:20270114')
    expect(lines(t)).toContain('SUMMARY:Title\\, with\\; marks')
    expect(t.endsWith('END:VCALENDAR\r\n')).toBe(true)
  })
  it('is due today when the end is close', () => {
    expect(lines(sslReminder('a.az', '2026-11-10', 'T', 'D', now))).toContain('DTSTART;VALUE=DATE:20261105')
  })
})
