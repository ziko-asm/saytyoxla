import { describe, expect, it } from 'vitest'
import { buildPdf, textLayer } from './pdf'
import { snippetsFor } from './fixes'

const text = (bytes: Uint8Array) => new TextDecoder('latin1').decode(bytes)

describe('buildPdf', () => {
  const pdf = text(buildPdf([new Uint8Array([0xff, 0xd8, 1, 2, 0xff, 0xd9]), new Uint8Array([0xff, 0xd8, 3, 0xff, 0xd9])]))

  it('is a PDF with one page per image', () => {
    expect(pdf.startsWith('%PDF-1.4\n')).toBe(true)
    expect(pdf.endsWith('%%EOF\n')).toBe(true)
    expect(pdf.match(/\/Type \/Page /g)).toHaveLength(2)
    expect(pdf).toContain('/Count 2')
  })

  it('has a cross-reference table that points at every object', () => {
    const start = Number(pdf.match(/startxref\n(\d+)/)?.[1])
    expect(pdf.slice(start, start + 4)).toBe('xref')
    const offsets = [...pdf.slice(start).matchAll(/^(\d{10}) 00000 n $/gm)].map((m) => Number(m[1]))
    expect(offsets).toHaveLength(8)
    offsets.forEach((offset, i) => expect(pdf.slice(offset).startsWith(`${i + 1} 0 obj`)).toBe(true))
  })

  it('declares the true length of each image', () => {
    expect(pdf).toContain('/Filter /DCTDecode /Length 6 ')
    expect(pdf).toContain('/Filter /DCTDecode /Length 5 ')
  })
})

describe('the text over the picture', () => {
  const run = { text: 'Qiymət: A', x: 124, y: 248, size: 40, width: 200 }
  const pdf = text(buildPdf([new Uint8Array([0xff, 0xd8, 1, 0xff, 0xd9])], 1240, 1754, [[run]], { title: 'saytyoxla-məktəb.az', lang: 'az' }))

  it('is invisible, placed where it was drawn and as wide as it was drawn', () => {
    const layer = textLayer([run], 0.5, 842)
    expect(layer).toContain('BT 3 Tr')                              // mode 3: neither filled nor stroked
    expect(layer).toContain('/F0 20 Tf 111.11 Tz 1 0 0 1 62 718 Tm')  // 9 letters x 0.5 x 20 = 90 wide, stretched to 100
    expect(layer).toContain('<005100690079006D0259')                // "Qiymə" as UTF-16: ə survives
    expect(textLayer([], 0.5, 842)).toBe('')
  })

  it('adds the blank font, a map back to characters, the language and the title', () => {
    expect(pdf).toContain('/Subtype /Type0')
    expect(pdf).toContain('/Font << /F0 6 0 R >>')
    expect(pdf).toContain('<0000> <FFFF> <0000>')
    expect(pdf).toContain('/Lang (az)')
    expect(pdf).toContain('/Info 11 0 R')
    const start = Number(pdf.match(/startxref\n(\d+)/)?.[1])
    const offsets = [...pdf.slice(start).matchAll(/^(\d{10}) 00000 n $/gm)].map((m) => Number(m[1]))
    expect(offsets).toHaveLength(11)
    offsets.forEach((offset, i) => expect(pdf.slice(offset).startsWith(`${i + 1} 0 obj`)).toBe(true))
  })

  it('declares the content length in bytes', () => {
    const content = pdf.match(/4 0 obj\n<< \/Length (\d+) >>\nstream\n([\s\S]*?)\nendstream/)
    expect(Number(content?.[1])).toBe(content?.[2].length)
  })
})

describe('snippetsFor', () => {
  it('gives every platform the same header value', () => {
    const hsts = snippetsFor('hsts')
    expect(hsts.map((s) => s.platform)).toContain('Nginx')
    hsts.forEach((s) => expect(s.code).toContain('max-age=31536000'))
  })

  it('starts CSP in report-only mode, so a fix cannot break a live site', () => {
    snippetsFor('csp').forEach((s) => expect(s.code).toContain('Content-Security-Policy-Report-Only'))
  })

  it('caches static files for a month on every platform', () => {
    const cache = snippetsFor('asset_cache')
    expect(cache.map((s) => s.platform)).toEqual(['Nginx', 'Apache (.htaccess)', 'Vercel (vercel.json)', 'Netlify (_headers)'])
    cache.forEach((s) => expect(s.code).toContain('max-age=2592000'))
    expect(() => JSON.parse(cache[2].code)).not.toThrow()
  })

  it('has nothing for an unknown check', () => {
    expect(snippetsFor('no-such-check')).toEqual([])
  })
})
