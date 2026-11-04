import { describe, expect, it } from 'vitest'
import { buildPdf } from './pdf'
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

describe('snippetsFor', () => {
  it('gives every platform the same header value', () => {
    const hsts = snippetsFor('hsts')
    expect(hsts.map((s) => s.platform)).toContain('Nginx')
    hsts.forEach((s) => expect(s.code).toContain('max-age=31536000'))
  })

  it('starts CSP in report-only mode, so a fix cannot break a live site', () => {
    snippetsFor('csp').forEach((s) => expect(s.code).toContain('Content-Security-Policy-Report-Only'))
  })

  it('has nothing for an unknown check', () => {
    expect(snippetsFor('no-such-check')).toEqual([])
  })
})
