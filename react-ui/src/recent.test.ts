import { describe, expect, it } from 'vitest'
import { parseRecent, pushRecent } from './recent'

describe('pushRecent', () => {
  it('puts the newest site first', () => expect(pushRecent(['a.az'], 'b.az')).toEqual(['b.az', 'a.az']))
  it('moves a repeated site to the front instead of listing it twice', () => {
    expect(pushRecent(['a.az', 'b.az'], 'B.az')).toEqual(['B.az', 'a.az'])
  })
  it('keeps at most five', () => {
    const list = ['1.az', '2.az', '3.az', '4.az', '5.az']
    expect(pushRecent(list, '6.az')).toEqual(['6.az', '1.az', '2.az', '3.az', '4.az'])
  })
  it('ignores an empty address', () => expect(pushRecent(['a.az'], '  ')).toEqual(['a.az']))
})

describe('parseRecent', () => {
  it('reads a saved list', () => expect(parseRecent('["a.az","b.az"]')).toEqual(['a.az', 'b.az']))
  it('gives an empty list for nothing, broken JSON or the wrong shape', () => {
    expect(parseRecent(null)).toEqual([])
    expect(parseRecent('{oops')).toEqual([])
    expect(parseRecent('{"a":1}')).toEqual([])
  })
  it('drops entries that are not short strings', () => {
    expect(parseRecent(JSON.stringify(['a.az', 5, '', 'x'.repeat(301)]))).toEqual(['a.az'])
  })
})
