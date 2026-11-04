import { describe, expect, it } from 'vitest'
import { compareSnapshots, findChains, snapshotOf } from './chains'
import type { DeepItem } from './chains'
import { ALL_WORDS, fill } from './deepText'

const item = (id: string, status: DeepItem['status'], params: Record<string, unknown> = {}): DeepItem => ({ id, status, params })
const ids = (items: DeepItem[], extra = {}) => findChains({ items, ...extra }).map((c) => c.id)

describe('attack scenarios', () => {
  it('finds nothing in a healthy report', () => {
    expect(ids([item('spoof_blocked', 'ok'), item('tls_old_off', 'ok'), item('surface_clean', 'ok')], { csp: true, hsts: true })).toEqual([])
  })

  it('never fires on unknowns: no answer is not a problem', () => {
    expect(ids([item('dns_unavailable', 'info'), item('rep_unknown', 'info'), item('page_blocked', 'info'), item('surface_unavailable', 'info')], { csp: null, hsts: null })).toEqual([])
  })

  it('joins takeover and open mail into one worse scenario', () => {
    const items = [item('takeover_risk', 'fail', { host: 'old.a.az', target: 'x.github.io' }), item('spoof_open', 'fail')]
    const chains = findChains({ items })
    expect(chains.map((c) => c.id)).toEqual(['brand_phish'])
    expect(chains[0].level).toBe('critical')
  })

  it('keeps them apart when only one is true', () => {
    expect(ids([item('spoof_open', 'fail')])).toEqual(['fake_mail'])
    expect(ids([item('takeover_risk', 'fail', { host: 'h', target: 't' })])).toEqual(['subdomain_takeover'])
  })

  it('needs both the weak library and the missing CSP, and an unknown CSP does not count', () => {
    const lib = item('vuln_library', 'fail', { name: 'jquery', version: '1', count: 2, ids: 'x' })
    expect(ids([lib], { csp: true })).toEqual([])
    expect(ids([lib], { csp: null })).toEqual([])
    expect(ids([lib], { csp: false })).toEqual(['script_injection'])
  })

  it('needs both old TLS and the missing HSTS', () => {
    expect(ids([item('tls_old', 'warn')], { hsts: true })).toEqual([])
    expect(ids([item('tls_old', 'warn')], { hsts: false })).toEqual(['weak_transport'])
  })

  it('treats a directory listing as less than a secret', () => {
    expect(ids([item('exposed_file', 'warn', { path: '/.DS_Store', kind: 'listing' })])).toEqual([])
    expect(ids([item('exposed_file', 'fail', { path: '/.env', kind: 'env' })])).toEqual(['exposed_secret'])
  })

  it('only serious open ports are a scenario', () => {
    expect(ids([item('open_port', 'info', { port: 22, service: 'SSH' })])).toEqual([])
    expect(ids([item('open_port', 'fail', { port: 6379, service: 'Redis' })])).toEqual(['open_database'])
  })

  it('a far-off domain date is not a scenario', () => {
    expect(ids([item('domain_expiry', 'ok', { date: 'd', days: 400 })])).toEqual([])
    expect(findChains({ items: [item('domain_expiry', 'fail', { date: 'd', days: 5 })] })[0].level).toBe('high')
  })

  it('puts the most urgent first', () => {
    const chains = findChains({ items: [item('sensitive_hosts', 'warn', { hosts: 'a', count: 1 }), item('exposed_file', 'fail', { path: '/.env', kind: 'env' }), item('spoof_open', 'fail')] })
    expect(chains.map((c) => c.level)).toEqual(['critical', 'high', 'medium'])
  })
})

describe('words', () => {
  const langs = Object.values(ALL_WORDS)

  it('every scenario the rules can give has words in all three languages', () => {
    const everything = [
      item('takeover_risk', 'fail', { host: 'h', target: 't' }), item('spoof_open', 'fail'), item('exposed_file', 'fail', { path: 'p', kind: 'env' }),
      item('open_port', 'fail', { port: 1, service: 's' }), item('vuln_library', 'fail', { name: 'n', version: 'v' }), item('domain_expiry', 'fail', { date: 'd', days: 1 }),
      item('rep_listed', 'fail', { list: 'l', target: 't' }), item('eol_runtime', 'fail', { name: 'n', version: 'v', date: 'd' }),
      item('sensitive_hosts', 'warn', { hosts: 'h', count: 1 }), item('dangling_cname', 'warn', { host: 'h', target: 't' }), item('tls_old', 'warn', { versions: 'v' }),
    ]
    const fired = new Set(findChains({ items: everything, csp: false, hsts: false }).map((c) => c.id))
    fired.add('fake_mail')
    fired.add('subdomain_takeover')
    for (const words of langs) for (const id of fired) expect(words.chains[id]?.could, id).toBeTruthy()
    for (const words of langs) expect(Object.keys(words.chains).sort()).toEqual(Object.keys(langs[0].chains).sort())
  })

  it('all languages have the same items and the same placeholders', () => {
    const marks = (s = '') => (s.match(/\{\w+\}/g) || []).sort()
    for (const words of langs) {
      expect(Object.keys(words.items).sort()).toEqual(Object.keys(langs[0].items).sort())
      for (const [id, entry] of Object.entries(langs[0].items)) {
        const other = words.items[id]
        expect(marks(other[0]), id).toEqual(marks(entry[0]))
        expect(marks(other[1]), id).toEqual(marks(entry[1]))
        expect(Boolean(other[2]), id).toBe(Boolean(entry[2]))
      }
    }
  })

  it('never says a site can be hacked as a fact', () => {
    const banned = /sındırılır|sındırıla bilər\b|can be hacked|will be hacked|взломают/i
    for (const words of langs) for (const chain of Object.values(words.chains)) expect(chain.could).not.toMatch(banned)
  })

  it('fills only what it knows', () => {
    expect(fill('{a} və {b}', { a: 1 })).toBe('1 və {b}')
  })
})

describe('comparing two checks', () => {
  it('names what is new and what was solved, and ignores info', () => {
    const old = snapshotOf([item('tls_old', 'warn', { versions: 'TLS 1.0' }), item('surface_count', 'info', { total: 1 })], ['a.x.az'], '2026-11-01')
    const now = snapshotOf([item('spoof_open', 'fail'), item('surface_count', 'info', { total: 2 })], ['a.x.az', 'b.x.az'], '2026-11-05')
    const diff = compareSnapshots(old, now)
    expect(diff.since).toBe('2026-11-01')
    expect(diff.newHosts).toEqual(['b.x.az'])
    expect(diff.newProblems).toEqual(['spoof_open|{}'])
    expect(diff.solved).toEqual(['tls_old|{"versions":"TLS 1.0"}'])
  })
})
