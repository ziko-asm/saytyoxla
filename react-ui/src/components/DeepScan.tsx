import { useEffect, useRef, useState } from 'react'
import { compareSnapshots, findChains, snapshotOf } from '../chains'
import type { Changes, Chain, DeepItem } from '../chains'
import { d, fill } from '../deepText'
import { LANG, LOCALE, t } from '../i18n'
import type { Finding } from '../types'
import { FindingItem } from './FindingItem'
import { Code } from './Generators'

// The public parts run side by side, each its own request: one slow or failed part leaves the rest standing.
// The active part is separate, and the server refuses it until the site's owner has proved control.
const PUBLIC = ['surface', 'mail', 'tech', 'tls', 'reputation'] as const
type ModuleId = typeof PUBLIC[number] | 'active'
type Host = { host: string; live: boolean; cname: string; flag: '' | 'takeover' | 'dangling' | 'sensitive' | 'private' }
type Data = {
  hosts?: Host[]; software?: { name: string; version: string }[]; csp?: boolean | null; hsts?: boolean | null
  nameservers?: string[]; records?: { spf?: string[]; dmarc?: string[]; dmarc_parent?: string; mx?: string[] }
  checked?: string[]; safe_browsing?: string
}
type Result = { module: ModuleId; host: string; items: DeepItem[]; data: Data }
type Part = { state: 'loading' | 'done' | 'error'; result?: Result; error?: string }
type Proof = { host: string; token: string; dns_name: string; file_url: string }

const ORDER: Record<string, number> = { fail: 0, warn: 1, ok: 2, info: 3 }

async function ask(path: string, body: object) {
  const res = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...body, lang: LANG }) })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(typeof data.detail === 'string' ? data.detail : t.genericError)
  return data
}

function toFinding(item: DeepItem): Finding {
  const words = d.items[item.id] || [item.id, '']
  return { id: `deep-${item.id}`, status: item.status, title: fill(words[0], item.params), detail: fill(words[1], item.params), fix: item.status === 'fail' || item.status === 'warn' ? fill(words[2] || '', item.params) : '' } as Finding
}

function remember(host: string, snapshot: ReturnType<typeof snapshotOf>): Changes | null {
  const key = `saytyoxla-deep:${host}`
  try {
    const before = localStorage.getItem(key)
    localStorage.setItem(key, JSON.stringify(snapshot))
    return before ? compareSnapshots(JSON.parse(before), snapshot) : null
  } catch {
    return null     // a private window or blocked storage: the check itself still stands
  }
}

function problemTitle(key: string) {
  const [id, params] = key.split(/\|(.*)/s)
  const words = d.items[id]
  try {
    return words ? fill(words[0], JSON.parse(params)) : id
  } catch {
    return id
  }
}

function ChainCard({ chain }: { chain: Chain }) {
  const words = d.chains[chain.id]
  if (!words) return null
  return (
    <article className={`chain ${chain.level}`}>
      <h4>{fill(words.title, chain.params)}<span className="chain-level">{d.ui.levels[chain.level]}</span></h4>
      <dl>
        <div><dt>{d.ui.fact}</dt><dd>{fill(words.fact, chain.params)}</dd></div>
        <div><dt>{d.ui.could}</dt><dd>{fill(words.could, chain.params)}</dd></div>
        <div><dt>{d.ui.fix}</dt><dd>{fill(words.fix, chain.params)}</dd></div>
      </dl>
    </article>
  )
}

function Facts({ result }: { result: Result }) {
  const { data } = result
  const rows: [string, string][] = []
  if (data.software?.length) rows.push([d.ui.software, data.software.map((s) => `${s.name}${s.version ? ` ${s.version}` : ''}`).join(', ')])
  if (data.records?.spf?.length) rows.push(['SPF', data.records.spf.join(' ')])
  if (data.records?.dmarc?.length) rows.push(['DMARC', data.records.dmarc.join(' ')])
  if (data.records?.mx?.length) rows.push(['MX', data.records.mx.join(', ')])
  if (data.nameservers?.length) rows.push([d.ui.nameservers, data.nameservers.join(', ')])
  if (data.checked?.length) rows.push([d.ui.lists, data.checked.join(', ')])
  if (!rows.length) return null
  return <dl className="facts">{rows.map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}</dl>
}

function Hosts({ hosts }: { hosts: Host[] }) {
  return (
    <details className="deep-hosts" open={hosts.length <= 12}>
      <summary>{d.ui.hosts} ({hosts.length})</summary>
      <ul>
        {hosts.map((h) => (
          <li key={h.host} className={h.live ? '' : 'off'}>
            <span>{h.host}</span>
            {h.flag ? <b className={`flag ${h.flag}`}>{d.ui.flags[h.flag]}</b> : !h.live && <small>{d.ui.offline}</small>}
          </li>
        ))}
      </ul>
    </details>
  )
}

function Section({ id, part, onRetry }: { id: ModuleId; part?: Part; onRetry: () => void }) {
  if (!part) return null
  const items = [...(part.result?.items || [])].sort((a, b) => ORDER[a.status] - ORDER[b.status])
  return (
    <section className="deep-part" aria-busy={part.state === 'loading'}>
      <h3>{d.ui.modules[id]}</h3>
      {part.state === 'loading' && <div className="spinner" role="status" aria-label={d.ui.running}></div>}
      {part.state === 'error' && (
        <p className="form-error" role="alert">{part.error || d.ui.failed}{' '}
          <button className="btn btn-ghost" type="button" onClick={onRetry}>{d.ui.retry}</button>
        </p>
      )}
      {part.result && <Facts result={part.result} />}
      {part.result?.data.hosts && part.result.data.hosts.length > 0 && <Hosts hosts={part.result.data.hosts} />}
      {items.map((item, i) => <FindingItem key={`${item.id}${i}`} f={toFinding(item)} />)}
      {part.result?.data.safe_browsing && (
        <p className="tool-more"><a href={part.result.data.safe_browsing} target="_blank" rel="noopener noreferrer">{d.ui.safeBrowsing} →</a></p>
      )}
    </section>
  )
}

function Ownership({ target, part, onCheck }: { target: string; part?: Part; onCheck: () => void }) {
  const [proof, setProof] = useState<Proof | null>(null)
  const [error, setError] = useState('')
  const [waiting, setWaiting] = useState(false)

  async function start() {
    setError('')
    setWaiting(true)
    try {
      setProof(await ask('/api/ownership', { url: target }))
    } catch (e) {
      setError(e instanceof Error ? e.message : t.genericError)
    } finally {
      setWaiting(false)
    }
  }

  return (
    <section className="deep-part deep-own">
      <h3>{d.ui.ownTitle}</h3>
      <p>{d.ui.ownLead}</p>
      <p className="g-tip">{d.ui.ownOnly}</p>
      {!proof && <button className="btn btn-primary" type="button" disabled={waiting} onClick={start}>{d.ui.ownStart}</button>}
      {error && <p className="form-error" role="alert">{error}</p>}
      {proof && (
        <>
          <h4>{d.ui.ownDns}</h4>
          <p className="g-tip">{d.ui.ownDnsHint}</p>
          <Code label="TXT" code={proof.dns_name} />
          <h4>{d.ui.ownFile}</h4>
          <p className="g-tip">{d.ui.ownFileHint}</p>
          <Code label="URL" code={proof.file_url} />
          <Code label={d.ui.ownCode} code={proof.token} file="saytyoxla.txt" />
          <p>
            <button className="btn btn-primary" type="button" disabled={part?.state === 'loading'} onClick={onCheck}>
              {part?.state === 'loading' ? d.ui.ownChecking : d.ui.ownCheck}
            </button>
          </p>
          {part?.state === 'error' && <p className="g-tip">{d.ui.ownNotYet}</p>}
        </>
      )}
      {part?.state === 'error' && <p className="form-error" role="alert">{part.error}</p>}
      {part?.result && (
        <>
          {[...part.result.items].sort((a, b) => ORDER[a.status] - ORDER[b.status]).map((item, i) => <FindingItem key={`${item.id}${i}`} f={toFinding(item)} />)}
        </>
      )}
    </section>
  )
}

export function DeepScan({ initialUrl, onTarget }: { initialUrl: string; onTarget: (value: string) => void }) {
  const [url, setUrl] = useState(initialUrl)
  const [target, setTarget] = useState('')
  const [parts, setParts] = useState<Partial<Record<ModuleId, Part>>>({})
  const [changes, setChanges] = useState<Changes | null>(null)
  const [error, setError] = useState('')
  const input = useRef<HTMLInputElement>(null)
  const run = useRef(0)      // a new analysis makes the answers of the previous one stale

  async function runModule(id: ModuleId, value: string, fresh = false) {
    const mine = run.current
    setParts((now) => ({ ...now, [id]: { state: 'loading' } }))
    try {
      const result: Result = await ask('/api/deep', { url: value, module: id, fresh })
      if (mine === run.current) setParts((now) => ({ ...now, [id]: { state: 'done', result } }))
    } catch (e) {
      const message = e instanceof TypeError ? t.networkError : e instanceof Error ? e.message : t.genericError
      if (mine === run.current) setParts((now) => ({ ...now, [id]: { state: 'error', error: message } }))
    }
  }

  function start(value: string) {
    const clean = value.trim()
    setError('')
    if (!clean) {
      setError(t.emptyUrl)
      input.current?.focus()
      return
    }
    run.current += 1
    setTarget(clean)
    onTarget(clean)
    setChanges(null)
    setParts({})
    window.history.replaceState(null, '', `${window.location.pathname}?tool=deep&url=${encodeURIComponent(clean)}`)
    PUBLIC.forEach((id) => runModule(id, clean))
  }

  useEffect(() => {
    if (initialUrl) start(initialUrl)
    // only the address the page was opened with
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const results = Object.values(parts).map((p) => p?.result).filter((r): r is Result => !!r)
  const items = results.flatMap((r) => r.items)
  const publicDone = target !== '' && PUBLIC.every((id) => parts[id] && parts[id]!.state !== 'loading')
  const chains = publicDone ? findChains({ items, csp: parts.tech?.result?.data.csp, hsts: parts.tech?.result?.data.hsts }) : []

  // Compare only complete answers: a part that failed would look like every problem in it was solved
  const finished = publicDone && PUBLIC.every((id) => parts[id]?.state === 'done')
  useEffect(() => {
    if (!finished) return
    const hosts = (parts.surface?.result?.data.hosts || []).map((h) => h.host)
    const publicItems = PUBLIC.flatMap((id) => parts[id]?.result?.items || [])
    const host = parts.surface?.result?.host || target
    setChanges(remember(host, snapshotOf(publicItems, hosts, new Date().toLocaleDateString(LOCALE[LANG]))))
    // once per finished analysis
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [finished, target])

  return (
    <>
      <form className="scan" noValidate onSubmit={(e) => { e.preventDefault(); start(url) }}>
        <label htmlFor="deep-url" className="sr">{t.urlLabel}</label>
        <input ref={input} id="deep-url" name="url" type="text" inputMode="url" autoComplete="url" autoCapitalize="off"
          spellCheck={false} maxLength={300} placeholder={t.placeholder} value={url} onInput={(e) => setUrl(e.currentTarget.value)} />
        <button className="btn btn-primary" type="submit" disabled={target !== '' && !publicDone}>
          {target !== '' && !publicDone ? d.ui.running : d.ui.start}
        </button>
      </form>
      <p className="g-tip deep-passive">{d.ui.passive}</p>
      {error && <p className="form-error" role="alert">{error}</p>}
      {target && (
        <div className="deep-results">
          <section className="deep-part">
            <h3>{d.ui.chainsTitle}</h3>
            {!publicDone && <p className="g-tip">{d.ui.chainsWait}</p>}
            {publicDone && chains.length > 0 && <p className="g-tip">{d.ui.chainsLead}</p>}
            {publicDone && chains.length === 0 && <p>{d.ui.chainsNone}</p>}
            {chains.map((chain, i) => <ChainCard key={`${chain.id}${i}`} chain={chain} />)}
          </section>
          {changes && (
            <section className="deep-part deep-changes">
              <h3>{d.ui.since(changes.since)}</h3>
              {!changes.newHosts.length && !changes.newProblems.length && !changes.solved.length && <p>{d.ui.noChange}</p>}
              {changes.newHosts.length > 0 && <p><strong>{d.ui.newHosts}:</strong> {changes.newHosts.join(', ')}</p>}
              {changes.newProblems.length > 0 && <p><strong>{d.ui.newProblems}:</strong> {changes.newProblems.map(problemTitle).join('; ')}</p>}
              {changes.solved.length > 0 && <p><strong>{d.ui.solved}:</strong> {changes.solved.map(problemTitle).join('; ')}</p>}
            </section>
          )}
          {PUBLIC.map((id) => <Section key={id} id={id} part={parts[id]} onRetry={() => runModule(id, target, true)} />)}
          <Ownership key={target} target={target} part={parts.active} onCheck={() => runModule('active', target)} />
          <p className="g-tip">{d.ui.limits}</p>
        </div>
      )}
    </>
  )
}
