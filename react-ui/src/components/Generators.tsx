import { useState } from 'react'
import type { ReactNode } from 'react'
import {
  AI_BOTS, SPF_LOOKUP_LIMIT, SPF_PROVIDERS, cspPolicy, dmarcRecord, explainRecord, headerConfigs, headerList, metaTags,
  redirectConfigs, robotsTxt, securityTxt, sitemapXml, spfRecord,
} from '../generators'
import type { Output as OutputItem } from '../generators'
import { g } from '../genText'
import type { GeneratorId } from '../genText'
import { saveFile } from '../pdf'

// ---------------------------------------------------------------- small form parts
function Text({ label, value, onChange, hint, type = 'text', rows }: { label: string; value: string; onChange: (v: string) => void; hint?: string; type?: string; rows?: number }) {
  return (
    <label className="g-field">
      <span>{label}</span>
      {rows
        ? <textarea rows={rows} value={value} placeholder={hint} spellCheck={false} onInput={(e) => onChange(e.currentTarget.value)} />
        : <input type={type} value={value} placeholder={hint} spellCheck={false} autoComplete="off" onInput={(e) => onChange(e.currentTarget.value)} />}
    </label>
  )
}

function Choice({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: [string, string][] }) {
  return (
    <label className="g-field">
      <span>{label}</span>
      <select value={value} onChange={(e) => onChange(e.currentTarget.value)}>
        {options.map(([v, name]) => <option key={v} value={v}>{name}</option>)}
      </select>
    </label>
  )
}

function Tick({ label, on, onChange }: { label: string; on: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="g-tick">
      <input type="checkbox" checked={on} onChange={(e) => onChange(e.currentTarget.checked)} />
      <span>{label}</span>
    </label>
  )
}

function Code({ label, code, file }: { label?: string; code: string; file?: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      window.prompt(g.copy, code)     // the browser refused the clipboard
    }
  }
  return (
    <div className="g-output">
      <div className="g-output-top">
        <span>{label || g.result}</span>
        <div>
          {file && <button className="btn btn-ghost" type="button" onClick={() => saveFile(new File([code], file, { type: 'text/plain' }))}>{g.download}</button>}
          <button className="btn btn-primary" type="button" onClick={copy} aria-live="polite">{copied ? g.copied : g.copy}</button>
        </div>
      </div>
      <pre tabIndex={0}><code>{code}</code></pre>
    </div>
  )
}

const Tip = ({ children, warn }: { children: ReactNode; warn?: boolean }) => <p className={warn ? 'g-tip warn' : 'g-tip'}>{children}</p>
const Outputs = ({ items }: { items: OutputItem[] }) => <>{items.map((x) => <Code key={x.label} label={x.label} code={x.code} />)}</>

function DnsRecord({ name, value }: { name: string; value: string }) {
  return (
    <>
      <dl className="facts g-dns">
        <div><dt>{g.dnsName}</dt><dd>{name}</dd></div>
        <div><dt>{g.dnsType}</dt><dd>TXT</dd></div>
      </dl>
      <Code label={g.dnsValue} code={value} />
      <Tip>{g.dnsNote}</Tip>
    </>
  )
}

const plusYear = () => { const d = new Date(); d.setFullYear(d.getFullYear() + 1); return d.toISOString().slice(0, 10) }

// ---------------------------------------------------------------- generators
function Dmarc() {
  const [policy, setPolicy] = useState('none')
  const [subdomains, setSubdomains] = useState('')
  const [percent, setPercent] = useState('100')
  const [reports, setReports] = useState('')
  const [forensic, setForensic] = useState('')
  const [strict, setStrict] = useState(false)
  const policies: [string, string][] = [['none', g.policyNone], ['quarantine', g.policyQuarantine], ['reject', g.policyReject]]
  return (
    <>
      <Choice label={g.policy} value={policy} onChange={setPolicy} options={policies} />
      <Tip>{g.policyTip}</Tip>
      <Choice label={g.subdomains} value={subdomains} onChange={setSubdomains} options={[['', g.sameAsMain], ...policies]} />
      <Text label={g.percent} type="number" value={percent} onChange={setPercent} />
      <Text label={g.reports} value={reports} onChange={setReports} hint="dmarc@example.az" />
      <Text label={g.forensic} value={forensic} onChange={setForensic} />
      <Tick label={g.strict} on={strict} onChange={setStrict} />
      <DnsRecord name="_dmarc" value={dmarcRecord({ policy, subdomains, percent: Math.min(100, Number(percent) || 0), reports, forensic, strict })} />
    </>
  )
}

function Spf() {
  const [providers, setProviders] = useState<string[]>([])
  const [mx, setMx] = useState(false)
  const [a, setA] = useState(false)
  const [ips, setIps] = useState('')
  const [extra, setExtra] = useState('')
  const [ending, setEnding] = useState('~all')
  const { record, lookups } = spfRecord({ providers, mx, a, ips, extra, ending })
  const over = lookups > SPF_LOOKUP_LIMIT
  return (
    <>
      <fieldset className="g-group">
        <legend>{g.providers}</legend>
        {SPF_PROVIDERS.map((p) => (
          <Tick key={p.id} label={p.name} on={providers.includes(p.id)}
            onChange={(on) => setProviders(on ? [...providers, p.id] : providers.filter((x) => x !== p.id))} />
        ))}
        <Tick label={g.spfMx} on={mx} onChange={setMx} />
        <Tick label={g.spfA} on={a} onChange={setA} />
      </fieldset>
      <Text label={g.ips} value={ips} onChange={setIps} hint="203.0.113.10" />
      <Text label={g.extra} value={extra} onChange={setExtra} hint="spf.example.az" />
      <Choice label={g.ending} value={ending} onChange={setEnding} options={[['~all', g.endingSoft], ['-all', g.endingHard]]} />
      <p className={over ? 'g-count warn' : 'g-count'}>{g.lookups(lookups, SPF_LOOKUP_LIMIT)}</p>
      <Tip warn={over}>{over ? g.lookupsWarn : g.lookupsNote}</Tip>
      <DnsRecord name="@" value={record} />
      <Tip>{g.spfOneOnly} {g.providerCheck}</Tip>
    </>
  )
}

function Headers() {
  const [hsts, setHsts] = useState(true)
  const [days, setDays] = useState('365')
  const [subs, setSubs] = useState(false)
  const [frame, setFrame] = useState('SAMEORIGIN')
  const [nosniff, setNosniff] = useState(true)
  const [referrer, setReferrer] = useState('strict-origin-when-cross-origin')
  const [permissions, setPermissions] = useState(true)
  const [csp, setCsp] = useState('')
  const list = headerList({ hsts, hstsDays: Number(days) || 0, subdomains: subs, frame, nosniff, referrer, permissions, csp })
  return (
    <>
      <Tick label={g.hsts} on={hsts} onChange={setHsts} />
      {hsts && (
        <>
          <Text label={g.hstsDays} type="number" value={days} onChange={setDays} />
          <Tick label={g.hstsSubs} on={subs} onChange={setSubs} />
          {subs && <Tip warn>{g.hstsTip}</Tip>}
        </>
      )}
      <Choice label={g.frame} value={frame} onChange={setFrame} options={[['SAMEORIGIN', g.frameSame], ['DENY', g.frameDeny], ['', g.frameOff]]} />
      <Tick label={g.nosniff} on={nosniff} onChange={setNosniff} />
      <Choice label={g.referrer} value={referrer} onChange={setReferrer}
        options={[['strict-origin-when-cross-origin', g.referrerStrict], ['no-referrer', g.referrerNone], ['', g.referrerOff]]} />
      <Tick label={g.permissions} on={permissions} onChange={setPermissions} />
      <Text label={g.cspHeader} rows={2} value={csp} onChange={setCsp} hint="default-src 'self'" />
      <Tip>{g.cspHeaderTip}</Tip>
      <Outputs items={headerConfigs(list)} />
    </>
  )
}

function Csp() {
  const [scripts, setScripts] = useState('')
  const [styles, setStyles] = useState('')
  const [images, setImages] = useState('')
  const [fonts, setFonts] = useState('')
  const [connect, setConnect] = useState('')
  const [frames, setFrames] = useState('')
  const [inlineStyles, setInlineStyles] = useState(false)
  const [embed, setEmbed] = useState('none')
  const policy = cspPolicy({ scripts, styles, images, fonts, connect, frames, inlineStyles, embed })
  return (
    <>
      <Tip>{g.sourcesHint}</Tip>
      <Text label={g.scripts} value={scripts} onChange={setScripts} />
      <Text label={g.styles} value={styles} onChange={setStyles} />
      <Text label={g.images} value={images} onChange={setImages} />
      <Text label={g.fonts} value={fonts} onChange={setFonts} />
      <Text label={g.connect} value={connect} onChange={setConnect} />
      <Text label={g.frames} value={frames} onChange={setFrames} />
      <Tick label={g.inlineStyles} on={inlineStyles} onChange={setInlineStyles} />
      <Choice label={g.embed} value={embed} onChange={setEmbed} options={[['none', g.embedNone], ['self', g.embedSelf]]} />
      <Code code={policy} />
      <Tip>{g.cspTip}</Tip>
      <Outputs items={headerConfigs([['Content-Security-Policy-Report-Only', policy]])} />
    </>
  )
}

function Robots() {
  const [blockAll, setBlockAll] = useState(false)
  const [paths, setPaths] = useState('')
  const [blockAi, setBlockAi] = useState(false)
  const [sitemap, setSitemap] = useState('')
  return (
    <>
      <Tick label={g.blockAll} on={blockAll} onChange={setBlockAll} />
      {blockAll && <Tip warn>{g.blockAllWarn}</Tip>}
      {!blockAll && <Text label={g.paths} value={paths} onChange={setPaths} hint={g.pathsHint} />}
      <Tick label={`${g.blockAi} (${AI_BOTS.join(', ')})`} on={blockAi} onChange={setBlockAi} />
      <Text label={g.sitemapUrl} value={sitemap} onChange={setSitemap} hint="https://example.az/sitemap.xml" />
      <Code code={robotsTxt({ blockAll, paths, blockAi, sitemap })} file="robots.txt" />
      <Tip>{g.robotsTip}</Tip>
    </>
  )
}

function Meta() {
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [url, setUrl] = useState('')
  const [image, setImage] = useState('')
  const [siteName, setSiteName] = useState('')
  const counted = (n: number, a: number, b: number) => <p className={n && (n < a || n > b) ? 'g-count warn' : 'g-count'}>{g.chars(n, a, b)}</p>
  return (
    <>
      <Text label={g.title} value={title} onChange={setTitle} />
      {counted(title.length, 10, 70)}
      <Text label={g.description} rows={3} value={description} onChange={setDescription} />
      {counted(description.length, 50, 170)}
      <Text label={g.url} value={url} onChange={setUrl} hint="https://example.az/" />
      <Text label={g.image} value={image} onChange={setImage} hint="https://example.az/image.png" />
      <Text label={g.siteName} value={siteName} onChange={setSiteName} />
      <Code code={metaTags({ title, description, url, image, siteName })} />
      <Tip>{g.metaTip}</Tip>
    </>
  )
}

function Sitemap() {
  const [urls, setUrls] = useState('')
  const [lastmod, setLastmod] = useState('')
  return (
    <>
      <Text label={g.urls} rows={5} value={urls} onChange={setUrls} hint={'https://example.az/\nhttps://example.az/about'} />
      <Text label={g.lastmod} type="date" value={lastmod} onChange={setLastmod} />
      <Code code={sitemapXml(urls, lastmod)} file="sitemap.xml" />
      <Tip>{g.sitemapTip}</Tip>
    </>
  )
}

function Security() {
  const [contact, setContact] = useState('')
  const [expires, setExpires] = useState(plusYear)
  const [languages, setLanguages] = useState('az en ru')
  const [policy, setPolicy] = useState('')
  return (
    <>
      <Text label={g.contact} value={contact} onChange={setContact} hint="security@example.az" />
      <Text label={g.expires} type="date" value={expires} onChange={setExpires} />
      <Text label={g.languages} value={languages} onChange={setLanguages} />
      <Text label={g.policyUrl} value={policy} onChange={setPolicy} />
      <Code code={securityTxt(contact, expires, languages, policy)} file="security.txt" />
      <Tip>{g.securityTip}</Tip>
    </>
  )
}

function Redirect() {
  const [domain, setDomain] = useState('')
  const [mode, setMode] = useState('bare')
  return (
    <>
      <Text label={g.domain} value={domain} onChange={setDomain} hint="example.az" />
      <Choice label={g.mode} value={mode} onChange={setMode} options={[['bare', g.modeBare], ['www', g.modeWww]]} />
      <Tip>{g.redirectTip}</Tip>
      <Outputs items={redirectConfigs(domain, mode)} />
    </>
  )
}

function Explain() {
  const [record, setRecord] = useState('')
  const result = explainRecord(record)
  return (
    <>
      <Text label={g.recordInput} rows={3} value={record} onChange={setRecord} hint={g.recordHint} />
      {record.trim() && result.kind === 'unknown' && <Tip warn>{g.notRecord}</Tip>}
      {result.items.length > 0 && (
        <dl className="facts g-explain">
          {result.items.map((item, i) => (
            <div key={i}>
              <dt><code>{item.token}</code></dt>
              <dd>{g.explain[item.key] || g.explain.unknownPart}</dd>
            </div>
          ))}
        </dl>
      )}
      {result.kind === 'spf' && (
        <>
          <p className={result.lookups > SPF_LOOKUP_LIMIT ? 'g-count warn' : 'g-count'}>{g.lookups(result.lookups, SPF_LOOKUP_LIMIT)}</p>
          <Tip warn={result.lookups > SPF_LOOKUP_LIMIT}>{result.lookups > SPF_LOOKUP_LIMIT ? g.lookupsWarn : g.lookupsNote}</Tip>
        </>
      )}
    </>
  )
}

const SCREENS: Record<GeneratorId, () => ReactNode> = {
  dmarc: Dmarc, spf: Spf, headers: Headers, csp: Csp, robots: Robots, meta: Meta, sitemap: Sitemap, security: Security, redirect: Redirect, explain: Explain,
}

export function Generator({ id }: { id: GeneratorId }) {
  const Screen = SCREENS[id]
  return <div className="generator"><Screen /></div>
}
