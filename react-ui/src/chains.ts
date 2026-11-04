// Attack scenarios: rules over facts the deep analysis actually found. A rule fires only on real findings, and
// its words (deepText.ts) say what could happen, never that it has or will. Order is what to do first.
export type DeepItem = { id: string; status: 'ok' | 'warn' | 'fail' | 'info'; params: Record<string, unknown> }
export type Level = 'critical' | 'high' | 'medium'
export type Chain = { id: string; level: Level; params: Record<string, unknown> }
export type Evidence = { items: DeepItem[]; csp?: boolean | null; hsts?: boolean | null }

const SECRET_KINDS = ['env', 'git', 'svn', 'config', 'database', 'passwords', 'key', 'phpinfo']
const LEVEL_ORDER: Record<Level, number> = { critical: 0, high: 1, medium: 2 }

export function findChains({ items, csp, hsts }: Evidence): Chain[] {
  const all = (id: string) => items.filter((x) => x.id === id)
  const first = (id: string) => all(id)[0]
  const chains: Chain[] = []
  const add = (id: string, level: Level, params: Record<string, unknown> = {}) => chains.push({ id, level, params })

  const takeovers = all('takeover_risk')
  const mailOpen = first('spoof_open') || first('spf_pass_all')
  if (takeovers.length && mailOpen) add('brand_phish', 'critical', takeovers[0].params)
  else {
    takeovers.forEach((x) => add('subdomain_takeover', 'high', x.params))
    if (mailOpen) add('fake_mail', 'high')
  }
  all('exposed_file').filter((x) => SECRET_KINDS.includes(String(x.params.kind))).forEach((x) => add('exposed_secret', 'critical', x.params))
  all('open_port').filter((x) => x.status === 'fail').forEach((x) => add('open_database', 'critical', x.params))
  if (csp === false) {
    const vulnerable = all('vuln_library').sort((a, b) => Number(b.status === 'fail') - Number(a.status === 'fail'))[0]
    if (vulnerable) add('script_injection', vulnerable.status === 'fail' ? 'high' : 'medium', vulnerable.params)
  }
  const expiry = first('domain_expiry')
  if (expiry && expiry.status !== 'ok') add('domain_loss', expiry.status === 'fail' ? 'high' : 'medium', expiry.params)
  all('rep_listed').slice(0, 1).forEach((x) => add('bad_reputation', 'high', x.params))
  all('eol_runtime').forEach((x) => add('old_runtime', 'medium', x.params))
  if (first('sensitive_hosts')) add('forgotten_service', 'medium', first('sensitive_hosts').params)
  all('dangling_cname').slice(0, 3).forEach((x) => add('dangling_record', 'medium', x.params))
  if ((first('tls_old') || first('tls_weak_cipher')) && hsts === false) add('weak_transport', 'medium')

  return chains.sort((a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level])
}

// What the browser remembers between checks of one site, so a later check can say what changed
export type Snapshot = { at: string; hosts: string[]; problems: string[] }
export type Changes = { since: string; newHosts: string[]; newProblems: string[]; solved: string[] }

export function snapshotOf(items: DeepItem[], hosts: string[], at: string): Snapshot {
  const problems = items.filter((x) => x.status === 'fail' || x.status === 'warn').map((x) => `${x.id}|${JSON.stringify(x.params)}`)
  return { at, hosts: [...hosts].sort(), problems: [...new Set(problems)].sort() }
}

export function compareSnapshots(old: Snapshot, now: Snapshot): Changes {
  return {
    since: old.at,
    newHosts: now.hosts.filter((x) => !old.hosts.includes(x)),
    newProblems: now.problems.filter((x) => !old.problems.includes(x)),
    solved: old.problems.filter((x) => !now.problems.includes(x)),
  }
}
