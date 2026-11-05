// Attack scenarios: rules over facts the deep analysis actually found. A rule fires only on real findings, and
// its words (deepText.ts) say what could happen, never that it has or will. Order is what to do first.
export type DeepItem = { id: string; status: 'ok' | 'warn' | 'fail' | 'info'; params: Record<string, unknown> }
export type Level = 'critical' | 'high' | 'medium'
export type Chain = { id: string; level: Level; params: Record<string, unknown>; covers: DeepItem[] }
export type Evidence = { items: DeepItem[]; csp?: boolean | null; hsts?: boolean | null }

const SECRET_KINDS = ['env', 'git', 'svn', 'config', 'database', 'passwords', 'key', 'phpinfo', 'backup', 'log', 'debug']
const LEVEL_ORDER: Record<Level, number> = { critical: 0, high: 1, medium: 2 }

export function findChains({ items, csp, hsts }: Evidence): Chain[] {
  const all = (id: string) => items.filter((x) => x.id === id)
  const first = (id: string) => all(id)[0]
  const chains: Chain[] = []
  const add = (id: string, level: Level, params: Record<string, unknown>, covers: DeepItem[]) => chains.push({ id, level, params, covers })

  const takeovers = all('takeover_risk')
  const mailOpen = all('spoof_open').concat(all('spf_pass_all'))
  if (takeovers.length && mailOpen.length) add('brand_phish', 'critical', takeovers[0].params, [takeovers[0], ...mailOpen])
  else {
    takeovers.forEach((x) => add('subdomain_takeover', 'high', x.params, [x]))
    if (mailOpen.length) add('fake_mail', 'high', {}, mailOpen)
  }
  all('safe_browsing_listed').forEach((x) => add('browser_warning', 'critical', x.params, [x]))
  all('js_secret').forEach((x) => add('leaked_key', 'critical', x.params, [x]))
  const plainPasswords = all('password_plain').concat(all('password_plain_pages'))
  if (plainPasswords.length) add('password_exposed', 'critical', {}, plainPasswords)
  all('sqli_found').forEach((x) => add('sql_injection', 'critical', x.params, [x]))
  all('xss_found').forEach((x) => add('xss', 'critical', x.params, [x]))
  all('exposed_file').filter((x) => SECRET_KINDS.includes(String(x.params.kind))).forEach((x) => add('exposed_secret', 'critical', x.params, [x]))
  all('open_port').filter((x) => x.status === 'fail').forEach((x) => add('open_database', 'critical', x.params, [x]))
  if (csp === false) {
    const vulnerable = all('vuln_library').sort((a, b) => Number(b.status === 'fail') - Number(a.status === 'fail'))[0]
    if (vulnerable) add('script_injection', vulnerable.status === 'fail' ? 'high' : 'medium', vulnerable.params, [vulnerable])
  }
  all('plugin_vuln').concat(all('plugin_closed')).forEach((x) => add('plugin_risk', 'high', x.params, [x]))
  all('cors_reflect').forEach((x) => add('data_read', 'high', {}, [x]))
  all('dir_listing').forEach((x) => add('open_folder', 'high', x.params, [x]))
  const expiry = first('domain_expiry')
  if (expiry && expiry.status !== 'ok') add('domain_loss', expiry.status === 'fail' ? 'high' : 'medium', expiry.params, [expiry])
  all('rep_listed').slice(0, 1).forEach((x) => add('bad_reputation', 'high', x.params, [x]))
  all('axfr_open').forEach((x) => add('zone_open', 'medium', x.params, [x]))
  if (first('sri_missing') && csp === false) add('outside_code', 'medium', first('sri_missing').params, [first('sri_missing')])
  all('cve_server').forEach((x) => add('server_cves', 'medium', x.params, [x]))
  all('eol_runtime').forEach((x) => add('old_runtime', 'medium', x.params, [x]))
  if (first('sensitive_hosts')) add('forgotten_service', 'medium', first('sensitive_hosts').params, [first('sensitive_hosts')])
  all('dangling_cname').slice(0, 3).forEach((x) => add('dangling_record', 'medium', x.params, [x]))
  if (first('csrf_missing')) add('csrf', 'medium', first('csrf_missing').params, [first('csrf_missing')])
  const weakTls = all('tls_old').concat(all('tls_weak_cipher'), all('http_no_redirect'))
  if (weakTls.length && hsts === false) add('weak_transport', 'medium', {}, weakTls)

  return chains.sort((a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level])
}

// What to do, in order: the scenarios first, then every other problem that no scenario already speaks for
export type Step = { chain: Chain } | { item: DeepItem }

export function actionPlan(chains: Chain[], items: DeepItem[]): Step[] {
  const covered = new Set(chains.flatMap((c) => c.covers))
  const rest = items.filter((x) => (x.status === 'fail' || x.status === 'warn') && !covered.has(x))
  return [
    ...chains.map((chain) => ({ chain })),
    ...rest.filter((x) => x.status === 'fail').map((item) => ({ item })),
    ...rest.filter((x) => x.status === 'warn').map((item) => ({ item })),
  ]
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
