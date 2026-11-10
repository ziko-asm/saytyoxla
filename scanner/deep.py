"""
Deep analysis: what an attacker could learn about a domain from the outside.

surface, mail, tech, tls and reputation only read public information: certificate logs, DNS, the home page
and public databases. active probes for exposed files and open ports, so it runs only after the owner
has proved control of the site (see ownership_token).

Each module returns {"module", "host", "items", "data"}. An item is a code, a status and parameters: the
words live in react-ui/src/deepText.ts in three languages, and tests/test_deep.py keeps the two in step.
Nothing here may return a secret: for an exposed file the report names the path, never the content.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait as wait_for
from datetime import date, datetime, timezone
from urllib.parse import urljoin, urlsplit

import requests

from scanner import checks, cve, fetch, injection, page_audit, tlsprobe
from scanner.models import Context
from scanner.safety import HOST_RE, UnsafeTarget, is_public_ip, normalize, resolve_public

MAX_HOSTS = 60              # subdomains looked at per scan
SURFACE_BUDGET = 22         # seconds for all of them
HTTP_TIMEOUT = 8
FILE_BUDGET = 4
PORT_TIMEOUT = 2.5
SPF_LIMIT = 10
SPF_BUDGET = 15
ACTIVE_BUDGET = 30
OWNERSHIP_DNS = "_saytyoxla-verify"
OWNERSHIP_FILE = "/.well-known/saytyoxla.txt"
HEADERS = {"User-Agent": fetch.USER_AGENT}

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"


def _item(item_id: str, status: str, /, **params) -> dict:
    return {"id": item_id, "status": status, "params": params}


def _host(raw: str) -> str:
    return normalize(raw).split("/")[2]


def _domain(raw: str) -> str:
    return fetch.mail_domain(_host(raw))


def _result(module: str, host: str, items: list, **data) -> dict:
    return {"module": module, "host": host, "items": items, "data": data}


# ---------------------------------------------------------------- attack surface
SENSITIVE = re.compile(r"(^|[-.])(dev|develop|test|testing|stage|staging|uat|qa|old|beta|demo|backup|bak|admin|administrator|"
                       r"cpanel|whm|plesk|phpmyadmin|pma|db|database|mysql|jenkins|gitlab|git|grafana|kibana|vpn|ftp|internal|"
                       r"intranet)($|[-.])")

# CNAME target -> what the provider says for a name nobody has claimed, where anyone can then claim it. Each message
# was checked against the provider's real answer for a made-up name. An empty one means a missing target is the sign.
TAKEOVER = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "herokudns.com": "No such app",
    "amazonaws.com": "NoSuchBucket",
    "bitbucket.io": "Repository not found",
    "surge.sh": "project not found",
    "ghost.io": "Failed to resolve DNS path for this host",
    "pantheonsite.io": "Unknown site",
    "readthedocs.io": "Project not found",
    "helpscoutdocs.com": "No settings were found for this company",
    "helpjuice.com": "We could not find what you're looking for",
    "hatenablog.com": "404 Blog is not found",
    "launchrock.com": "It looks like you may have taken a wrong turn",
    "azurewebsites.net": "",
    "cloudapp.net": "",
    "cloudapp.azure.com": "",
    "trafficmanager.net": "",
}
# Here the service is gone too, but the provider ties a name to its owner, so calling it a takeover would be untrue
DEAD = {
    "netlify.app": "Not Found - Request ID", "netlify.com": "Not Found - Request ID",
    "vercel.app": "DEPLOYMENT_NOT_FOUND", "vercel-dns.com": "DEPLOYMENT_NOT_FOUND",
    "firebaseapp.com": "Site Not Found", "web.app": "Site Not Found",
    "myshopify.com": "Store unavailable", "squarespace.com": "No Such Website", "webflow.io": "The page you are looking for doesn",
}


def _issuer_org(name: str) -> str:
    m = re.search(r"\bO=\"?([^,\"]+)", name or "")
    return m.group(1).strip() if m else ""


def _cert_spotter(domain: str) -> list | None:
    r = requests.get("https://api.certspotter.com/v1/issuances", headers=HEADERS, timeout=HTTP_TIMEOUT,
                     params={"domain": domain, "include_subdomains": "true", "expand": ["dns_names", "issuer"]})
    if r.status_code != 200:
        return None
    return [{"names": e.get("dns_names", []), "issuer": (e.get("issuer") or {}).get("friendly_name") or _issuer_org((e.get("issuer") or {}).get("name", "")),
             "from": e.get("not_before", "")[:10], "to": e.get("not_after", "")[:10]} for e in r.json()]


def _crt_sh(domain: str) -> list | None:
    r = requests.get("https://crt.sh/", headers=HEADERS, timeout=HTTP_TIMEOUT, params={"q": f"%.{domain}", "output": "json"})
    if r.status_code != 200:
        return None
    return [{"names": e.get("name_value", "").split(), "issuer": _issuer_org(e.get("issuer_name", "")),
             "from": e.get("not_before", "")[:10], "to": e.get("not_after", "")[:10]} for e in r.json()]


def _certificate_log(domain: str) -> list | None:
    for source in (_cert_spotter, _crt_sh):
        try:
            entries = source(domain)
        except (requests.RequestException, ValueError):
            continue
        if entries is not None:
            return entries
    return None


def certificate_names(entries: list, domain: str) -> set:
    found = {n.lower().lstrip("*.").rstrip(".") for e in entries for n in e["names"]}
    return {n for n in found if (n == domain or n.endswith("." + domain)) and HOST_RE.match(n)}


def certificate_stats(entries: list) -> dict:
    today = datetime.now(timezone.utc).date().isoformat()
    starts = sorted(e["from"] for e in entries if e.get("from"))
    active = [e for e in entries if e.get("to", "") >= today]
    return {"count": len(entries), "active": len(active), "first": starts[0] if starts else "", "last": starts[-1] if starts else "",
            "next_expiry": min((e["to"] for e in active), default=""), "issuers": sorted({e["issuer"] for e in entries if e.get("issuer")})[:6]}


def _provider_of(target: str, table: dict = TAKEOVER) -> str | None:
    return next((p for p in table if target == p or target.endswith("." + p)), None)


def _service_says(host: str, sign: str) -> bool:
    """Does the provider itself answer for this name with its "nobody here" message?"""
    if not sign:
        return False
    for scheme in ("https", "http"):
        try:
            _, _, _, _, body, _ = fetch._get(f"{scheme}://{host}/", budget=FILE_BUDGET, verify=False)
        except (requests.RequestException, UnsafeTarget):
            continue
        return sign.lower().encode() in body.lower()
    return False


def inspect_host(host: str) -> dict:
    cname = fetch.dns_lookup(host, "CNAME")
    target = str(cname[1][0].target).rstrip(".").lower() if cname[0] == "ok" else ""
    ips = [r.address for r in fetch.dns_lookup(host, "A")[1]]
    out = {"host": host, "live": bool(ips), "cname": target, "ips": ips[:3], "flag": ""}
    if target:
        provider = _provider_of(target)
        dead = _provider_of(target, DEAD)
        target_state = fetch.dns_lookup(target, "A")[0]
        if target_state == "nx":
            out["flag"] = "takeover" if provider else "dangling"
        elif provider and _service_says(host, TAKEOVER[provider]):
            out["flag"] = "takeover"
        elif dead and _service_says(host, DEAD[dead]):
            out["flag"] = "dead"
    if ips and not all(is_public_ip(ip) for ip in ips):
        out["flag"] = out["flag"] or "private"
    if not out["flag"] and out["live"] and SENSITIVE.search(host):
        out["flag"] = "sensitive"
    return out


def surface(raw: str) -> dict:
    domain = _domain(raw)
    entries = _certificate_log(domain)
    if entries is None:
        return _result("surface", domain, [_item("surface_unavailable", INFO)], hosts=[], total=0)
    names = certificate_names(entries, domain)
    names.discard(domain)
    names.discard("www." + domain)
    # Names that look sensitive first: with a very long list they are the ones worth the time
    ordered = sorted(names, key=lambda n: (not SENSITIVE.search(n), n))
    chosen = ordered[:MAX_HOSTS]
    pool = ThreadPoolExecutor(max_workers=12)
    jobs = [pool.submit(inspect_host, h) for h in chosen]
    wait_for(jobs, timeout=SURFACE_BUDGET)
    pool.shutdown(wait=False, cancel_futures=True)
    hosts = [j.result() for j in jobs if j.done() and not j.cancelled() and not j.exception()]
    by_flag = lambda flag: [h["host"] for h in hosts if h["flag"] == flag]

    items = [_item("surface_count", INFO, total=len(names), live=sum(h["live"] for h in hosts))]
    for h in hosts:
        if h["flag"] == "takeover":
            items.append(_item("takeover_risk", FAIL, host=h["host"], target=h["cname"]))
        elif h["flag"] == "dangling":
            items.append(_item("dangling_cname", WARN, host=h["host"], target=h["cname"]))
        elif h["flag"] == "dead":
            items.append(_item("dead_service", WARN, host=h["host"], target=h["cname"]))
    if by_flag("sensitive"):
        items.append(_item("sensitive_hosts", WARN, hosts=", ".join(by_flag("sensitive")[:8]), count=len(by_flag("sensitive"))))
    if by_flag("private"):
        items.append(_item("private_ip", WARN, hosts=", ".join(by_flag("private")[:8])))
    if len(items) == 1:
        items.append(_item("surface_clean", OK))
    if len(hosts) < len(chosen) or len(names) > MAX_HOSTS:
        items.append(_item("surface_partial", INFO, checked=len(hosts), total=len(names)))
    order = {"takeover": 0, "dangling": 1, "dead": 1, "private": 2, "sensitive": 3, "": 4}
    return _result("surface", domain, items, total=len(names), certs=certificate_stats(entries), hosts=sorted(hosts, key=lambda h: (order[h["flag"]], h["host"])))


# ---------------------------------------------------------------- e-mail
LOOKUP_TERMS = ("include", "a", "mx", "ptr", "exists")


def _spf_of(records: list | None) -> list:
    return [r for r in records or [] if r.lower().startswith("v=spf1")]


def spf_tree(domain: str, seen: set | None = None, depth: int = 0, deadline: float | None = None, steps: list | None = None) -> dict:
    """How many DNS lookups an SPF record really costs, following every include."""
    seen = set() if seen is None else seen
    deadline = time.monotonic() + SPF_BUDGET if deadline is None else deadline
    result = {"lookups": 0, "void": 0, "unknown": False}
    if domain in seen or depth > 10:
        return result
    if time.monotonic() > deadline:
        result["unknown"] = True
        return result
    seen.add(domain)
    records = fetch.txt_records(domain)
    if records is None:
        result["unknown"] = True
    spf = _spf_of(records)
    if not spf:
        result["void"] += records == []
        return result
    own = 0
    step = {"domain": domain, "depth": depth, "lookups": 0}
    if steps is not None:
        steps.append(step)
    for term in spf[0].split()[1:]:
        body = term.lower().lstrip("+-~?")
        mech = re.split(r"[:/=]", body)[0]
        if mech in LOOKUP_TERMS or mech == "redirect":
            result["lookups"] += 1
            own += 1
            step["lookups"] = own
        if mech in ("include", "redirect") and re.search(r"[:=]", body):
            sub = spf_tree(re.split(r"[:=]", term, maxsplit=1)[1].strip(), seen, depth + 1, deadline, steps)
            for key in ("lookups", "void"):
                result[key] += sub[key]
            result["unknown"] = result["unknown"] or sub["unknown"]
    return result


def dkim_bits(record: str) -> int | None:
    """Rough size of a DKIM key. An RSA key's encoded form grows with it: about 162 bytes for 1024 bits, 294 for 2048."""
    m = re.search(r"(?:^|;)\s*p\s*=\s*([A-Za-z0-9+/=\s]+)", record)
    if not m:
        return None
    if "ed25519" in record.lower():
        return 256
    key = re.sub(r"[\s=]", "", m.group(1))
    try:
        size = len(base64.b64decode(key + "=" * (-len(key) % 4)))
    except ValueError:
        return None
    return 1024 if size < 200 else 2048 if size < 400 else 4096


def _dkim_records(domain: str) -> dict | None:
    with ThreadPoolExecutor(max_workers=len(fetch.DKIM_SELECTORS)) as pool:
        answers = list(pool.map(lambda s: (s, fetch.txt_records(f"{s}._domainkey.{domain}")), fetch.DKIM_SELECTORS))
    if all(records is None for _, records in answers):
        return None
    return {s: next(r for r in records if fetch.DKIM_KEY.search(r)) for s, records in answers
            if records and any(fetch.DKIM_KEY.search(r) for r in records)}


def _mta_sts_mode(domain: str) -> str | None:
    if not any(r.lower().startswith("v=stsv1") for r in fetch.txt_records("_mta-sts." + domain) or []):
        return None
    try:
        r, _, _, _, body, _ = fetch._get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", budget=FILE_BUDGET)
    except (requests.RequestException, UnsafeTarget):
        return "broken"
    if r.status_code != 200:
        return "broken"
    m = re.search(r"(?im)^mode:\s*(\w+)", body.decode("utf-8", "replace"))
    return m.group(1).lower() if m else "broken"


def mail(raw: str) -> dict:
    domain = _domain(raw)
    ctx = Context(input_url=f"https://{domain}/", final_url=f"https://{domain}/", host=domain)
    if checks.on_platform(ctx):
        return _result("mail", domain, [_item("mail_platform", INFO)], records={})
    with ThreadPoolExecutor(max_workers=6) as pool:
        spf_job = pool.submit(fetch.txt_records, domain)
        dmarc_job = pool.submit(fetch.dmarc_records, domain)
        steps = []
        tree_job = pool.submit(spf_tree, domain, None, 0, None, steps)
        dkim_job = pool.submit(_dkim_records, domain)
        mx_job = pool.submit(fetch.dns_lookup, domain, "MX")
        sts_job = pool.submit(_mta_sts_mode, domain)
        rpt_job = pool.submit(fetch.txt_records, "_smtp._tls." + domain)
    txt, (dmarc_recs, parent), tree, dkim = spf_job.result(), dmarc_job.result(), tree_job.result(), dkim_job.result()
    mx_state, mx = mx_job.result()
    items = []

    tags = {}
    policy = None
    rec = next((r for r in dmarc_recs or [] if r.lower().startswith("v=dmarc1")), None)
    if rec:
        tags = dict(p.strip().lower().split("=", 1) for p in rec.split(";") if "=" in p)
        policy = (tags.get("sp") or tags.get("p")) if parent else tags.get("p")
    enforced = policy in ("quarantine", "reject")

    spf = _spf_of(txt)
    if txt is None:
        items.append(_item("dns_unavailable", INFO))
    elif not spf:
        # A DMARC policy that refuses unaligned mail covers a name with no SPF of its own
        items.append(_item("spf_missing", INFO if enforced else FAIL))
    elif len(spf) > 1:
        items.append(_item("spf_multiple", FAIL, count=len(spf)))
    else:
        tail = spf[0].lower().split()[-1]
        if tail in ("+all", "all"):
            items.append(_item("spf_pass_all", FAIL))
        elif tail == "?all":
            items.append(_item("spf_neutral", WARN))
        if tree["lookups"] > SPF_LIMIT:
            items.append(_item("spf_too_many", FAIL, count=tree["lookups"], limit=SPF_LIMIT))
        elif tail not in ("+all", "all", "?all") and not tree["unknown"]:   # an unfinished count proves nothing
            items.append(_item("spf_ok", OK, count=tree["lookups"], limit=SPF_LIMIT))
        if tree["void"] > 2:
            items.append(_item("spf_void", WARN, count=tree["void"]))

    try:
        percent = int(tags.get("pct", "100"))
    except ValueError:
        percent = 100
    if dmarc_recs is None:
        pass    # dns_unavailable already says so, or only this one lookup failed: nothing can be claimed
    elif enforced and percent >= 100:
        items.append(_item("spoof_blocked", OK, policy=policy))
    elif enforced:
        items.append(_item("spoof_partial", WARN, percent=percent))
    else:
        # As in the short check: no record at all is the serious case, a record that only watches (p=none) is advice
        items.append(_item("spoof_open", WARN if rec else FAIL, state="none" if rec else "missing"))
    if rec and "rua" not in tags:
        items.append(_item("dmarc_no_reports", INFO))

    if dkim is None:
        pass
    elif not dkim:
        items.append(_item("dkim_unknown", INFO))
    else:
        weak = [s for s, r in dkim.items() if (dkim_bits(r) or 2048) <= 1024]
        if weak:
            items.append(_item("dkim_weak", WARN, selectors=", ".join(weak[:3])))
        else:
            items.append(_item("dkim_found", OK, selectors=", ".join(list(dkim)[:3])))

    null_mx = mx_state == "ok" and all(str(r.exchange) == "." for r in mx)
    if mx_state in ("none", "nx") or null_mx:
        items.append(_item("mx_none", INFO))
    elif mx_state == "ok":
        mode = sts_job.result()
        if mode == "enforce":
            items.append(_item("mta_sts_ok", OK))
        elif mode == "broken":
            items.append(_item("mta_sts_broken", WARN))
        else:
            items.append(_item("mta_sts_missing", INFO))
        if not any(r.lower().startswith("v=tlsrptv1") for r in rpt_job.result() or []):
            items.append(_item("tls_rpt_missing", INFO))
    mx_hosts = sorted((r.preference, str(r.exchange).rstrip(".")) for r in mx if str(r.exchange) != ".")[:6]
    with ThreadPoolExecutor(max_workers=6) as pool:
        mx_ips = list(pool.map(lambda x: [a.address for a in fetch.dns_lookup(x[1], "A")[1]][:3], mx_hosts))
    return _result("mail", domain, items, spf_lookups=tree["lookups"], spf_limit=SPF_LIMIT, spf_steps=steps[:25], dmarc_tags=tags,
                   dkim=[{"selector": name, "bits": dkim_bits(r)} for name, r in (dkim or {}).items()],
                   mx_hosts=[{"priority": p, "host": h, "ips": i} for (p, h), i in zip(mx_hosts, mx_ips, strict=True)],
                   mta_sts=sts_job.result(), tls_rpt=next((r for r in rpt_job.result() or [] if r.lower().startswith("v=tlsrptv1")), ""),
                   records={"spf": spf, "dmarc": [rec] if rec else [], "dmarc_parent": parent or "",
                                                   "mx": sorted(str(r.exchange).rstrip(".") for r in mx if str(r.exchange) != ".")[:6]})


# ---------------------------------------------------------------- software
# npm package -> file names that reveal it
LIBRARIES = {
    "jquery": r"jquery", "bootstrap": r"bootstrap", "angular": r"angular(?:js)?", "vue": r"vue", "react": r"react",
    "lodash": r"lodash", "moment": r"moment", "handlebars": r"handlebars", "underscore": r"underscore", "dompurify": r"(?:dom)?purify",
}
# End of security support, from php.net
PHP_EOL = {"5.3": "2014-08-14", "5.4": "2015-09-03", "5.5": "2016-07-21", "5.6": "2018-12-31", "7.0": "2019-01-10", "7.1": "2019-12-01", "7.2": "2020-11-30", "7.3": "2021-12-06",
           "7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31", "8.2": "2026-12-31", "8.3": "2027-12-31", "8.4": "2028-12-31"}
CMS_SIGNS = {"WordPress": rb"wp-content/|wp-includes/", "Joomla": rb"/media/jui/|Joomla!", "Drupal": rb"Drupal\.settings|/sites/default/files/",
             "Bitrix": rb"/bitrix/(?:js|templates)/", "Tilda": rb"tildacdn\.", "Wix": rb"static\.wixstatic\.com", "Shopify": rb"cdn\.shopify\.com"}


def detect_libraries(html: str) -> dict:
    """{package: version} from script addresses. Only addresses that state a version count: guessing would invent problems."""
    found = {}
    for src in re.findall(r"""<script[^>]+src=["']([^"']+)""", html, re.IGNORECASE):
        low = src.lower()
        for name, pattern in LIBRARIES.items():
            if name in found:
                continue
            match = (re.search(rf"(?:^|[/\-_.]){pattern}(?:\.min)?[-.@/]v?(\d+\.\d+(?:\.\d+)?)(?:[./\-?]|$)", low)
                     or re.search(rf"/{pattern}(?:\.js)?[@/]v?(\d+\.\d+(?:\.\d+)?)/", low)
                     or re.search(rf"/{pattern}(?:\.min)?\.js\?(?:[^#]*&)?ver=(\d+\.\d+(?:\.\d+)?)", low))
            if match:
                found[name] = match.group(1)
    return found


def _version_key(version: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", version)[:4])


def osv_vulns(name: str, version: str) -> dict | None:
    try:
        r = requests.post("https://api.osv.dev/v1/query", headers=HEADERS, timeout=HTTP_TIMEOUT,
                          json={"package": {"ecosystem": "npm", "name": name}, "version": version})
        if r.status_code != 200:
            return None
        vulns = r.json().get("vulns", [])
    except (requests.RequestException, ValueError):
        return None
    high = sum((v.get("database_specific") or {}).get("severity") in ("HIGH", "CRITICAL") for v in vulns)
    # The version that leaves all of these behind: the highest fix named by any of them
    fixes = [ev["fixed"] for v in vulns for a in v.get("affected", []) for rng in a.get("ranges", []) for ev in rng.get("events", []) if ev.get("fixed")]
    return {"count": len(vulns), "high": high, "ids": [v["id"] for v in vulns[:3]], "fixed": max(fixes, key=_version_key, default="")}


def _fetch_quietly(url: str, budget: float = 3):
    try:
        return fetch._get(url, budget=budget, verify=False)
    except (requests.RequestException, UnsafeTarget):
        return None


def _older(version: str, latest: str) -> bool:
    return bool(version and latest and cve.version_key(version) < cve.version_key(latest))


def _software_items(found: list, items: list) -> list:
    """Known weaknesses for each server program whose exact version is visible."""
    with ThreadPoolExecutor(max_workers=4) as pool:
        answers = list(pool.map(lambda x: cve.server_cves(*x), found))
    rows = []
    unknown = False
    for (name, version), answer in zip(found, answers, strict=True):
        if answer is None:
            unknown = unknown or name.lower() in cve.CPE and version.count(".") >= 1
        elif answer["count"]:
            rows.append({"name": name, "version": version, **answer})
            items.append(_item("cve_server", WARN, name=name, version=version, count=answer["count"], high=answer["high"], ids=", ".join(answer["ids"][:3])))
    if unknown:
        items.append(_item("cve_unavailable", INFO))
    return rows


def _plugin_items(slugs: dict, items: list) -> list:
    chosen = list(slugs.items())[:8]
    with ThreadPoolExecutor(max_workers=6) as pool:
        infos = list(pool.map(lambda kv: cve.plugin_info(kv[0]), chosen))
        vulns = list(pool.map(lambda kv: cve.plugin_vulns(*kv), chosen))
    rows = []
    for (slug, version), info, vuln in zip(chosen, infos, vulns, strict=True):
        info = info or {}
        rows.append({"slug": slug, "version": version, "latest": info.get("latest", ""), "updated": info.get("updated", ""),
                     "closed": info.get("closed", False), "vulns": vuln["count"] if vuln else None})
        if vuln and vuln["count"]:
            items.append(_item("plugin_vuln", FAIL, slug=slug, version=version, count=vuln["count"], ids=", ".join(vuln["ids"])))
        if info.get("closed"):
            items.append(_item("plugin_closed", FAIL, slug=slug))
        elif _older(version, info.get("latest", "")):
            items.append(_item("plugin_old", WARN, slug=slug, version=version, latest=info["latest"]))
    return rows


def tech(raw: str) -> dict:
    url = normalize(raw)
    host = url.split("/")[2]
    blank = {"software": [], "csp": None, "hsts": None}
    try:
        # A bad certificate is the TLS part's finding; the software behind it can still be read
        r, final, chain, elapsed, body, _ = fetch._get(url, budget=10, verify=False)
    except requests.RequestException:
        try:    # a site with no HTTPS at all still has a page to read
            r, final, chain, elapsed, body, _ = fetch._get(f"http://{host}/", budget=8, verify=False)
        except requests.RequestException:
            return _result("tech", host, [_item("page_unavailable", INFO)], **blank)
    headers = {k.lower(): v for k, v in r.headers.items()}
    if r.status_code in (401, 403, 429, 503):
        return _result("tech", host, [_item("page_blocked", INFO, status=r.status_code)], **blank)
    html = body.decode("utf-8", "replace")
    items, software, libs = [], [], []
    base = final.split("?")[0]
    https = final.startswith("https://")
    site = "/".join(final.split("/")[:3])

    for cms, sign in CMS_SIGNS.items():
        if re.search(sign, body):
            software.append({"name": cms, "version": ""})
    generator = (checks.parse(html).meta.get("generator") or "").strip()
    wp = re.match(r"(?i)wordpress\s+(\d+\.\d+(?:\.\d+)?)", generator)
    wp_latest = None
    if wp:
        software = [s for s in software if s["name"] != "WordPress"] + [{"name": "WordPress", "version": wp.group(1)}]
        wp_latest = cve.latest_wordpress()
        if _older(wp.group(1), wp_latest or ""):
            items.append(_item("cms_outdated", WARN, name="WordPress", version=wp.group(1), latest=wp_latest))
        else:
            items.append(_item("cms_version_shown", WARN, name="WordPress", version=wp.group(1)))

    visible = []
    php = re.search(r"PHP/(\d+\.\d+)((?:\.\d+)?)", headers.get("x-powered-by", "") + " " + headers.get("server", ""))
    if php:
        software.append({"name": "PHP", "version": php.group(1) + php.group(2)})
        visible.append(("PHP", php.group(1) + php.group(2)))
        ended = PHP_EOL.get(php.group(1))
        if ended and date.fromisoformat(ended) < datetime.now(timezone.utc).date():
            items.append(_item("eol_runtime", FAIL, name="PHP", version=php.group(1), date=ended))
        else:
            items.append(_item("version_shown", WARN, name="PHP", version=php.group(1)))
    server = re.match(r"(nginx|apache|microsoft-iis|litespeed|openresty)/(\d+(?:\.\d+)*)", headers.get("server", ""), re.IGNORECASE)
    if server:
        software.append({"name": server.group(1), "version": server.group(2)})
        visible.append((server.group(1), server.group(2)))
        items.append(_item("version_shown", WARN, name=server.group(1), version=server.group(2)))
    if wp:
        visible.append(("WordPress", wp.group(1)))

    # The page's own scripts, as any browser fetches them: versions, leaked keys and source maps
    parsed = page_audit.parse(html)
    with ThreadPoolExecutor(max_workers=6) as pool:
        loaded = list(pool.map(_fetch_quietly, page_audit.own_scripts(parsed, base)))
    libraries = detect_libraries(html)
    leaks, maps = {}, []
    for kind in page_audit.find_secrets(body):
        leaks[kind] = "/"
    for answer in loaded:
        if not answer or answer[0].status_code != 200:
            continue
        path = "/" + answer[1].split("/", 3)[-1].split("?")[0][:100]
        for name, version in page_audit.banner_versions(answer[4]).items():
            libraries.setdefault(name, version)
        for kind in page_audit.find_secrets(answer[4]):
            leaks.setdefault(kind, path)
        if re.search(rb"//[#@] ?sourceMappingURL=(?!data:)\S+", answer[4][-2000:]) or "x-sourcemap" in {k.lower() for k in answer[0].headers}:
            maps.append(path)
    for kind, path in leaks.items():
        items.append(_item("js_secret", FAIL, kind=kind, path=path))
    if maps:
        items.append(_item("source_map", WARN, paths=", ".join(maps[:3])))

    with ThreadPoolExecutor(max_workers=6) as pool:
        answers = list(pool.map(lambda kv: (kv, osv_vulns(*kv)), libraries.items()))
    unknown = 0
    for (name, version), vulns in answers:
        software.append({"name": name, "version": version})
        libs.append({"name": name, "version": version, "known": vulns is not None, **{k: (vulns or {}).get(k, d) for k, d in (("count", 0), ("high", 0), ("ids", []), ("fixed", ""))}})
        if vulns is None:
            unknown += 1
        elif vulns["count"]:
            items.append(_item("vuln_library", FAIL if vulns["high"] else WARN, name=name, version=version,
                               count=vulns["count"], ids=", ".join(vulns["ids"])))
    if unknown:
        items.append(_item("osv_unavailable", INFO))
    cves = _software_items(visible, items)
    plugins = _plugin_items(cve.detect_plugins(html), items) if any(s["name"] == "WordPress" for s in software) else []

    # Forms and outside scripts
    forms = page_audit.audit_forms(parsed, base)
    if forms["password_plain"]:
        items.append(_item("password_plain", FAIL, count=forms["password_plain"]))
    if forms["outside"]:
        items.append(_item("form_outside", WARN, hosts=", ".join(forms["outside"][:4])))
    outside = page_audit.outside_resources(parsed, base)
    if outside["plain_scripts"]:
        items.append(_item("script_plain", FAIL, count=outside["plain_scripts"]))
    if outside["unsigned"]:
        items.append(_item("sri_missing", WARN, count=len(outside["unsigned"]), hosts=", ".join(outside["unsigned"][:4])))

    # Headers and cookies
    quality = page_audit.audit_headers(headers)
    if quality["missing"]:
        items.append(_item("headers_missing", WARN, count=len(quality["missing"]), names=", ".join(quality["missing"])))
    if quality["csp_unsafe"]:
        items.append(_item("csp_unsafe", WARN, words=", ".join(quality["csp_unsafe"])))
    if quality["hsts_short"]:
        items.append(_item("hsts_short", WARN))
    if quality["cors_any"]:
        items.append(_item("cors_any", INFO))
    cookies = []
    for raw_cookie in fetch.set_cookies(r)[:15]:
        low = raw_cookie.lower()
        cookies.append({"name": raw_cookie.split("=", 1)[0].strip()[:60], "secure": "; secure" in low, "httponly": "; httponly" in low,
                        "samesite": (re.search(r"samesite=(\w+)", low) or [None, ""])[1]})
    weak_cookies = page_audit.audit_cookies(cookies, https)
    if weak_cookies:
        items.append(_item("cookie_weak", WARN, names=", ".join(weak_cookies)))

    # Public files, and whether plain HTTP moves visitors to HTTPS
    with ThreadPoolExecutor(max_workers=3) as pool:
        robots_job = pool.submit(_fetch_quietly, site + "/robots.txt")
        security_job = pool.submit(_fetch_quietly, site + "/.well-known/security.txt")
        plain_job = pool.submit(_fetch_quietly, f"http://{host}/", 5) if https else None
    robots = robots_job.result()
    secret_paths = page_audit.robots_paths(robots[4].decode("utf-8", "replace")) if robots and robots[0].status_code == 200 else []
    if secret_paths:
        items.append(_item("robots_reveals", INFO, paths=", ".join(secret_paths[:5])))
    security = security_job.result()
    has_security = bool(security and security[0].status_code == 200 and b"contact:" in security[4].lower()[:5000])
    if not has_security:
        items.append(_item("security_txt_missing", INFO))
    plain = plain_job.result() if plain_job else None
    if plain and not plain[1].startswith("https://"):
        items.append(_item("http_no_redirect", WARN))
    if not any(i["status"] in (WARN, FAIL) for i in items):
        items.append(_item("tech_clean", OK))
    return _result("tech", host, items, software=software, csp="content-security-policy" in headers, hsts="strict-transport-security" in headers,
                   headers=[{"name": name, "value": headers.get(name, "")[:220]} for name in page_audit.SECURITY_HEADERS], libs=libs, cookies=cookies, cves=cves,
                   plugins=plugins, theme=cve.detect_theme(html), wp_latest=wp_latest or "", outside=outside["hosts"][:20], unsigned=outside["unsigned"][:20],
                   forms={"total": forms["total"], "passwords": forms["passwords"]}, security_txt=has_security,
                   page={"final_url": final[:200], "status": r.status_code, "ms": round(elapsed), "bytes": len(body), "redirects": len(chain)})


# ---------------------------------------------------------------- TLS and DNS
def _handshake(host: str, ip: str, ciphers: str, version=None) -> bool | None:
    """Would the server agree to this? True or False, or None when nothing can be said (this machine's TLS
    library cannot offer it, or the connection itself failed)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers(ciphers)
        ctx.minimum_version = version or ssl.TLSVersion.TLSv1
        ctx.maximum_version = version or ssl.TLSVersion.TLSv1_2
    except (ssl.SSLError, ValueError):
        return None
    try:
        with socket.create_connection((ip, 443), timeout=4) as raw, ctx.wrap_socket(raw, server_hostname=host):
            return True
    except ssl.SSLError as e:
        return None if "NO_PROTOCOLS_AVAILABLE" in str(e) or "NO_CIPHERS_AVAILABLE" in str(e) else False
    except OSError:
        return None


def _rdap(kind: str, name: str) -> dict:
    """Public registration data. Many country domains, .az among them, publish none: that is an empty answer."""
    try:
        r = requests.get(f"https://rdap.org/{kind}/{name}", headers=HEADERS, timeout=6)
        return r.json() if r.status_code == 200 else {}
    except (requests.RequestException, ValueError):
        return {}


def _domain_record(domain: str) -> dict:
    data = _rdap("domain", domain)
    events = {e.get("eventAction"): e.get("eventDate", "")[:10] for e in data.get("events", [])}
    registrar = next((v[3] for e in data.get("entities", []) if "registrar" in e.get("roles", [])
                      for v in (e.get("vcardArray") or [None, []])[1] if v[0] == "fn"), "")
    return {"registrar": registrar, "created": events.get("registration", ""), "updated": events.get("last changed", ""),
            "expires": events.get("expiration", ""), "status": data.get("status", [])[:6]}


def _ip_record(ip: str) -> dict:
    data = _rdap("ip", ip)
    state, ptr = "none", []
    try:
        import dns.reversename
        state, ptr = fetch.dns_lookup(str(dns.reversename.from_address(ip)), "PTR", lifetime=3)
    except (ImportError, ValueError):
        pass
    return {"ip": ip, "network": data.get("name", ""), "country": data.get("country", ""), "ptr": str(ptr[0].target).rstrip(".") if state == "ok" else ""}


def _cert_details(host: str, ip: str) -> dict:
    """What a browser would be shown. Only a certificate that passes validation can be read in detail here."""
    try:
        with socket.create_connection((ip, 443), timeout=4) as raw, ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
            c = tls.getpeercert()
            cipher = tls.cipher()
    except (OSError, ssl.SSLError):
        return {}
    field = lambda part, key: dict(x[0] for x in c.get(part, ())).get(key, "")
    until = datetime.fromtimestamp(ssl.cert_time_to_seconds(c["notAfter"]), tz=timezone.utc)
    return {"subject": field("subject", "commonName"), "issuer": field("issuer", "organizationName"), "issuer_cn": field("issuer", "commonName"),
            "from": datetime.fromtimestamp(ssl.cert_time_to_seconds(c["notBefore"]), tz=timezone.utc).date().isoformat(), "to": until.date().isoformat(),
            "days_left": (until - datetime.now(timezone.utc)).days, "names": [v for k, v in c.get("subjectAltName", ()) if k == "DNS"][:20],
            "cipher": cipher[0], "bits": cipher[2]}


def _apex(domain: str) -> str:
    """The domain that holds DNSSEC and the registration. Without a suffix list, the longest DNS zone that answers."""
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        candidate = ".".join(labels[i:])
        if fetch.dns_lookup(candidate, "SOA", lifetime=3)[0] == "ok":
            return candidate
    return domain


def _caa(domain: str) -> list | None:
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        state, records = fetch.dns_lookup(".".join(labels[i:]), "CAA", lifetime=3)
        if state == "error":
            return None
        if state == "ok":
            return sorted({r.value.decode() for r in records if r.tag.decode().lower() in ("issue", "issuewild") and r.value})
    return []


def _speaks(host: str, ip: str, version: tuple) -> bool | None:
    answer = tlsprobe.accepts_version(host, ip, version)
    return tlsprobe.accepts_version(host, ip, version) if answer is None else answer


def tls_dns(raw: str) -> dict:
    host = _host(raw)
    domain = fetch.mail_domain(host)
    ip = resolve_public(host)
    items = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        cert_job = pool.submit(fetch.cert_info, host, ip)
        old_jobs = {name: pool.submit(_speaks, host, ip, version) for name, version in (("TLS 1.0", tlsprobe.TLS10), ("TLS 1.1", tlsprobe.TLS11))}
        new_jobs = {name: pool.submit(_handshake, host, ip, "DEFAULT:@SECLEVEL=0", version) for name, version in
                    (("TLS 1.2", ssl.TLSVersion.TLSv1_2), ("TLS 1.3", ssl.TLSVersion.TLSv1_3))}
        details_job = pool.submit(_cert_details, host, ip)
        weak_job = pool.submit(tlsprobe.weak_cipher, host, ip)
        apex_job = pool.submit(_apex, domain)
        caa_job = pool.submit(_caa, domain)
    cert = cert_job.result()
    apex = apex_job.result()

    if cert.get("error"):
        items.append(_item("cert_problem", FAIL) if " " in cert["error"] else _item("https_unavailable", INFO))
    else:
        version = cert.get("tls") or ""
        items.append(_item("tls_version", OK if version in ("TLSv1.3", "TLSv1.2") else WARN, version=version.replace("TLSv", "TLS ")))
    accepted = [name for name, job in old_jobs.items() if job.result()]
    if accepted:
        items.append(_item("tls_old", WARN, versions=", ".join(accepted)))
    elif all(job.result() is False for job in old_jobs.values()):
        items.append(_item("tls_old_off", OK))
    if weak_job.result():
        items.append(_item("tls_weak_cipher", FAIL, cipher=weak_job.result()))

    with ThreadPoolExecutor(max_workers=3) as pool:
        ds_job = pool.submit(fetch.dns_lookup, apex, "DS")
        ns_job = pool.submit(fetch.dns_lookup, apex, "NS")
        record_job = pool.submit(_domain_record, apex)
        ip_job = pool.submit(_ip_record, ip)
        a_job = pool.submit(fetch.dns_lookup, host, "A")
        aaaa_job = pool.submit(fetch.dns_lookup, host, "AAAA")
        soa_job = pool.submit(fetch.dns_lookup, apex, "SOA")
    ds_state = ds_job.result()[0]
    if ds_state == "ok":
        items.append(_item("dnssec_on", OK))
    elif ds_state in ("none", "nx"):
        items.append(_item("dnssec_off", INFO))
    ns_state, ns = ns_job.result()
    names = sorted(str(r.target).rstrip(".") for r in ns)
    if ns_state == "ok" and len(names) < 2:
        items.append(_item("ns_single", WARN, names=", ".join(names)))
    caa = caa_job.result()
    if caa:
        items.append(_item("caa_set", OK, issuers=", ".join(caa[:4])))
    elif caa == []:
        items.append(_item("caa_missing", INFO))
    record = record_job.result()
    expiry = record["expires"]
    if expiry:
        days = (date.fromisoformat(expiry) - datetime.now(timezone.utc).date()).days
        status = FAIL if days < 14 else WARN if days < 45 else OK
        items.append(_item("domain_expiry", status, date=expiry, days=days))
    soa = soa_job.result()[1]
    return _result("tls", host, items, apex=apex, nameservers=names[:6], issuer=cert.get("issuer") or "", cert=details_job.result(),
                   protocols={name: job.result() for name, job in {**old_jobs, **new_jobs}.items()},
                   addresses=[r.address for r in a_job.result()[1]][:6], addresses6=[r.address for r in aaaa_job.result()[1]][:6],
                   soa={"primary": str(soa[0].mname).rstrip("."), "serial": soa[0].serial} if soa else {},
                   caa=caa or [], dnssec=ds_state == "ok", domain_record=record, ip_record=ip_job.result())


# ---------------------------------------------------------------- reputation
def _listed(name: str, listing: set) -> bool | None:
    state, answers = fetch.dns_lookup(name, "A", lifetime=3)
    if state in ("nx", "none"):
        return False
    if state == "error":
        return None
    codes = {str(a.address) for a in answers}
    if any(c.startswith("127.255.255.") or c == "127.0.0.1" for c in codes):
        return None             # the list refuses this resolver: that says nothing about the site
    return bool(codes & listing) if listing else any(c.startswith("127.") for c in codes)


# name -> (zone, codes that mean listed, the test entry every list keeps permanently listed)
DOMAIN_LISTS = {"Spamhaus DBL": ("dbl.spamhaus.org", {f"127.0.1.{i}" for i in range(2, 100)}, "dbltest.com"),
                "SURBL": ("multi.surbl.org", set(), "test.surbl.org")}
# 10 and 11 only mark home connections, which says nothing about a website
IP_LISTS = {"Spamhaus SBL/XBL": ("zen.spamhaus.org", {f"127.0.0.{i}" for i in (2, 3, 4, 5, 6, 7, 9)}, "2.0.0.127"),
            "SpamCop": ("bl.spamcop.net", {"127.0.0.2"}, "2.0.0.127")}


def _zone(zone: str) -> str:
    """With a Spamhaus DQS key its lists answer any server. The key goes only into this DNS name, never into a result."""
    key = os.getenv("SPAMHAUS_DQS_KEY")
    if key and zone.endswith(".spamhaus.org"):
        return f"{key}.{zone.removesuffix('.spamhaus.org')}.dq.spamhaus.net"
    return zone


def _safe_browsing(domain: str) -> dict | None:
    """Google's verdict with a key; None without one, or if it did not answer."""
    key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
    if not key:
        return None
    try:
        r = requests.post("https://safebrowsing.googleapis.com/v4/threatMatches:find", params={"key": key}, headers=HEADERS, timeout=6, json={
            "client": {"clientId": "saytyoxla", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                           "threatEntries": [{"url": f"https://{domain}/"}, {"url": f"http://{domain}/"}]}})
        if r.status_code != 200:
            return None
        return {"threats": sorted({m.get("threatType", "") for m in r.json().get("matches", [])})}
    except (requests.RequestException, ValueError):
        return None


def reputation(raw: str) -> dict:
    domain = _domain(raw)
    ips = [r.address for r in fetch.dns_lookup(_host(raw), "A")[1] if is_public_ip(r.address)][:2]
    jobs, canaries = {}, {}
    with ThreadPoolExecutor(max_workers=12) as pool:
        for name, (zone, codes, test) in {**DOMAIN_LISTS, **IP_LISTS}.items():
            canaries[name] = pool.submit(_listed, f"{test}.{_zone(zone)}", codes)
        for name, (zone, codes, _) in DOMAIN_LISTS.items():
            jobs[(name, domain)] = pool.submit(_listed, f"{domain}.{_zone(zone)}", codes)
        for ip in ips:
            reversed_ip = ".".join(reversed(ip.split(".")))
            for name, (zone, codes, _) in IP_LISTS.items():
                jobs[(name, ip)] = pool.submit(_listed, f"{reversed_ip}.{_zone(zone)}", codes)
        google_job = pool.submit(_safe_browsing, domain)
    # Lists refuse many large resolvers by answering "not listed" for everything. A list that does not
    # even know its own test entry has told us nothing, so its "not listed" must not read as clean.
    working = {name for name, job in canaries.items() if job.result()}
    answers = {key: job.result() for key, job in jobs.items() if key[0] in working}
    table = [{"list": name, "target": target, "state": "unavailable" if name not in working or job.result() is None else "listed" if job.result() else "clean"}
             for (name, target), job in jobs.items()]
    items = [_item("rep_listed", FAIL, list=name, target=target) for (name, target), hit in answers.items() if hit]
    checked = sorted({name for (name, _), hit in answers.items() if hit is not None})
    google = google_job.result()
    if google is not None:
        checked = sorted([*checked, "Google Safe Browsing"])
        if google["threats"]:
            items.append(_item("safe_browsing_listed", FAIL, threats=", ".join(google["threats"])))
        table.append({"list": "Google Safe Browsing", "target": domain, "state": "listed" if google["threats"] else "clean"})
    if not items and checked:
        items.append(_item("rep_clean", OK, lists=", ".join(checked)))
    if not checked:
        items.append(_item("rep_unknown", INFO))
    return _result("reputation", domain, items, checked=checked, table=table, safe_browsing_checked=google is not None, safe_browsing=f"https://transparencyreport.google.com/safe-browsing/search?url={domain}")


# ---------------------------------------------------------------- ownership and active checks
def ownership_token(host: str) -> str:
    """Not a secret: what proves control is being able to publish it on the site or in its DNS."""
    return "saytyoxla-" + hashlib.sha256(f"saytyoxla-ownership:{host}".encode()).hexdigest()[:32]


def ownership(raw: str) -> dict:
    host = _host(raw)
    return {"host": host, "token": ownership_token(host), "dns_name": f"{OWNERSHIP_DNS}.{host}",
            "file_url": f"https://{host}{OWNERSHIP_FILE}"}


def is_owner(host: str) -> bool:
    token = ownership_token(host)
    if any(token in r for r in fetch.txt_records(f"{OWNERSHIP_DNS}.{host}") or []):
        return True
    try:
        r, final, _, _, body, _ = fetch._get(f"https://{host}{OWNERSHIP_FILE}", budget=FILE_BUDGET)
    except (requests.RequestException, UnsafeTarget):
        return False
    # A redirect to some other site must not count: that site is not the one being claimed
    return r.status_code == 200 and final.split("/")[2] == host and token.encode() in body[:2000]


# path -> (what it is, what must be in it). The content check keeps a site that answers 200 for everything from looking exposed.
EXPOSED = {
    "/.env": ("env", rb"(?m)^[A-Z][A-Z0-9_]+=\S*"),
    "/.git/HEAD": ("git", rb"^ref: refs/|^[0-9a-f]{40}\s*$"),
    "/.git/config": ("git", rb"\[core\]"),
    "/.svn/entries": ("svn", rb"^\d+\s"),
    "/wp-config.php.bak": ("config", rb"DB_PASSWORD"),
    "/wp-config.php~": ("config", rb"DB_PASSWORD"),
    "/config.php.bak": ("config", rb"(?i)password"),
    "/backup.sql": ("database", rb"(?i)(CREATE TABLE|INSERT INTO)"),
    "/dump.sql": ("database", rb"(?i)(CREATE TABLE|INSERT INTO)"),
    "/database.sql": ("database", rb"(?i)(CREATE TABLE|INSERT INTO)"),
    "/.htpasswd": ("passwords", rb"(?m)^[^:\s<]+:\$?[A-Za-z0-9./$]{10,}"),
    "/id_rsa": ("key", rb"BEGIN [A-Z ]*PRIVATE KEY"),
    "/.ssh/id_rsa": ("key", rb"BEGIN [A-Z ]*PRIVATE KEY"),
    "/phpinfo.php": ("phpinfo", rb"phpinfo\(\)"),
    "/info.php": ("phpinfo", rb"phpinfo\(\)"),
    "/server-status": ("status", rb"Apache Server Status"),
    "/.DS_Store": ("listing", rb"^\x00\x00\x00\x01Bud1"),
    "/.env.local": ("env", rb"(?m)^[A-Z][A-Z0-9_]+=\S*"),
    "/.env.production": ("env", rb"(?m)^[A-Z][A-Z0-9_]+=\S*"),
    "/.env.backup": ("env", rb"(?m)^[A-Z][A-Z0-9_]+=\S*"),
    "/.git/index": ("git", rb"^DIRC"),
    "/.hg/hgrc": ("git", rb"\[paths\]"),
    "/.aws/credentials": ("key", rb"aws_access_key_id"),
    "/docker-compose.yml": ("config", rb"(?m)^(services|version):"),
    "/web.config": ("config", rb"<configuration"),
    "/wp-config.php.save": ("config", rb"DB_PASSWORD"),
    "/wp-config.php.old": ("config", rb"DB_PASSWORD"),
    "/.wp-config.php.swp": ("config", rb"b0VIM"),
    "/configuration.php.bak": ("config", rb"(?i)password"),
    "/.vscode/sftp.json": ("config", rb'"password"'),
    "/sftp-config.json": ("config", rb'"password"'),
    "/db.sql": ("database", rb"(?i)(CREATE TABLE|INSERT INTO)"),
    "/backup.zip": ("backup", rb"^PK\x03\x04"),
    "/site.zip": ("backup", rb"^PK\x03\x04"),
    "/www.zip": ("backup", rb"^PK\x03\x04"),
    "/backup.tar.gz": ("backup", rb"^\x1f\x8b"),
    "/wp-content/debug.log": ("log", rb"PHP (Notice|Warning|Fatal|Parse)"),
    "/storage/logs/laravel.log": ("log", rb"(production|local)\.(ERROR|INFO|WARNING)"),
    "/error_log": ("log", rb"PHP (Notice|Warning|Fatal|Parse)"),
    "/elmah.axd": ("debug", rb"Error Log for"),
    "/actuator/env": ("debug", rb'"propertySources"'),
    "/_profiler/": ("debug", rb"Symfony Profiler"),
    "/telescope": ("debug", rb"Laravel Telescope|telescope"),
}
PANELS = {"/phpmyadmin/": rb"phpMyAdmin", "/adminer.php": rb"Adminer", "/wp-login.php": rb"wp-submit", "/administrator/": rb"Joomla", "/cpanel": rb"cPanel"}
LISTED_DIRS = ("/uploads/", "/backup/", "/backups/", "/files/", "/wp-content/uploads/", "/images/", "/assets/", "/logs/")
LISTING = rb"<title>Index of /|<h1>Index of /|Directory listing for /"
PORTS = {21: ("FTP", WARN), 22: ("SSH", INFO), 23: ("Telnet", FAIL), 445: ("SMB", FAIL), 1433: ("SQL Server", FAIL), 2375: ("Docker", FAIL),
         3306: ("MySQL", FAIL), 3389: ("RDP", FAIL), 5432: ("PostgreSQL", FAIL), 5900: ("VNC", FAIL), 6379: ("Redis", FAIL),
         9200: ("Elasticsearch", FAIL), 11211: ("Memcached", FAIL), 27017: ("MongoDB", FAIL)}


def _probe_path(base: str, host: str, path: str, sign: bytes) -> bool | None:
    """True if the file is really there, False if it is not. None if the site would not say: a refused or failed
    request is no evidence that the file is absent."""
    try:
        r, final, _, _, body, _ = fetch._get(base + path, budget=FILE_BUDGET, verify=False)
    except (requests.RequestException, UnsafeTarget):
        return None
    if r.status_code in (401, 403, 429) or r.status_code >= 500:
        return None
    if r.status_code != 200 or final.split("/")[2] != host:
        return False
    return bool(re.search(sign, body[:200000]))


def _port_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=PORT_TIMEOUT):
            return True
    except OSError:
        return False


def _cors_reflects(base: str, ip: str) -> bool:
    """Does the site let any other site read its answers with the visitor's own login?"""
    try:
        with fetch._session(ip) as session:
            r = session.get(base + "/", headers={"User-Agent": fetch.USER_AGENT, "Origin": "https://saytyoxla-origin-test.example"},
                            allow_redirects=False, stream=True, verify=False, timeout=4)
            r.close()
    except requests.RequestException:
        return False
    return r.headers.get("access-control-allow-origin") == "https://saytyoxla-origin-test.example" and r.headers.get("access-control-allow-credentials", "").lower() == "true"


def _axfr_open(domain: str) -> str:
    """The name server that hands the whole DNS zone to anyone, if there is one. Asked only for a proven owner."""
    try:
        import dns.exception
        import dns.query
        import dns.zone
    except ImportError:
        return ""
    for record in fetch.dns_lookup(domain, "NS")[1][:3]:
        server = str(record.target).rstrip(".")
        addresses = fetch.dns_lookup(server, "A")[1]
        if not addresses or not is_public_ip(addresses[0].address):
            continue
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(addresses[0].address, domain, lifetime=4, timeout=3))
        except (OSError, EOFError, ValueError, dns.exception.DNSException):     # the normal answer is a refusal, in many forms
            continue
        if len(zone.nodes) > 0:
            return server
    return ""


def active(raw: str) -> dict:
    host = _host(raw)
    if not is_owner(host):
        raise UnsafeTarget("Əvvəlcə saytın sizə aid olduğunu təsdiqləyin.")
    ip = resolve_public(host)
    base = f"https://{host}" if _port_open(ip, 443) else f"http://{host}"
    # Few at a time: firewalls block a burst, and a real owner's site should not feel this
    pool = ThreadPoolExecutor(max_workers=5)
    files = {p: pool.submit(_probe_path, base, host, p, s) for p, (_, s) in EXPOSED.items()}
    panels = {p: pool.submit(_probe_path, base, host, p, s) for p, s in PANELS.items()}
    dirs = {p: pool.submit(_probe_path, base, host, p, LISTING) for p in LISTED_DIRS}
    xmlrpc_job = pool.submit(_probe_path, base, host, "/xmlrpc.php", rb"XML-RPC server accepts POST")
    users_job = pool.submit(_probe_path, base, host, "/wp-json/wp/v2/users", rb'"slug"')
    cors_job = pool.submit(_cors_reflects, base, ip)
    axfr_job = pool.submit(_axfr_open, fetch.mail_domain(host))
    port_pool = ThreadPoolExecutor(max_workers=14)
    ports = {p: port_pool.submit(_port_open, ip, p) for p in PORTS}
    asked = [*files.values(), *panels.values(), *dirs.values(), xmlrpc_job, users_job]
    wait_for([*asked, *ports.values(), cors_job, axfr_job], timeout=ACTIVE_BUDGET)
    pool.shutdown(wait=False, cancel_futures=True)
    port_pool.shutdown(wait=False, cancel_futures=True)
    done = lambda job: job.done() and not job.cancelled() and not job.exception() and job.result()

    items = [_item("exposed_file", WARN if EXPOSED[p][0] == "listing" else FAIL, path=p, kind=EXPOSED[p][0]) for p, j in files.items() if done(j)]
    items += [_item("admin_panel", WARN, path=p) for p, j in panels.items() if done(j)]
    items += [_item("open_port", PORTS[p][1], port=p, service=PORTS[p][0]) for p, j in ports.items() if done(j)]
    items += [_item("dir_listing", FAIL, path=p) for p, j in dirs.items() if done(j)]
    if done(xmlrpc_job):
        items.append(_item("xmlrpc_open", WARN))
    if done(users_job):
        items.append(_item("user_list", WARN))         # that the names are open is the finding; the names stay out of it
    if done(cors_job):
        items.append(_item("cors_reflect", FAIL))
    if done(axfr_job):
        items.append(_item("axfr_open", FAIL, server=axfr_job.result()))
    # A file that could not be asked about is not a file that is absent
    unanswered = sum(not job.done() or job.cancelled() or job.exception() is not None or job.result() is None for job in asked)
    if unanswered:
        items.append(_item("active_partial", INFO, unanswered=unanswered, total=len(asked)))
    if not items:
        items.append(_item("active_clean", OK, files=len(EXPOSED) + len(LISTED_DIRS), ports=len(PORTS)))
    return _result("active", host, items, checked_files=len(EXPOSED) + len(PANELS) + len(LISTED_DIRS) + 2, checked_ports=len(PORTS))


# ---------------------------------------------------------------- the owner's whole site, a page at a time
CRAWL_PAGES = 30
CRAWL_BUDGET = 26
SKIP_LINK = re.compile(r"(?i)\.(pdf|zip|gz|rar|jpe?g|png|gif|webp|svg|ico|mp4|mp3|css|js|woff2?|xml|docx?|xlsx?)(\?|$)|logout|signout|cikis|delete|remove")


def _same_site_links(page: page_audit.Page, base: str, host: str) -> list:
    found = []
    for link in page.links:
        target = urljoin(base, link).split("#")[0]
        parts = urlsplit(target)
        if parts.scheme in ("http", "https") and parts.hostname == host and not SKIP_LINK.search(target):
            found.append(target)
    return list(dict.fromkeys(found))


def _read_page(url: str):
    try:
        return fetch._get(url, budget=6, verify=False)
    except (requests.RequestException, UnsafeTarget):
        return None


def crawl(raw: str) -> dict:
    """Follows the owner's links within the site, with plain GETs only: no form is sent and nothing is changed."""
    host = _host(raw)
    if not is_owner(host):
        raise UnsafeTarget("Əvvəlcə saytın sizə aid olduğunu təsdiqləyin.")
    start = normalize(raw)
    seen, queue, pages = {start}, [start], []
    leaks, errors, plain_forms, outside_forms, plain_scripts = {}, [], [], [], []
    deadline = time.monotonic() + CRAWL_BUDGET
    with ThreadPoolExecutor(max_workers=6) as pool:
        while queue and len(pages) < CRAWL_PAGES and time.monotonic() < deadline:
            batch, queue = queue[:6], queue[6:]
            for answer in pool.map(_read_page, batch):
                if not answer:
                    continue
                r, final, _, elapsed, body, _ = answer
                if urlsplit(final).hostname != host:
                    continue
                path = (urlsplit(final).path or "/")[:120]
                pages.append({"path": path, "status": r.status_code, "ms": round(elapsed)})
                if "html" not in r.headers.get("content-type", "html").lower():
                    continue
                parsed = page_audit.parse(body.decode("utf-8", "replace"))
                for kind in page_audit.find_secrets(body):
                    leaks.setdefault(kind, path)
                if re.search(page_audit.ERROR_SIGNS, body):
                    errors.append(path)
                forms = page_audit.audit_forms(parsed, final)
                if forms["password_plain"]:
                    plain_forms.append(path)
                if forms["outside"]:
                    outside_forms.append(path)
                if page_audit.outside_resources(parsed, final)["plain_scripts"]:
                    plain_scripts.append(path)
                for link in _same_site_links(parsed, final, host):
                    if link not in seen and len(seen) < CRAWL_PAGES * 4:
                        seen.add(link)
                        queue.append(link)
    broken = [p["path"] for p in pages if p["status"] >= 500]
    items = [_item("crawl_summary", INFO, pages=len(pages))]
    items += [_item("js_secret", FAIL, kind=kind, path=path) for kind, path in leaks.items()]
    if plain_forms:
        items.append(_item("password_plain_pages", FAIL, paths=", ".join(plain_forms[:5])))
    if plain_scripts:
        items.append(_item("mixed_pages", WARN, count=len(plain_scripts), paths=", ".join(plain_scripts[:5])))
    if errors:
        items.append(_item("error_shown", WARN, count=len(errors), paths=", ".join(errors[:5])))
    if broken:
        items.append(_item("server_errors", WARN, count=len(broken), paths=", ".join(broken[:5])))
    if outside_forms:
        items.append(_item("forms_outside_pages", INFO, paths=", ".join(outside_forms[:5])))
    if len(items) == 1:
        items.append(_item("crawl_clean", OK))
    return _result("crawl", host, items, pages=pages[:CRAWL_PAGES], cut_short=bool(queue))


PROBE_PAGES = 16
PROBE_BUDGET = 28


def _collect_probe_targets(start: str, host: str) -> list:
    """A light read of the owner's pages to list query parameters and GET-form fields worth testing."""
    seen, queue, links, forms = {start}, [start], [], []
    deadline = time.monotonic() + 8
    with ThreadPoolExecutor(max_workers=6) as pool:
        while queue and len(seen) < PROBE_PAGES * 3 and time.monotonic() < deadline and len(links) < 60:
            batch, queue = queue[:6], queue[6:]
            for answer in pool.map(_read_page, batch):
                if not answer:
                    continue
                r, final, _, _, body, _ = answer
                if urlsplit(final).hostname != host or "html" not in r.headers.get("content-type", "html").lower():
                    continue
                parsed = page_audit.parse(body.decode("utf-8", "replace"))
                forms.extend(page_audit.get_form_targets(parsed, final, host))
                if urlsplit(final).query:
                    links.append(final)
                for link in _same_site_links(parsed, final, host):
                    if link not in seen and len(seen) < PROBE_PAGES * 3:
                        seen.add(link)
                        queue.append(link)
                        if urlsplit(link).query:
                            links.append(link)
    return injection.collect_targets(links, forms)


def _probe_send(url: str, deadline: float):
    if time.monotonic() > deadline:
        return None
    try:
        r, _, _, _, body, _ = fetch._get(url, budget=5, verify=False)
    except (requests.RequestException, UnsafeTarget):
        return None
    return r.status_code, body


def probe(raw: str) -> dict:
    """Safe injection and reflected-XSS checks on the owner's own site. Every request is a GET (nothing is
    submitted or changed), and the payloads only read: see scanner/injection.py. Owner proof is required."""
    host = _host(raw)
    if not is_owner(host):
        raise UnsafeTarget("Əvvəlcə saytın sizə aid olduğunu təsdiqləyin.")
    start = normalize(raw)
    targets = _collect_probe_targets(start, host)
    # CSRF is read from the home page without sending anything
    csrf = 0
    home = _read_page(start)
    if home:
        csrf = page_audit.csrf_missing(page_audit.parse(home[4].decode("utf-8", "replace")))

    deadline = time.monotonic() + PROBE_BUDGET
    sqli, xss = [], []
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = pool.map(lambda t: (t, injection.probe_param(t[0], t[1], lambda u: _probe_send(u, deadline))), targets)
        for (url, param), found in results:
            path = (urlsplit(url).path or "/")[:80]
            if found["sqli"]:
                sqli.append((path, param, found["sqli"]))
            if found["xss"]:
                xss.append((path, param))

    items = [_item("probe_summary", INFO, params=len(targets))]
    items += [_item("sqli_found", FAIL, path=path, param=param, method=method) for path, param, method in sqli[:6]]
    items += [_item("xss_found", FAIL, path=path, param=param) for path, param in xss[:6]]
    if csrf:
        items.append(_item("csrf_missing", WARN, count=csrf))
    if len(items) == 1 and targets:
        items.append(_item("probe_clean", OK, params=len(targets)))
    elif not targets:
        items.append(_item("probe_no_params", INFO))
    return _result("probe", host, items, tested=len(targets))


MODULES = {"surface": surface, "mail": mail, "tech": tech, "tls": tls_dns, "reputation": reputation,
           "active": active, "crawl": crawl, "probe": probe}
