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
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait as wait_for
from datetime import date, datetime, timezone

import requests

from scanner import checks, fetch
from scanner.models import Context
from scanner.safety import HOST_RE, UnsafeTarget, is_public_ip, normalize, resolve_public

MAX_HOSTS = 60              # subdomains looked at per scan
SURFACE_BUDGET = 22         # seconds for all of them
HTTP_TIMEOUT = 8
FILE_BUDGET = 4
PORT_TIMEOUT = 2.5
SPF_LIMIT = 10
SPF_BUDGET = 15
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

# CNAME target -> what the provider shows for a name nobody has claimed. Anyone may then claim it.
TAKEOVER = {
    "github.io": "There isn't a GitHub Pages site here",
    "herokuapp.com": "No such app",
    "herokudns.com": "No such app",
    "amazonaws.com": "NoSuchBucket",
    "bitbucket.io": "Repository not found",
    "surge.sh": "project not found",
    "ghost.io": "The thing you were looking for is no longer here",
    "pantheonsite.io": "The gods are wise",
    "readthedocs.io": "is unknown to Read the Docs",
    "myshopify.com": "Sorry, this shop is currently unavailable",
    "azurewebsites.net": "",
    "cloudapp.net": "",
    "trafficmanager.net": "",
    "cloudfront.net": "Bad request.",
}


def _cert_spotter(domain: str) -> set | None:
    r = requests.get("https://api.certspotter.com/v1/issuances", headers=HEADERS, timeout=HTTP_TIMEOUT,
                     params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"})
    if r.status_code != 200:
        return None
    return {n for entry in r.json() for n in entry.get("dns_names", [])}


def _crt_sh(domain: str) -> set | None:
    r = requests.get("https://crt.sh/", headers=HEADERS, timeout=HTTP_TIMEOUT, params={"q": f"%.{domain}", "output": "json"})
    if r.status_code != 200:
        return None
    return {n for entry in r.json() for n in entry.get("name_value", "").split()}


def certificate_names(domain: str) -> set | None:
    """Names found in public certificate logs; None if neither log answered."""
    for source in (_cert_spotter, _crt_sh):
        try:
            names = source(domain)
        except (requests.RequestException, ValueError):
            continue
        if names is not None:
            found = {n.lower().lstrip("*.").rstrip(".") for n in names}
            return {n for n in found if (n == domain or n.endswith("." + domain)) and HOST_RE.match(n)}
    return None


def _provider_of(target: str) -> str | None:
    return next((p for p in TAKEOVER if target == p or target.endswith("." + p)), None)


def _unclaimed(host: str, provider: str) -> bool:
    """Does the provider itself say that nobody has claimed this name?"""
    sign = TAKEOVER[provider]
    if not sign:
        return False
    try:
        _, _, _, _, body, _ = fetch._get(f"https://{host}/", budget=FILE_BUDGET, verify=False)
    except (requests.RequestException, UnsafeTarget):
        return False
    return sign.encode() in body


def inspect_host(host: str) -> dict:
    cname = fetch.dns_lookup(host, "CNAME")
    target = str(cname[1][0].target).rstrip(".").lower() if cname[0] == "ok" else ""
    ips = [r.address for r in fetch.dns_lookup(host, "A")[1]]
    out = {"host": host, "live": bool(ips), "cname": target, "flag": ""}
    if target:
        provider = _provider_of(target)
        target_state = fetch.dns_lookup(target, "A")[0]
        if target_state == "nx":
            out["flag"] = "takeover" if provider else "dangling"
        elif provider and _unclaimed(host, provider):
            out["flag"] = "takeover"
    if ips and not all(is_public_ip(ip) for ip in ips):
        out["flag"] = out["flag"] or "private"
    if not out["flag"] and out["live"] and SENSITIVE.search(host):
        out["flag"] = "sensitive"
    return out


def surface(raw: str) -> dict:
    domain = _domain(raw)
    names = certificate_names(domain)
    if names is None:
        return _result("surface", domain, [_item("surface_unavailable", INFO)], hosts=[], total=0)
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
    if by_flag("sensitive"):
        items.append(_item("sensitive_hosts", WARN, hosts=", ".join(by_flag("sensitive")[:8]), count=len(by_flag("sensitive"))))
    if by_flag("private"):
        items.append(_item("private_ip", WARN, hosts=", ".join(by_flag("private")[:8])))
    if len(items) == 1:
        items.append(_item("surface_clean", OK))
    if len(hosts) < len(chosen) or len(names) > MAX_HOSTS:
        items.append(_item("surface_partial", INFO, checked=len(hosts), total=len(names)))
    order = {"takeover": 0, "dangling": 1, "private": 2, "sensitive": 3, "": 4}
    return _result("surface", domain, items, total=len(names), hosts=sorted(hosts, key=lambda h: (order[h["flag"]], h["host"])))


# ---------------------------------------------------------------- e-mail
LOOKUP_TERMS = ("include", "a", "mx", "ptr", "exists")


def _spf_of(records: list | None) -> list:
    return [r for r in records or [] if r.lower().startswith("v=spf1")]


def spf_tree(domain: str, seen: set | None = None, depth: int = 0, deadline: float | None = None) -> dict:
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
    for term in spf[0].split()[1:]:
        body = term.lower().lstrip("+-~?")
        mech = re.split(r"[:/=]", body)[0]
        if mech in LOOKUP_TERMS or mech == "redirect":
            result["lookups"] += 1
        if mech in ("include", "redirect") and re.search(r"[:=]", body):
            sub = spf_tree(re.split(r"[:=]", term, maxsplit=1)[1].strip(), seen, depth + 1, deadline)
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
        tree_job = pool.submit(spf_tree, domain)
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
        items.append(_item("spoof_open", FAIL, state="none" if rec else "missing"))
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
    return _result("mail", domain, items, records={"spf": spf, "dmarc": [rec] if rec else [], "dmarc_parent": parent or "",
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
    return {"count": len(vulns), "high": high, "ids": [v["id"] for v in vulns[:3]]}


def tech(raw: str) -> dict:
    url = normalize(raw)
    host = url.split("/")[2]
    try:
        # A bad certificate is the TLS part's finding; the software behind it can still be read
        r, _, _, _, body, _ = fetch._get(url, budget=10, verify=False)
    except requests.RequestException:
        return _result("tech", host, [_item("page_unavailable", INFO)], software=[], csp=None, hsts=None)
    headers = {k.lower(): v for k, v in r.headers.items()}
    if r.status_code in (401, 403, 429, 503):
        return _result("tech", host, [_item("page_blocked", INFO, status=r.status_code)], software=[], csp=None, hsts=None)
    html = body.decode("utf-8", "replace")
    items, software = [], []

    for cms, sign in CMS_SIGNS.items():
        if re.search(sign, body):
            software.append({"name": cms, "version": ""})
    generator = (checks.parse(html).meta.get("generator") or "").strip()
    wp = re.match(r"(?i)wordpress\s+(\d+\.\d+(?:\.\d+)?)", generator)
    if wp:
        software = [s for s in software if s["name"] != "WordPress"] + [{"name": "WordPress", "version": wp.group(1)}]
        items.append(_item("cms_version_shown", WARN, name="WordPress", version=wp.group(1)))

    php = re.search(r"PHP/(\d+\.\d+)(?:\.\d+)?", headers.get("x-powered-by", "") + " " + headers.get("server", ""))
    if php:
        software.append({"name": "PHP", "version": php.group(1)})
        ended = PHP_EOL.get(php.group(1))
        if ended and date.fromisoformat(ended) < datetime.now(timezone.utc).date():
            items.append(_item("eol_runtime", FAIL, name="PHP", version=php.group(1), date=ended))
        else:
            items.append(_item("version_shown", WARN, name="PHP", version=php.group(1)))
    server = re.match(r"(nginx|apache|microsoft-iis|litespeed|openresty)/(\d+(?:\.\d+)*)", headers.get("server", ""), re.IGNORECASE)
    if server:
        software.append({"name": server.group(1), "version": server.group(2)})
        items.append(_item("version_shown", WARN, name=server.group(1), version=server.group(2)))

    libraries = detect_libraries(html)
    with ThreadPoolExecutor(max_workers=6) as pool:
        answers = list(pool.map(lambda kv: (kv, osv_vulns(*kv)), libraries.items()))
    unknown = 0
    for (name, version), vulns in answers:
        software.append({"name": name, "version": version})
        if vulns is None:
            unknown += 1
        elif vulns["count"]:
            items.append(_item("vuln_library", FAIL if vulns["high"] else WARN, name=name, version=version,
                               count=vulns["count"], ids=", ".join(vulns["ids"])))
    if unknown:
        items.append(_item("osv_unavailable", INFO))
    if not items:
        items.append(_item("tech_clean", OK))
    return _result("tech", host, items, software=software, csp="content-security-policy" in headers,
                   hsts="strict-transport-security" in headers)


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


def _rdap_expiry(domain: str) -> str | None:
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", headers=HEADERS, timeout=6)
        if r.status_code != 200:
            return None
        event = next((e for e in r.json().get("events", []) if e.get("eventAction") == "expiration"), None)
        return event["eventDate"][:10] if event else None
    except (requests.RequestException, ValueError, KeyError):
        return None


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


def tls_dns(raw: str) -> dict:
    host = _host(raw)
    domain = fetch.mail_domain(host)
    ip = resolve_public(host)
    items = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        cert_job = pool.submit(fetch.cert_info, host, ip)
        old_jobs = {name: pool.submit(_handshake, host, ip, "DEFAULT:@SECLEVEL=0", version) for name, version in
                    (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1))}
        weak_job = pool.submit(_handshake, host, ip, "3DES:RC4:DES:NULL:EXPORT:@SECLEVEL=0")
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
        items.append(_item("tls_weak_cipher", FAIL))

    with ThreadPoolExecutor(max_workers=3) as pool:
        ds_job = pool.submit(fetch.dns_lookup, apex, "DS")
        ns_job = pool.submit(fetch.dns_lookup, apex, "NS")
        expiry_job = pool.submit(_rdap_expiry, apex)
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
    expiry = expiry_job.result()
    if expiry:
        days = (date.fromisoformat(expiry) - datetime.now(timezone.utc).date()).days
        status = FAIL if days < 14 else WARN if days < 45 else OK
        items.append(_item("domain_expiry", status, date=expiry, days=days))
    return _result("tls", host, items, apex=apex, nameservers=names[:6], issuer=cert.get("issuer") or "")


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


def reputation(raw: str) -> dict:
    domain = _domain(raw)
    ips = [r.address for r in fetch.dns_lookup(_host(raw), "A")[1] if is_public_ip(r.address)][:2]
    jobs, canaries = {}, {}
    with ThreadPoolExecutor(max_workers=12) as pool:
        for name, (zone, codes, test) in {**DOMAIN_LISTS, **IP_LISTS}.items():
            canaries[name] = pool.submit(_listed, f"{test}.{zone}", codes)
        for name, (zone, codes, _) in DOMAIN_LISTS.items():
            jobs[(name, domain)] = pool.submit(_listed, f"{domain}.{zone}", codes)
        for ip in ips:
            reversed_ip = ".".join(reversed(ip.split(".")))
            for name, (zone, codes, _) in IP_LISTS.items():
                jobs[(name, ip)] = pool.submit(_listed, f"{reversed_ip}.{zone}", codes)
    # Lists refuse many large resolvers by answering "not listed" for everything. A list that does not
    # even know its own test entry has told us nothing, so its "not listed" must not read as clean.
    working = {name for name, job in canaries.items() if job.result()}
    answers = {key: job.result() for key, job in jobs.items() if key[0] in working}
    items = [_item("rep_listed", FAIL, list=name, target=target) for (name, target), hit in answers.items() if hit]
    checked = sorted({name for (name, _), hit in answers.items() if hit is not None})
    if not items and checked:
        items.append(_item("rep_clean", OK, lists=", ".join(checked)))
    if not checked:
        items.append(_item("rep_unknown", INFO))
    return _result("reputation", domain, items, checked=checked, safe_browsing=f"https://transparencyreport.google.com/safe-browsing/search?url={domain}")


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
}
PANELS = {"/phpmyadmin/": rb"phpMyAdmin", "/adminer.php": rb"Adminer", "/wp-login.php": rb"wp-submit"}
PORTS = {21: ("FTP", WARN), 22: ("SSH", INFO), 23: ("Telnet", FAIL), 445: ("SMB", FAIL), 1433: ("SQL Server", FAIL), 2375: ("Docker", FAIL),
         3306: ("MySQL", FAIL), 3389: ("RDP", FAIL), 5432: ("PostgreSQL", FAIL), 5900: ("VNC", FAIL), 6379: ("Redis", FAIL),
         9200: ("Elasticsearch", FAIL), 11211: ("Memcached", FAIL), 27017: ("MongoDB", FAIL)}


def _probe_path(base: str, host: str, path: str, sign: bytes) -> bool:
    try:
        r, final, _, _, body, _ = fetch._get(base + path, budget=FILE_BUDGET, verify=False)
    except (requests.RequestException, UnsafeTarget):
        return False
    if r.status_code != 200 or final.split("/")[2] != host:
        return False
    return bool(re.search(sign, body[:200000]))


def _port_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=PORT_TIMEOUT):
            return True
    except OSError:
        return False


def active(raw: str) -> dict:
    host = _host(raw)
    if not is_owner(host):
        raise UnsafeTarget("Əvvəlcə saytın sizə aid olduğunu təsdiqləyin.")
    ip = resolve_public(host)
    base = f"https://{host}"
    pool = ThreadPoolExecutor(max_workers=16)
    files = {p: pool.submit(_probe_path, base, host, p, s) for p, (_, s) in EXPOSED.items()}
    panels = {p: pool.submit(_probe_path, base, host, p, s) for p, s in PANELS.items()}
    ports = {p: pool.submit(_port_open, ip, p) for p in PORTS}
    wait_for([*files.values(), *panels.values(), *ports.values()], timeout=SURFACE_BUDGET)
    pool.shutdown(wait=False, cancel_futures=True)
    done = lambda job: job.done() and not job.cancelled() and not job.exception() and job.result()

    items = [_item("exposed_file", WARN if EXPOSED[p][0] == "listing" else FAIL, path=p, kind=EXPOSED[p][0]) for p, j in files.items() if done(j)]
    items += [_item("admin_panel", WARN, path=p) for p, j in panels.items() if done(j)]
    items += [_item("open_port", PORTS[p][1], port=p, service=PORTS[p][0]) for p, j in ports.items() if done(j)]
    if not items:
        items.append(_item("active_clean", OK, files=len(EXPOSED), ports=len(PORTS)))
    return _result("active", host, items, checked_files=len(EXPOSED) + len(PANELS), checked_ports=len(PORTS))


MODULES = {"surface": surface, "mail": mail, "tech": tech, "tls": tls_dns, "reputation": reputation, "active": active}
