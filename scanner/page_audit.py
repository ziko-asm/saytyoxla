"""
What a home page reveals about itself: outside scripts, forms, leaked keys, source maps and header quality.

Only what any visitor's browser receives is read: the page, its headers and the scripts it loads from its own site.
A leaked key is reported by its kind and file, never by its value.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

SECRET_PATTERNS = {
    "AWS": rb"\bAKIA[0-9A-Z]{16}\b",
    "Stripe": rb"\bsk_live_[0-9a-zA-Z]{20,}\b",
    "GitHub": rb"\bgh[pousr]_[A-Za-z0-9]{36}\b",
    "Slack": rb"\bxox[abprs]-[0-9A-Za-z-]{20,}\b",
    "SendGrid": rb"\bSG\.[\w-]{22}\.[\w-]{43}\b",
    "Telegram": rb"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b",
    "private key": rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
}
# What libraries say about themselves at the top of their file: this also finds versions the address does not state
BANNERS = {
    "jquery": rb"jQuery(?: JavaScript Library)? v(\d+\.\d+\.\d+)", "bootstrap": rb"Bootstrap v(\d+\.\d+\.\d+)",
    "angular": rb"AngularJS v(\d+\.\d+\.\d+)", "vue": rb"Vue\.js v(\d+\.\d+\.\d+)", "lodash": rb"lodash(?:\.min)?\.js?[^\n]{0,40}?(\d+\.\d+\.\d+)|Lodash <[^>]*>\s*\n?\s*\*?[^\n]*?(\d+\.\d+\.\d+)",
    "moment": rb"//! version : (\d+\.\d+\.\d+)", "handlebars": rb"handlebars v(\d+\.\d+\.\d+)", "underscore": rb"Underscore\.js (\d+\.\d+\.\d+)",
    "dompurify": rb"DOMPurify (\d+\.\d+\.\d+)",
}
SECURITY_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy")
SESSION_NAME = re.compile(r"sess|auth|token|login|jwt|sid\b", re.IGNORECASE)
ERROR_SIGNS = rb"Fatal error</b>|Stack trace:|SQLSTATE\[|You have an error in your SQL syntax|Traceback \(most recent call last\)|Warning</b>:  ?[a-z_]+\(\)"


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.scripts, self.styles, self.forms, self.links, self.frames = [], [], [], [], []
        self.inline = []
        self.in_script = False
        self.form = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script":
            if a.get("src"):
                self.scripts.append(a)
            else:
                self.in_script = True
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower() and a.get("href"):
            self.styles.append(a)
        elif tag == "form":
            self.form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "password": False}
            self.forms.append(self.form)
        elif tag == "input" and self.form is not None and a.get("type", "").lower() == "password":
            self.form["password"] = True
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "iframe" and a.get("src"):
            self.frames.append(a["src"])

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False
        elif tag == "form":
            self.form = None

    def handle_data(self, data):
        if self.in_script and data.strip():
            self.inline.append(data)


def parse(html: str) -> Page:
    page = Page()
    try:
        page.feed(html)
    except (AssertionError, ValueError):
        pass        # broken HTML gives what was read so far
    return page


def registered_part(host: str) -> str:
    """Enough of a name to tell "our own CDN" from a stranger: www.a.az and cdn.a.az are both a.az."""
    labels = host.lower().split(".")
    if len(labels) > 2 and labels[-2] in ("com", "net", "org", "gov", "edu", "co", "ac"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _host_of(url: str, base: str) -> str:
    return urlsplit(urljoin(base, url)).hostname or ""


def find_secrets(body: bytes) -> list:
    return sorted(kind for kind, pattern in SECRET_PATTERNS.items() if re.search(pattern, body))


def banner_versions(body: bytes) -> dict:
    head = body[:4000]
    found = {}
    for name, pattern in BANNERS.items():
        match = re.search(pattern, head)
        if match:
            found[name] = next(g for g in match.groups() if g).decode()
    return found


def own_scripts(page: Page, base: str, limit: int = 6) -> list:
    host = urlsplit(base).hostname or ""
    urls = [urljoin(base, s["src"]) for s in page.scripts]
    own = [u for u in urls if urlsplit(u).hostname == host and urlsplit(u).scheme in ("http", "https")]
    return list(dict.fromkeys(own))[:limit]


def audit_forms(page: Page, base: str) -> dict:
    scheme = urlsplit(base).scheme
    own = registered_part(urlsplit(base).hostname or "")
    plain, outside = 0, set()
    for form in page.forms:
        target = urljoin(base, form["action"] or base)
        parts = urlsplit(target)
        if form["password"] and (parts.scheme == "http" or (scheme == "http" and not form["action"])):
            plain += 1
        if parts.hostname and form["method"] == "post" and registered_part(parts.hostname) != own:
            outside.add(parts.hostname)
    return {"password_plain": plain, "outside": sorted(outside), "total": len(page.forms), "passwords": sum(f["password"] for f in page.forms)}


def outside_resources(page: Page, base: str) -> dict:
    own = registered_part(urlsplit(base).hostname or "")
    hosts, unsigned, plain = set(), set(), 0
    for script in page.scripts:
        host = _host_of(script["src"], base)
        if script["src"].lower().startswith("http://"):
            plain += 1
        if host and registered_part(host) != own:
            hosts.add(host)
            if not script.get("integrity"):
                unsigned.add(host)
    return {"hosts": sorted(hosts), "unsigned": sorted(unsigned), "plain_scripts": plain if urlsplit(base).scheme == "https" else 0}


def audit_headers(headers: dict) -> dict:
    missing = [name for name in SECURITY_HEADERS if name not in headers]
    csp = headers.get("content-security-policy", "")
    script_rule = next((part for part in csp.split(";") if part.strip().lower().startswith(("script-src", "default-src"))), "")
    unsafe = [word for word in ("'unsafe-inline'", "'unsafe-eval'") if word in script_rule.lower()]
    age = re.search(r"max-age=(\d+)", headers.get("strict-transport-security", ""), re.IGNORECASE)
    return {"missing": missing, "csp_unsafe": unsafe, "hsts_short": bool(age and int(age.group(1)) < 15552000),
            "cors_any": headers.get("access-control-allow-origin", "") == "*"}


def audit_cookies(cookies: list, https: bool) -> list:
    weak = []
    for cookie in cookies:
        if SESSION_NAME.search(cookie["name"]) and ((https and not cookie["secure"]) or not cookie["httponly"]):
            weak.append(cookie["name"])
    return weak[:6]


def robots_paths(text: str) -> list:
    """Paths a robots.txt names that look private. The file is public, and it tells everyone where these are."""
    paths = re.findall(r"(?im)^\s*disallow:\s*(/\S*)", text)
    # WordPress writes /wp-admin/ there on every site: naming it would say nothing about this one
    return [p for p in dict.fromkeys(paths) if not p.startswith("/wp-admin") and re.search(r"admin|backup|private|secret|config|login|panel|\.sql|\.bak|\.env|internal|dev\b|test\b|old\b", p, re.IGNORECASE)][:8]
