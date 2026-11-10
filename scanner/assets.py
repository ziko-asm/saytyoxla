"""
What the home page makes a browser download besides its HTML: scripts, stylesheets and images.

The server's answer time says little about how fast a page feels: a page that answers in 100 ms and then
loads 6 MB of pictures is slow on a phone. Each file named in the HTML is asked for once, like a browser
would, and only its size and caching headers are kept. Nothing is executed, so files a script adds later
are not seen; the report says "at least" when the list was cut short.

Every address goes through the same checks as the page itself (scanner/safety.py): public addresses only,
standard ports, each redirect checked, the connection pinned to the address that was checked.
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait as wait_for
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

from scanner import fetch
from scanner.safety import UnsafeTarget, check_hop, resolve_public

MAX_ASSETS = 40             # files asked for; a page with more is reported as "at least"
ASSETS_BUDGET = 9           # seconds for all of them together
ASSET_TIMEOUT = 4
MAX_ASSET_BYTES = 10_000_000
ASSET_REDIRECTS = 3
MAX_AGE = re.compile(r"max-age\s*=\s*(\d+)")


class _Assets(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_head = False
        self.scripts, self.styles, self.images = [], [], []     # addresses as written in the page
        self.blocking = 0       # scripts in <head> the browser must fetch and run before it shows anything
        self.lazy = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "head":
            self.in_head = True
        elif tag == "body":
            self.in_head = False
        elif tag == "script" and a.get("src"):
            kind = a.get("type", "").strip().lower()
            if kind and kind != "module" and "javascript" not in kind:
                return                  # a data block, not code
            self.scripts.append(a["src"])
            self.blocking += self.in_head and kind != "module" and "async" not in a and "defer" not in a
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower().split() and a.get("href"):
            self.styles.append(a["href"])
        elif tag == "img" and a.get("src"):
            self.images.append(a["src"])
            self.lazy += a.get("loading", "").lower() == "lazy"

    def handle_endtag(self, tag):
        if tag == "head":
            self.in_head = False


def listed(html: str, base: str) -> tuple[list, _Assets]:
    """(kind, absolute address) for each file the page names, each address once, in the order a browser needs
    them: what blocks the first paint (styles, scripts) before the pictures."""
    page = _Assets()
    page.feed(html)
    seen, out = set(), []
    for kind, urls in (("style", page.styles), ("script", page.scripts), ("image", page.images)):
        for raw in urls:
            url = urljoin(base, raw.strip()).split("#")[0]
            if urlsplit(url).scheme in ("http", "https") and url not in seen:
                seen.add(url)
                out.append((kind, url))
    return out, page


def _cached(headers) -> bool:
    control = headers.get("cache-control", "").lower()
    if "no-store" in control or "no-cache" in control:
        return False
    m = MAX_AGE.search(control)
    return bool(m and int(m.group(1)) > 0) or "immutable" in control or (not m and bool(headers.get("expires")))


def measure(url: str, verify: bool, deadline: float, resolve=resolve_public) -> dict | None:
    """The file's size as it travels (compressed), and whether a browser may keep it. None if it did not answer."""
    try:
        for _ in range(ASSET_REDIRECTS + 1):
            ip = resolve(check_hop(url))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            with fetch._session(ip) as s:
                r = s.get(url, headers={"User-Agent": fetch.USER_AGENT, "Accept": "*/*"}, allow_redirects=False,
                          stream=True, verify=verify, timeout=(min(ASSET_TIMEOUT, remaining), min(ASSET_TIMEOUT, remaining)))
                try:
                    if r.is_redirect and r.headers.get("location"):
                        url = urljoin(url, r.headers["location"])
                        continue
                    if r.status_code != 200:
                        return None
                    length = r.headers.get("content-length", "")
                    if length.isdigit():
                        size = int(length)
                    else:               # sent in pieces: count them as they arrive, without unpacking
                        size = 0
                        while size < MAX_ASSET_BYTES and time.monotonic() < deadline:
                            chunk = r.raw.read1(65536, decode_content=False)
                            if not chunk:
                                break
                            size += len(chunk)
                    return {"bytes": min(size, MAX_ASSET_BYTES), "cached": _cached(r.headers),
                            "type": r.headers.get("content-type", "").split(";")[0].strip().lower()}
                finally:
                    r.close()
    except (requests.RequestException, urllib3.exceptions.HTTPError, UnsafeTarget, OSError, ValueError):
        return None
    return None


def collect(html: str, base: str, verify: bool = True, measure=measure) -> dict:
    """{"items": [{"kind", "url", "bytes", "cached", "own"}], "found", "blocking", "images", "lazy"}.
    An item that did not answer in time has bytes None, so the report never counts it as zero."""
    files, page = listed(html, base)
    chosen = files[:MAX_ASSETS]
    host = urlsplit(base).hostname or ""
    deadline = time.monotonic() + ASSETS_BUDGET
    pool = ThreadPoolExecutor(max_workers=10)
    jobs = [pool.submit(measure, url, verify, deadline) for _, url in chosen]
    wait_for(jobs, timeout=ASSETS_BUDGET + 1)
    pool.shutdown(wait=False, cancel_futures=True)
    items = []
    for (kind, url), job in zip(chosen, jobs, strict=True):
        got = job.result() if job.done() and not job.cancelled() and not job.exception() else None
        items.append({"kind": kind, "url": url, "bytes": got and got["bytes"], "cached": bool(got and got["cached"]),
                      "own": (urlsplit(url).hostname or "") == host})
    return {"items": items, "found": len(files), "blocking": page.blocking, "images": len(page.images), "lazy": page.lazy}
