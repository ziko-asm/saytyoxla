"""
Collect what a normal visitor's browser would see: one page load (following
redirects, each hop checked), the TLS certificate, and two public DNS records.
Nothing here probes hidden paths or sends unusual requests.
"""

from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import requests

from scanner.models import Context
from scanner.safety import UnsafeTarget, check_host_is_public

USER_AGENT = "SaytYoxla/0.1 (sayt saglamligi yoxlamasi)"
TIMEOUT = 10
MAX_REDIRECTS = 5
MAX_HTML = 3_000_000


def _get(url: str, host_check=check_host_is_public):
    """GET with redirects followed by hand so every hop is validated."""
    chain = []
    for _ in range(MAX_REDIRECTS + 1):
        host = urlsplit(url).hostname or ""
        host_check(host)
        t0 = time.perf_counter()
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT,
                         allow_redirects=False, stream=True)
        elapsed = 1000 * (time.perf_counter() - t0)
        if r.is_redirect and r.headers.get("location"):
            chain.append(url)
            url = urljoin(url, r.headers["location"])
            r.close()
            continue
        body = bytearray()
        for chunk in r.iter_content(65536):   # handles gzip/deflate the same way a browser does
            body += chunk
            if len(body) >= MAX_HTML:
                break
        r.close()
        body = bytes(body)
        return r, url, chain, elapsed, body
    raise UnsafeTarget("Sayt çox sayda yönləndirmə edir.")


def cert_info(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=TIMEOUT) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as tls,
        ):
            c = tls.getpeercert()
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(c["notAfter"]), tz=timezone.utc)
        issuer = dict(x[0] for x in c.get("issuer", ())).get("organizationName", "")
        return {"days_left": (expires - datetime.now(timezone.utc)).days, "issuer": issuer,
                "expires": expires.date().isoformat(), "error": None}
    except ssl.SSLCertVerificationError as e:
        return {"days_left": None, "issuer": "", "expires": None, "error": e.verify_message or "invalid"}
    except (OSError, ssl.SSLError) as e:
        return {"days_left": None, "issuer": "", "expires": None, "error": type(e).__name__}


def txt_records(name: str) -> list | None:
    """TXT records for a DNS name; [] if none, None if the lookup failed."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError:
        return None
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return None
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]


def mail_domain(host: str) -> str:
    return host.removeprefix("www.")


def collect(url: str) -> Context:
    ctx = Context(input_url=url, host=urlsplit(url).hostname or "")
    try:
        r, final, chain, elapsed, body = _get(url)
    except requests.RequestException as e:
        ctx.error = type(e).__name__
        return ctx
    ctx.final_url, ctx.redirect_chain, ctx.elapsed_ms = final, chain, elapsed
    ctx.status_code = r.status_code
    ctx.headers = {k.lower(): v for k, v in r.headers.items()}
    ctx.html_bytes = len(body)
    ctx.html = body.decode(r.encoding or r.apparent_encoding or "utf-8", "replace")

    final_host = urlsplit(final).hostname or ctx.host
    if urlsplit(final).scheme == "https":
        ctx.cert = cert_info(final_host)
    # Does the plain-http address end up on https?
    try:
        _, http_final, _, _, _ = _get("http://" + ctx.host + "/")
        ctx.http_to_https = urlsplit(http_final).scheme == "https"
    except (requests.RequestException, UnsafeTarget):
        ctx.http_to_https = None

    domain = mail_domain(final_host)
    ctx.txt_records = {"spf": txt_records(domain), "dmarc": txt_records("_dmarc." + domain)}
    return ctx
