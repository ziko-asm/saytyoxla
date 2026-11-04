"""
Collect what a normal visitor's browser would see: one page load (following
redirects, each hop checked), the TLS certificate, and two public DNS records.
Nothing here probes hidden paths or sends unusual requests.

Every connection goes to an address that was resolved and checked just before (see _PinnedAdapter):
the host name is never looked up a second time, so a DNS answer that changes between the check and the
connection (DNS rebinding) cannot point the scanner at an internal address.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, InsecureRequestWarning, NewConnectionError
from urllib3.util.connection import create_connection

from scanner.models import Context
from scanner.safety import UnsafeTarget, check_hop, resolve_public

USER_AGENT = "SaytYoxla/0.1 (sayt saglamligi yoxlamasi)"
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
PAGE_BUDGET = 15        # seconds for the whole page load, redirects and body included
HTTP_CHECK_BUDGET = 8   # seconds for the http -> https check
MAX_REDIRECTS = 5
MAX_HTML = 3_000_000
META_CHARSET = re.compile(rb"""<meta[^>]+charset=["']?([A-Za-z0-9_\-]+)""", re.IGNORECASE)
MAX_DMARC_PARENTS = 2   # docs.shop.example.az -> shop.example.az, example.az

urllib3.disable_warnings(InsecureRequestWarning)    # verify=False is deliberate, see _open()


class _PinnedAdapter(HTTPAdapter):
    """Connects to one already-checked IP address instead of resolving the host name again.
    The URL keeps the host name, so the Host header, TLS SNI and certificate checks are unchanged."""

    def __init__(self, ip: str):
        self._ip = ip
        super().__init__(max_retries=0)

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        ip = self._ip

        def open_socket(conn):
            # Only the socket goes to `ip`. conn.host stays the host name: urllib3 uses it for the Host
            # header, TLS SNI and the certificate check, so those behave exactly as for a normal request.
            try:
                return create_connection((ip, conn.port), conn.timeout, source_address=conn.source_address,
                                         socket_options=conn.socket_options)
            except TimeoutError as e:
                raise ConnectTimeoutError(conn, f"Connection to {conn.host} timed out.") from e
            except OSError as e:
                raise NewConnectionError(conn, f"Failed to establish a new connection: {e}") from e

        class Conn(HTTPConnection):
            def _new_conn(self):
                return open_socket(self)

        class TLSConn(HTTPSConnection):
            def _new_conn(self):
                return open_socket(self)

        self.poolmanager.pool_classes_by_scheme = {
            "http": type("PinnedPool", (HTTPConnectionPool,), {"ConnectionCls": Conn}),
            "https": type("PinnedTLSPool", (HTTPSConnectionPool,), {"ConnectionCls": TLSConn}),
        }


def _session(ip: str) -> requests.Session:
    s = requests.Session()
    s.trust_env = False                     # no proxy from the environment: the connection must go to `ip`
    s.mount("http://", _PinnedAdapter(ip))
    s.mount("https://", _PinnedAdapter(ip))
    return s


def _encoding(r: requests.Response, body: bytes) -> str:
    """The charset a browser would use: the header's, else <meta charset>, else UTF-8.
    (requests falls back to ISO-8859-1 for text/html without a charset, which garbles ə, ş, ğ.)"""
    if "charset=" in r.headers.get("content-type", "").lower() and r.encoding:
        return r.encoding
    m = META_CHARSET.search(body[:4096])
    if m:
        name = m.group(1).decode("ascii", "ignore")
        try:
            "".encode(name)
            return name
        except LookupError:
            pass
    return "utf-8"


def _get(url: str, resolve=resolve_public, budget: float = PAGE_BUDGET, verify: bool = True):
    """GET with redirects followed by hand: every hop is checked (scheme, port, public address) and
    connected to the address that was checked. The whole call, body included, stays within `budget`."""
    deadline = time.perf_counter() + budget
    chain = []
    for _ in range(MAX_REDIRECTS + 1):
        host = check_hop(url)
        ip = resolve(host)
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise requests.exceptions.Timeout("time budget used up")
        t0 = time.perf_counter()
        with _session(ip) as s:
            r = s.get(url, headers={"User-Agent": USER_AGENT}, allow_redirects=False, stream=True, verify=verify,
                      timeout=(CONNECT_TIMEOUT, min(READ_TIMEOUT, remaining)))
            elapsed = 1000 * (time.perf_counter() - t0)
            if r.is_redirect and r.headers.get("location"):
                chain.append(url)
                url = urljoin(url, r.headers["location"])
                r.close()
                continue
            body = bytearray()
            try:
                # read1 returns whatever has arrived (iter_content waits for a full 64 KB), so the deadline
                # is checked after every packet: a server that trickles bytes cannot hold the scan
                while len(body) < MAX_HTML:
                    if time.perf_counter() > deadline:
                        raise requests.exceptions.ReadTimeout("time budget used up")
                    try:
                        chunk = r.raw.read1(65536, decode_content=True)   # gzip/deflate like a browser
                    except Exception as e:       # urllib3 read/decode errors -> the same type collect() handles
                        raise requests.exceptions.ConnectionError(str(e)) from e
                    if not chunk:
                        break
                    body += chunk
            finally:
                r.close()
        return r, url, chain, elapsed, bytes(body), ip
    raise UnsafeTarget("Sayt çox sayda yönləndirmə edir.")


def cert_info(host: str, ip: str | None = None, port: int = 443) -> dict:
    """Certificate of `host`, read from the already-checked address `ip` (never a fresh DNS answer)."""
    ctx = ssl.create_default_context()
    try:
        ip = ip or resolve_public(host)
        with (
            socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as tls,
        ):
            c = tls.getpeercert()
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(c["notAfter"]), tz=timezone.utc)
        issuer = dict(x[0] for x in c.get("issuer", ())).get("organizationName", "")
        return {"days_left": (expires - datetime.now(timezone.utc)).days, "issuer": issuer,
                "expires": expires.date().isoformat(), "error": None}
    except ssl.SSLCertVerificationError as e:
        return {"days_left": None, "issuer": "", "expires": None, "error": e.verify_message or "invalid"}
    except UnsafeTarget:
        return {"days_left": None, "issuer": "", "expires": None, "error": "unsafe"}
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
        answers = dns.resolver.resolve(name, "TXT", lifetime=4)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return None
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]


def mail_domain(host: str) -> str:
    return host.removeprefix("www.")


def _is_dmarc(records: list | None) -> bool:
    return any(r.lower().startswith("v=dmarc1") for r in records or [])


def dmarc_records(domain: str) -> tuple[list | None, str | None]:
    """The DMARC records that apply to `domain` and, when they come from a parent, that parent's name.
    A subdomain without its own record is covered by its parent's, so `docs.example.az` looks at `example.az`
    too (the DNS tree walk of RFC 7489's successor). The last label is never tried: a TLD is not a mail domain."""
    records = txt_records("_dmarc." + domain)
    if records is None or _is_dmarc(records):
        return records, None
    labels = domain.split(".")
    for i in range(1, min(len(labels) - 1, MAX_DMARC_PARENTS + 1)):
        parent = ".".join(labels[i:])
        parent_records = txt_records("_dmarc." + parent)
        if _is_dmarc(parent_records):
            return parent_records, parent
    return records, None


def _open(url: str):
    """Load the page, returning _get()'s values and whether the certificate was accepted. A bad certificate is
    a finding, not a dead end: the page is read anyway so its owner gets a report. Nothing secret is sent, and
    every hop still goes through the same public-address checks."""
    try:
        return (*_get(url), True)
    except requests.exceptions.SSLError:
        return (*_get(url, budget=HTTP_CHECK_BUDGET, verify=False), False)


def _open_with_fallback(url: str):
    """Addresses typed without a scheme are tried on https first; a site that only answers on http still
    gets a report (with the missing HTTPS as its main finding) instead of 'the site did not open'."""
    try:
        return _open(url)
    except requests.exceptions.ConnectionError as first:
        if not url.startswith("https://"):
            raise
        try:
            return (*_get("http://" + url.removeprefix("https://"), budget=HTTP_CHECK_BUDGET), True)
        except requests.RequestException:
            raise first from None


def collect(url: str) -> Context:
    ctx = Context(input_url=url, host=urlsplit(url).hostname or "")
    try:
        r, final, chain, elapsed, body, ip, verified = _open_with_fallback(url)
    except requests.RequestException as e:
        ctx.error = type(e).__name__
        return ctx
    ctx.final_url, ctx.redirect_chain, ctx.elapsed_ms = final, chain, elapsed
    ctx.status_code = r.status_code
    ctx.headers = {k.lower(): v for k, v in r.headers.items()}
    ctx.html_bytes = len(body)
    ctx.html = body.decode(_encoding(r, body), "replace")

    final_host = urlsplit(final).hostname or ctx.host
    if urlsplit(final).scheme == "https":
        ctx.cert = cert_info(final_host, ip)
    # Does the plain-http address end up on https?
    try:
        _, http_final, _, _, _, _ = _get("http://" + ctx.host + "/", budget=HTTP_CHECK_BUDGET, verify=verified)
        ctx.http_to_https = urlsplit(http_final).scheme == "https"
    except (requests.RequestException, UnsafeTarget):
        ctx.http_to_https = None

    domain = mail_domain(final_host)
    dmarc, dmarc_parent = dmarc_records(domain)
    ctx.txt_records = {"spf": txt_records(domain), "dmarc": dmarc, "dmarc_parent": dmarc_parent}
    return ctx
