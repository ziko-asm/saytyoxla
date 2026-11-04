"""SSRF and resource limits of the page loader (scanner/fetch.py), tested against local servers only."""

from __future__ import annotations

import http.server
import socket
import threading
import time

import pytest
import requests

from scanner import fetch, safety
from scanner.safety import UnsafeTarget, check_hop, resolve_public


def _page(url, verify=True):
    class Response:
        status_code, headers = 200, {"Content-Type": "text/html"}
        encoding = "utf-8"
    return Response(), url, [], 10.0, b"<title>Salam</title>", "93.184.216.34"


def _no_network(monkeypatch, get):
    monkeypatch.setattr(fetch, "_get", get)
    monkeypatch.setattr(fetch, "cert_info", lambda host, ip: {"days_left": None, "issuer": "", "expires": None,
                                                              "error": "certificate has expired"})
    monkeypatch.setattr(fetch, "txt_records", lambda name: [])


def test_bad_certificate_still_gives_a_report_read_without_verification(monkeypatch):
    calls = []

    def get(url, budget=None, verify=True):
        calls.append((url, verify))
        if url.startswith("https://") and verify:
            raise requests.exceptions.SSLError("certificate verify failed")
        return _page(url)
    _no_network(monkeypatch, get)
    ctx = fetch.collect("https://expired.example.az/")
    assert ctx.error is None and ctx.final_url == "https://expired.example.az/" and ctx.cert["error"]
    assert ("https://expired.example.az/", True) in calls and ("https://expired.example.az/", False) in calls
    assert ("http://expired.example.az/", False) in calls      # the http check may end on the same bad certificate


def test_tls_that_never_works_reports_ssl_error(monkeypatch):
    def get(url, budget=None, verify=True):
        raise requests.exceptions.SSLError("handshake failure")
    _no_network(monkeypatch, get)
    assert fetch.collect("https://old.example.az/").error == "SSLError"


def test_site_only_on_http_still_gives_a_report(monkeypatch):
    def get(url, budget=None, verify=True):
        if url.startswith("https://"):
            raise requests.exceptions.ConnectionError("port 443 closed")
        return _page(url)
    _no_network(monkeypatch, get)
    ctx = fetch.collect("https://plain.example.az/")
    assert ctx.error is None and ctx.final_url == "http://plain.example.az/" and ctx.cert is None


def test_read_timeout_does_not_retry_on_http(monkeypatch):
    calls = []

    def get(url, budget=None, verify=True):
        calls.append(url)
        raise requests.exceptions.ReadTimeout("slow")
    _no_network(monkeypatch, get)
    assert fetch.collect("https://slow.example.az/").error == "ReadTimeout" and len(calls) == 1


def test_first_error_is_kept_when_the_http_fallback_fails_too(monkeypatch):
    def get(url, budget=None, verify=True):
        raise (requests.exceptions.ConnectTimeout("x") if url.startswith("https://")
               else requests.exceptions.ConnectionError("y"))
    _no_network(monkeypatch, get)
    assert fetch.collect("https://down.example.az/").error == "ConnectTimeout"


def _file_server(monkeypatch, files):
    def get(url, budget=None, verify=True):
        for path, (status, ctype, body) in files.items():
            if url.endswith(path):
                class Response:
                    status_code, headers = status, {"content-type": ctype}
                return Response(), url, [], 1.0, body.encode(), "93.184.216.34"
        raise requests.exceptions.ConnectionError("no such file")
    monkeypatch.setattr(fetch, "_get", get)


def test_robots_txt_html_answer_means_no_file(monkeypatch):
    _file_server(monkeypatch, {"/robots.txt": (200, "text/html", "<html>page</html>")})
    assert fetch.robots_txt("https://a.az", True) == ""
    _file_server(monkeypatch, {"/robots.txt": (200, "text/plain", "User-agent: *")})
    assert fetch.robots_txt("https://a.az", True) == "User-agent: *"
    _file_server(monkeypatch, {"/robots.txt": (404, "text/plain", "gone")})
    assert fetch.robots_txt("https://a.az", True) == ""


def test_sitemap_comes_from_robots_or_a_real_xml_file(monkeypatch):
    _file_server(monkeypatch, {})
    assert fetch.has_sitemap("https://a.az", "Sitemap: https://a.az/s.xml\n", True) is True
    assert fetch.has_sitemap("https://a.az", "", True) is False
    _file_server(monkeypatch, {"/sitemap.xml": (200, "application/xml", "<?xml?><urlset></urlset>")})
    assert fetch.has_sitemap("https://a.az", "", True) is True
    _file_server(monkeypatch, {"/sitemap.xml": (200, "text/html", "<urlset>")})
    assert fetch.has_sitemap("https://a.az", "", True) is False
    _file_server(monkeypatch, {"/sitemap.xml": (200, "text/xml", "<html>not a sitemap</html>")})
    assert fetch.has_sitemap("https://a.az", "", True) is False


def test_dkim_finds_only_real_keys_and_admits_when_dns_is_down(monkeypatch):
    table = {"google._domainkey.a.az": ["v=DKIM1; k=rsa; p=ABC"], "mail._domainkey.a.az": ["not a key"],
             "k1._domainkey.a.az": ["k=rsa; p=MIGf"], "s1._domainkey.a.az": ["v=DKIM1; p="],     # s1: a revoked key
             "s2._domainkey.a.az": ["v=DKIM1; p= ; t=y"], "dkim._domainkey.a.az": ["sp=ABC"]}
    monkeypatch.setattr(fetch, "txt_records", lambda name: table.get(name, []))
    assert sorted(fetch.dkim_selectors("a.az")) == ["google", "k1"]
    monkeypatch.setattr(fetch, "txt_records", lambda name: None)
    assert fetch.dkim_selectors("a.az") is None


def test_slow_extras_stay_unknown_and_do_not_hold_the_scan(monkeypatch):
    def get(url, budget=None, verify=True):
        if url.endswith("/robots.txt"):
            time.sleep(2)
        return _page(url)
    _no_network(monkeypatch, get)
    monkeypatch.setattr(fetch, "EXTRAS_BUDGET", 0.3)
    started = time.perf_counter()
    ctx = fetch.collect("https://slow-files.example.az/")
    assert ctx.error is None and ctx.robots is None and ctx.sitemap is None
    assert time.perf_counter() - started < 1.5


def test_one_failed_extra_does_not_lose_the_others(monkeypatch):
    def boom(host, ip):
        raise RuntimeError("unexpected")
    _no_network(monkeypatch, lambda url, budget=None, verify=True: _page(url))
    monkeypatch.setattr(fetch, "cert_info", boom)
    ctx = fetch.collect("https://a.example.az/")
    assert ctx.cert.get("unknown") is True and ctx.http_to_https is not None and ctx.dkim == []


def test_cookies_are_read_one_by_one():
    class Raw:
        class headers:
            @staticmethod
            def getlist(name):
                return ["a=1; Secure", "b=2"]

    class Response:
        raw = Raw
    assert fetch.set_cookies(Response) == ["a=1; Secure", "b=2"]
    assert fetch.set_cookies(object()) == []


def test_dmarc_walks_up_to_the_parent_but_never_to_the_tld(monkeypatch):
    asked = []
    table = {"_dmarc.example.az": ["v=DMARC1; p=reject"]}

    def lookup(name):
        asked.append(name)
        return table.get(name, [])
    monkeypatch.setattr(fetch, "txt_records", lookup)
    assert fetch.dmarc_records("docs.shop.example.az") == (["v=DMARC1; p=reject"], "example.az")
    asked.clear()
    assert fetch.dmarc_records("example.az") == (["v=DMARC1; p=reject"], None)
    assert asked == ["_dmarc.example.az"]
    asked.clear()
    assert fetch.dmarc_records("nothing.az") == ([], None)
    assert asked == ["_dmarc.nothing.az"]


def test_dmarc_parent_walk_is_bounded_and_stops_on_dns_failure(monkeypatch):
    asked = []

    def lookup(name):
        asked.append(name)
        return []
    monkeypatch.setattr(fetch, "txt_records", lookup)
    fetch.dmarc_records("a.b.c.d.example.az")
    assert len(asked) == 1 + fetch.MAX_DMARC_PARENTS
    monkeypatch.setattr(fetch, "txt_records", lambda name: None)
    assert fetch.dmarc_records("a.example.az") == (None, None)


def _serve(ip: str, port: int, handler):
    srv = http.server.ThreadingHTTPServer((ip, port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _handler(body: bytes = b"", status: int = 200, headers: dict | None = None, trickle: float = 0):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            if not trickle:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if trickle:                      # one byte at a time, forever (until the client hangs up)
                try:
                    while True:
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(trickle)
                except OSError:
                    return
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    return H


@pytest.fixture
def two_hosts():
    """The same port on two loopback addresses: 127.0.0.2 plays the public site, 127.0.0.1 an internal service."""
    for _ in range(20):
        probe = socket.socket()
        probe.bind(("127.0.0.2", 0))
        port = probe.getsockname()[1]
        probe.close()
        try:
            public = _serve("127.0.0.2", port, _handler(b"PUBLIC SITE", headers={"Content-Type": "text/html"}))
            internal = _serve("127.0.0.1", port, _handler(b"INTERNAL ONLY", headers={"Content-Type": "text/html"}))
            break
        except OSError:
            continue
    else:
        pytest.skip("could not bind the same port on 127.0.0.1 and 127.0.0.2")
    yield port
    public.shutdown()
    internal.shutdown()


@pytest.fixture
def allow_port(monkeypatch):
    def allow(port):
        monkeypatch.setattr(safety, "ALLOWED_PORTS", {None, 80, 443, port})
    return allow


def test_dns_rebinding_cannot_reach_internal_address(two_hosts, allow_port, monkeypatch):
    """The checked address is the one connected to: a second DNS answer (127.0.0.1) is never used."""
    allow_port(two_hosts)
    real = socket.getaddrinfo

    def rebinding(host, *args, **kwargs):           # every lookup the scanner might make on its own
        if host == "rebind.test":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", two_hosts))]
        return real(host, *args, **kwargs)
    monkeypatch.setattr(socket, "getaddrinfo", rebinding)

    _r, _url, _chain, _ms, body, ip = fetch._get(f"http://rebind.test:{two_hosts}/", resolve=lambda host: "127.0.0.2")
    assert body == b"PUBLIC SITE" and ip == "127.0.0.2"


def test_pinned_request_keeps_the_host_name(allow_port):
    """Pinning changes only where the socket goes: the Host header (and TLS SNI) keep the host name,
    or virtual-hosted sites would answer for the wrong site."""
    class Echo(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = self.headers.get("Host", "").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    srv = _serve("127.0.0.1", 0, Echo)
    port = srv.server_address[1]
    allow_port(port)
    try:
        *_, body, _ip = fetch._get(f"http://shop.example.az:{port}/", resolve=lambda host: "127.0.0.1")
    finally:
        srv.shutdown()
    assert body.decode() == f"shop.example.az:{port}"


def test_redirect_to_another_port_is_refused(allow_port):
    srv = _serve("127.0.0.1", 0, _handler(status=302, headers={"Location": "http://example.test:9001/next"}))
    port = srv.server_address[1]
    allow_port(port)
    try:
        with pytest.raises(UnsafeTarget):
            fetch._get(f"http://site.test:{port}/", resolve=lambda host: "127.0.0.1")
    finally:
        srv.shutdown()


@pytest.mark.parametrize("target", ["ftp://example.test/", "http://user:pw@example.test/", "http://example.test:22/"])
def test_redirect_hops_are_checked_like_typed_addresses(target, allow_port):
    srv = _serve("127.0.0.1", 0, _handler(status=301, headers={"Location": target}))
    port = srv.server_address[1]
    allow_port(port)
    try:
        with pytest.raises(UnsafeTarget):
            fetch._get(f"http://site.test:{port}/", resolve=lambda host: "127.0.0.1")
    finally:
        srv.shutdown()


def test_slow_server_cannot_hold_the_scan(allow_port):
    srv = _serve("127.0.0.1", 0, _handler(headers={"Content-Type": "text/html"}, trickle=0.05))
    port = srv.server_address[1]
    allow_port(port)
    t0 = time.perf_counter()
    try:
        with pytest.raises(requests.exceptions.ReadTimeout):
            fetch._get(f"http://slow.test:{port}/", resolve=lambda host: "127.0.0.1", budget=1)
    finally:
        srv.shutdown()
    assert time.perf_counter() - t0 < 3


def test_page_charset_comes_from_meta_when_header_has_none(allow_port):
    page = '<html><head><meta charset="utf-8"><title>Ətirli sabunlar — Şəki</title></head></html>'.encode()
    srv = _serve("127.0.0.1", 0, _handler(page, headers={"Content-Type": "text/html"}))
    port = srv.server_address[1]
    allow_port(port)
    try:
        r, _url, _chain, _ms, body, _ip = fetch._get(f"http://az.test:{port}/", resolve=lambda host: "127.0.0.1")
    finally:
        srv.shutdown()
    assert "Ətirli sabunlar — Şəki" in body.decode(fetch._encoding(r, body))


def test_resolve_public_refuses_any_private_answer():
    def answers(*ips):
        return lambda host, port: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]
    assert resolve_public("x.test", answers("93.184.215.14")) == "93.184.215.14"
    for bad in (("10.0.0.1",), ("93.184.215.14", "127.0.0.1"), ("169.254.169.254",), ("100.64.0.1",)):
        with pytest.raises(UnsafeTarget):
            resolve_public("x.test", answers(*bad))


@pytest.mark.parametrize("url", ["gopher://a.test/", "http://u:p@a.test/", "https://a.test:8443/", "http://a.test:99999/"])
def test_check_hop_refuses(url):
    with pytest.raises(UnsafeTarget):
        check_hop(url)


def test_check_hop_accepts_normal_urls():
    assert check_hop("https://Shop.Example.az/path?q=1") == "shop.example.az"
    assert check_hop("http://example.az:80/") == "example.az"
