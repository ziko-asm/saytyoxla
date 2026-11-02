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
