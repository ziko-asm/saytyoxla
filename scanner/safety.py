"""
Input validation for a public scanner.

The service fetches URLs that strangers type in, so it must never be turned
against internal networks (SSRF): only http/https, only public IP addresses,
no unusual ports, no credentials in the URL.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

ALLOWED_PORTS = {None, 80, 443}
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,63}|xn--[a-z0-9-]{1,59})$")


class UnsafeTarget(ValueError):
    """Raised with a message that can be shown to the user."""


def ascii_host(host: str) -> str:
    """The name DNS knows: münchen.de -> xn--mnchen-3ya.de. Empty if it cannot be converted."""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""


def normalize(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise UnsafeTarget("Saytın ünvanını yazın, məsələn: example.az")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:      # an unclosed [ or a port that is not a number
        raise UnsafeTarget("Ünvan düzgün görünmür. Nümunə: example.az") from None
    if parts.scheme not in ("http", "https"):
        raise UnsafeTarget("Yalnız http və https ünvanları yoxlanılır.")
    if parts.username or parts.password:
        raise UnsafeTarget("Ünvanda istifadəçi adı və ya şifrə olmamalıdır.")
    host = ascii_host((parts.hostname or "").lower().rstrip("."))
    if not HOST_RE.match(host):
        raise UnsafeTarget("Ünvan düzgün görünmür. Nümunə: example.az")
    if port not in ALLOWED_PORTS:
        raise UnsafeTarget("Yalnız standart portlar (80, 443) yoxlanılır.")
    return f"{parts.scheme}://{host}{parts.path or '/'}"


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_global and not addr.is_multicast


def resolve_public(host: str, resolver=socket.getaddrinfo) -> str:
    """Resolve the host once and return one of its addresses, refusing it unless every address is public.

    The caller must connect to the returned address (scanner/fetch.py pins it) and never resolve the
    name again: a second lookup can return a different answer (DNS rebinding) and reach an internal address.
    """
    try:
        infos = resolver(host, None)
    except OSError:
        raise UnsafeTarget("Bu ünvan tapılmadı. Yazılışı yoxlayın.") from None
    ips = sorted({info[4][0] for info in infos}, key=lambda ip: ":" in ip)   # IPv4 first
    if not ips or not all(is_public_ip(ip) for ip in ips):
        raise UnsafeTarget("Bu ünvan daxili şəbəkəyə aiddir və yoxlanıla bilməz.")
    return ips[0]


def check_host_is_public(host: str, resolver=socket.getaddrinfo) -> None:
    resolve_public(host, resolver)


def check_hop(url: str) -> str:
    """Check a URL reached through a redirect like the typed address (scheme, credentials, port) and return
    its host. A redirect may point anywhere, so every hop is checked, not only the first one."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise UnsafeTarget("Yalnız http və https ünvanları yoxlanılır.")
    if parts.username or parts.password:
        raise UnsafeTarget("Ünvanda istifadəçi adı və ya şifrə olmamalıdır.")
    try:
        port = parts.port
    except ValueError:
        raise UnsafeTarget("Ünvan düzgün görünmür. Nümunə: example.az") from None
    if port not in ALLOWED_PORTS:
        raise UnsafeTarget("Yalnız standart portlar (80, 443) yoxlanılır.")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise UnsafeTarget("Ünvan düzgün görünmür. Nümunə: example.az")
    return host
