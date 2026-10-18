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
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


class UnsafeTarget(ValueError):
    """Raised with a message that can be shown to the user."""


def normalize(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise UnsafeTarget("Saytın ünvanını yazın, məsələn: example.az")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise UnsafeTarget("Yalnız http və https ünvanları yoxlanılır.")
    if parts.username or parts.password:
        raise UnsafeTarget("Ünvanda istifadəçi adı və ya şifrə olmamalıdır.")
    host = (parts.hostname or "").lower().rstrip(".")
    if not HOST_RE.match(host):
        raise UnsafeTarget("Ünvan düzgün görünmür. Nümunə: example.az")
    if parts.port not in ALLOWED_PORTS:
        raise UnsafeTarget("Yalnız standart portlar (80, 443) yoxlanılır.")
    return f"{parts.scheme}://{host}{parts.path or '/'}"


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return addr.is_global and not addr.is_multicast


def check_host_is_public(host: str, resolver=socket.getaddrinfo) -> None:
    try:
        infos = resolver(host, None)
    except OSError:
        raise UnsafeTarget("Bu ünvan tapılmadı. Yazılışı yoxlayın.") from None
    ips = {info[4][0] for info in infos}
    if not ips or not all(is_public_ip(ip) for ip in ips):
        raise UnsafeTarget("Bu ünvan daxili şəbəkəyə aiddir və yoxlanıla bilməz.")
