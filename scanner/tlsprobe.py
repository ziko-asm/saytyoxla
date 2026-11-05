"""
Asks a server whether it would speak an old TLS version or a weak cipher, by sending the first TLS message by hand
and reading the first answer.

Python's own TLS library cannot do this reliably: builds leave out 3DES, RC4 and old versions, so "the handshake
failed" may only mean this machine could not offer them. Here the offer is ours, whatever the library supports.
No connection is completed and nothing is sent after the first message.
"""

from __future__ import annotations

import os
import socket
import struct

TLS10, TLS11, TLS12 = (3, 1), (3, 2), (3, 3)
TIMEOUT = 4

# Ciphers any server that still speaks an old version would accept
COMMON = (0xC013, 0xC014, 0xC009, 0xC00A, 0xC02F, 0xC030, 0x009C, 0x009D, 0x002F, 0x0035, 0x000A)
# cipher -> family of what is wrong with it
WEAK = {
    0x000A: "3DES", 0x0016: "3DES", 0xC012: "3DES", 0xC008: "3DES",
    0x0004: "RC4", 0x0005: "RC4", 0xC007: "RC4", 0xC011: "RC4",
    0x0009: "DES", 0x0015: "DES",
    0x0001: "NULL", 0x0002: "NULL", 0x003B: "NULL",
    0x0003: "EXPORT", 0x0006: "EXPORT", 0x0008: "EXPORT", 0x0014: "EXPORT",
}


def _extension(kind: int, body: bytes) -> bytes:
    return struct.pack(">HH", kind, len(body)) + body


def client_hello(host: str, version: tuple, ciphers: tuple) -> bytes:
    name = host.encode("ascii", "ignore")
    sni = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    groups = struct.pack(">HHHH", 6, 0x001D, 0x0017, 0x0018)
    algorithms = (0x0401, 0x0403, 0x0501, 0x0503, 0x0601, 0x0603, 0x0804, 0x0201, 0x0203)
    signatures = struct.pack(">H", len(algorithms) * 2) + b"".join(struct.pack(">H", a) for a in algorithms)
    extensions = (_extension(0, sni) + _extension(10, groups) + _extension(11, b"\x01\x00")
                  + _extension(13, signatures) + _extension(0xFF01, b"\x00"))
    suites = b"".join(struct.pack(">H", c) for c in ciphers)
    body = (bytes(version) + os.urandom(32) + b"\x00" + struct.pack(">H", len(suites)) + suites
            + b"\x01\x00" + struct.pack(">H", len(extensions)) + extensions)
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def read_answer(data: bytes) -> tuple | None:
    """(version, cipher) of a ServerHello at the start of `data`; None if it is anything else, such as an alert."""
    if len(data) < 5 + 4 + 2 + 32 + 1 or data[0] != 0x16 or data[5] != 0x02:
        return None
    at = 9
    version = (data[at], data[at + 1])
    at += 2 + 32
    at += 1 + data[at]
    if len(data) < at + 2:
        return None
    return version, struct.unpack(">H", data[at:at + 2])[0]


def _ask(host: str, ip: str, version: tuple, ciphers: tuple, port: int = 443) -> tuple | None | bool:
    """The ServerHello's (version, cipher); False if the server said no; None if nothing can be said."""
    try:
        sock = socket.create_connection((ip, port), timeout=TIMEOUT)
    except OSError:
        return None
    with sock:
        data = b""
        try:
            sock.sendall(client_hello(host, version, ciphers))
            while len(data) < 200:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if data[0] != 0x16:
                    break
        except TimeoutError:
            return None if not data else (read_answer(data) or False)
        except OSError:
            pass                # a reset straight after the offer is a refusal
    return read_answer(data) or False


def accepts_version(host: str, ip: str, version: tuple, port: int = 443) -> bool | None:
    answer = _ask(host, ip, version, COMMON, port)
    if answer is None or answer is False:
        return answer
    return answer[0] == version     # a server may answer with a newer version than offered only by breaking the rules


def weak_cipher(host: str, ip: str, port: int = 443) -> str | None | bool:
    """The family of a weak cipher the server agreed to; False if it refused them all; None if nothing can be said."""
    answer = _ask(host, ip, TLS12, tuple(WEAK), port)
    if answer is None or answer is False:
        return answer
    return WEAK.get(answer[1], False)
