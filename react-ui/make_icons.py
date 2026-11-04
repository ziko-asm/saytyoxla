"""
Draw the site icons into web/static from the same shape as the SVG favicon. Standard library only.

    python3 make_icons.py      # run again only if the logo changes
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).parent.parent / "web" / "static"
BACK, CHECK = (0x0f, 0x2a, 0x4a), (0x34, 0xd3, 0x99)
RADIUS, STROKE = 14, 3.5                                    # in the logo's 64 x 64 units (half the stroke width)
POINTS = [(18, 33), (27, 42), (46, 22)]


def _segment_distance(x, y, a, b):
    dx, dy = b[0] - a[0], b[1] - a[1]
    t = max(0.0, min(1.0, ((x - a[0]) * dx + (y - a[1]) * dy) / (dx * dx + dy * dy)))
    return math.hypot(x - a[0] - t * dx, y - a[1] - t * dy)


def _box_distance(x, y):
    qx, qy = abs(x - 32) - (32 - RADIUS), abs(y - 32) - (32 - RADIUS)
    return math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - RADIUS


def _coverage(distance, pixel):
    return max(0.0, min(1.0, 0.5 - distance / pixel))


def draw(size: int, opaque: bool = False) -> bytes:
    """RGBA rows for PNG. `opaque` fills the corners: iOS rounds the icon itself and shows transparency as black."""
    pixel = 64 / size
    rows = bytearray()
    for j in range(size):
        rows.append(0)
        y = (j + 0.5) * pixel
        for i in range(size):
            x = (i + 0.5) * pixel
            alpha = 1.0 if opaque else _coverage(_box_distance(x, y), pixel)
            check = _coverage(min(_segment_distance(x, y, POINTS[0], POINTS[1]),
                                  _segment_distance(x, y, POINTS[1], POINTS[2])) - STROKE, pixel)
            rows += bytes(round(b + (c - b) * check) for b, c in zip(BACK, CHECK))
            rows.append(round(255 * alpha))
    return bytes(rows)


def png(size: int, opaque: bool = False) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(draw(size, opaque), 9)) + chunk(b"IEND", b""))


def ico(sizes: list[int]) -> bytes:
    images = [png(s) for s in sizes]
    offset = 6 + 16 * len(sizes)
    out = struct.pack("<HHH", 0, 1, len(sizes))
    for size, image in zip(sizes, images):
        out += struct.pack("<BBBBHHII", size, size, 0, 0, 1, 32, len(image), offset)
        offset += len(image)
    return out + b"".join(images)


if __name__ == "__main__":
    (OUT / "favicon.ico").write_bytes(ico([16, 32, 48]))
    (OUT / "apple-touch-icon.png").write_bytes(png(180, opaque=True))
    (OUT / "icon-192.png").write_bytes(png(192))
    (OUT / "icon-512.png").write_bytes(png(512))
    print("wrote icons to", OUT)
