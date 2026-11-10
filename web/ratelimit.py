"""
Rate limits for POST /api/scan that hold across server instances.

Vercel runs the app as many short-lived instances, each with its own memory, so a counter kept in memory
limits almost nothing (10 scans in 2 seconds all went through). The counters live in Redis instead,
through the Upstash REST API (plain HTTPS, no extra package). Set either pair of variables:

    UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN     (Upstash, free tier is enough)
    KV_REST_API_URL / KV_REST_API_TOKEN                   (Vercel KV, which is Upstash underneath)

Without them, or if Redis does not answer, the limits are counted in this instance's memory (local
development, and a degraded fallback that never blocks the service on a Redis outage).
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlsplit

import requests

log = logging.getLogger("saytyoxla.ratelimit")

# (name, limit, window in seconds); the per-IP rules are keyed by IP, "global" by the whole service
RULES = [
    ("ip-minute", int(os.getenv("SCAN_RATE_LIMIT", "6")), 60),
    ("ip-day", int(os.getenv("SCAN_DAILY_LIMIT", "60")), 86400),
    ("global-minute", int(os.getenv("SCAN_GLOBAL_LIMIT", "120")), 60),
]
# A deep analysis is several requests at once, so it has its own, larger allowance
DEEP_RULES = [
    ("deep-ip-minute", int(os.getenv("DEEP_RATE_LIMIT", "24")), 60),
    ("deep-ip-day", int(os.getenv("DEEP_DAILY_LIMIT", "150")), 86400),
    ("global-deep-minute", int(os.getenv("DEEP_GLOBAL_LIMIT", "240")), 60),
]
REDIS_TIMEOUT = 2


class MemoryCounter:
    """Sliding-window counter in this instance's memory."""

    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: int, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True

    def clear(self):
        with self._lock:
            self._hits.clear()


class RedisError(Exception):
    """Redis answered, but not with a count (wrong token, read-only token, unknown command ...)."""


def clean_url(raw: str) -> str:
    """Accept the forms people paste: with or without https://, in quotes, with spaces or a trailing slash.
    Upstash's console shows the endpoint as a bare host name (name-12345.upstash.io)."""
    url = raw.strip().strip("\"'").strip().rstrip("/")
    if url and "://" not in url:
        url = "https://" + url
    return url


def clean_token(raw: str) -> str:
    token = raw.strip().strip("\"'").strip()
    return token.removeprefix("Bearer ").strip()


class RedisCounter:
    """Fixed-window counter in Redis: INCR the window's key, give it an expiry the first time."""

    def __init__(self, url: str, token: str, session: requests.Session | None = None):
        self.url = clean_url(url)
        self.headers = {"Authorization": f"Bearer {clean_token(token)}"}
        self.session = session or requests.Session()

    def hit(self, key: str, limit: int, window: int, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        k = f"saytyoxla:rl:{key}:{int(now // window)}"
        r = self.session.post(self.url + "/pipeline", headers=self.headers, timeout=REDIS_TIMEOUT,
                              json=[["INCR", k], ["EXPIRE", k, str(window + 5), "NX"]])
        if r.status_code != 200:
            raise RedisError(f"HTTP {r.status_code}: {_error_text(r)}")
        first = r.json()[0]
        if "result" not in first:
            raise RedisError(str(first.get("error", first))[:200])
        return int(first["result"]) <= limit

    def command(self, *parts):
        """One Redis command; its result. Used for the report cache that every instance shares (web/app.py)."""
        r = self.session.post(self.url, headers=self.headers, timeout=REDIS_TIMEOUT, json=list(parts))
        if r.status_code != 200:
            raise RedisError(f"HTTP {r.status_code}: {_error_text(r)}")
        return r.json().get("result")


def _error_text(r) -> str:
    try:
        return str(r.json().get("error", ""))[:200]
    except (ValueError, AttributeError):
        return ""


class Limiter:
    def __init__(self, redis: RedisCounter | None = None):
        self.redis = redis
        self.memory = MemoryCounter()
        self.failed_at = 0.0        # when Redis last refused a count: /health shows it, so a broken setup is visible

    def state(self, now: float | None = None) -> str:
        """"shared": counted in Redis, so the limits hold across instances. "per-instance": no Redis configured.
        "shared-failing": Redis is configured but refused within the last 10 minutes, so this instance fell back."""
        if not self.redis:
            return "per-instance"
        return "shared-failing" if (time.time() if now is None else now) - self.failed_at < 600 else "shared"

    @classmethod
    def from_env(cls) -> Limiter:
        url = os.getenv("UPSTASH_REDIS_REST_URL") or os.getenv("KV_REST_API_URL")
        token = os.getenv("UPSTASH_REDIS_REST_TOKEN") or os.getenv("KV_REST_API_TOKEN")
        if url and token:
            redis = RedisCounter(url, token)
            # the host only, never the token: enough to see in the logs which database is used
            log.warning("Scan limits are counted in Redis at %s", urlsplit(redis.url).hostname or redis.url)
            return cls(redis)
        if os.getenv("VERCEL"):
            log.warning("No Redis configured: scan limits are per instance only. See web/ratelimit.py.")
        return cls()

    def allow(self, ip: str, now: float | None = None, rules: list | None = None) -> bool:
        """True if this scan is within every rule. Every rule is counted, so a refused request still uses
        up its per-IP allowance (a client that keeps hammering stays blocked)."""
        ok = True
        for name, limit, window in RULES if rules is None else rules:
            key = name if name.startswith("global") else f"{name}:{ip}"
            ok = self._hit(key, limit, window, now) and ok
        return ok

    def _hit(self, key, limit, window, now):
        if self.redis:
            try:
                return self.redis.hit(key, limit, window, now)
            except (RedisError, requests.RequestException, ValueError, KeyError, IndexError, TypeError) as e:
                # the message explains the cause (e.g. "HTTP 401: WRONGPASS" for a wrong token); it never
                # contains the token, which is only sent in a header
                self.failed_at = time.time()
                log.warning("Redis rate limit unavailable (%s: %s); counting in memory",
                            type(e).__name__, str(e)[:200])
        return self.memory.hit(key, limit, window, now)


def client_ip(headers, peer: str | None, on_vercel: bool | None = None) -> str:
    """The visitor's address, from a header the platform sets and the visitor cannot forge.

    On Vercel, x-vercel-forwarded-for / x-real-ip are written by Vercel's edge (it overwrites what the
    visitor sends). Elsewhere behind one proxy (Render, nginx) the proxy appends the real address to
    X-Forwarded-For, so the LAST entry is trusted; the first entry is whatever the visitor typed.
    """
    if on_vercel is None:
        on_vercel = bool(os.getenv("VERCEL"))
    if on_vercel:
        for name in ("x-vercel-forwarded-for", "x-real-ip"):
            v = (headers.get(name) or "").split(",")[0].strip()
            if v:
                return v
    fwd = [p.strip() for p in (headers.get("x-forwarded-for") or "").split(",") if p.strip()]
    if fwd:
        return fwd[-1]
    return peer or "unknown"
