"""Scan limits (web/ratelimit.py): shared across instances through Redis, and keyed by an address the
visitor cannot forge."""

from __future__ import annotations

import pytest
import requests

from web import ratelimit


class FakeUpstash:
    """Stands in for the Upstash REST API: /pipeline with INCR and EXPIRE, counts kept in a dict."""

    def __init__(self):
        self.store: dict[str, int] = {}
        self.down = False

    def post(self, url, headers=None, json=None, timeout=None):
        if self.down:
            raise requests.ConnectionError("redis down")
        assert url.endswith("/pipeline") and headers["Authorization"] == "Bearer t0ken"
        results = []
        for cmd in json:
            if cmd[0] == "INCR":
                self.store[cmd[1]] = self.store.get(cmd[1], 0) + 1
                results.append({"result": self.store[cmd[1]]})
            else:
                results.append({"result": 1})
        return FakeResponse(results)


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


@pytest.fixture
def rules(monkeypatch):
    monkeypatch.setattr(ratelimit, "RULES", [("ip-minute", 3, 60), ("ip-day", 5, 86400), ("global-minute", 8, 60)])


def two_instances(redis):
    """Two server instances: separate memory, the same Redis."""
    return (ratelimit.Limiter(ratelimit.RedisCounter("https://r.test", "t0ken", session=redis)),
            ratelimit.Limiter(ratelimit.RedisCounter("https://r.test", "t0ken", session=redis)))


def test_limit_holds_across_instances(rules):
    a, b = two_instances(FakeUpstash())
    results = [(a if i % 2 else b).allow("1.2.3.4", now=1000) for i in range(5)]
    assert results == [True, True, True, False, False]       # 3 per minute, whichever instance answers


def test_daily_and_global_limits(rules):
    a, b = two_instances(FakeUpstash())
    # 3 per minute, then the next minute 2 more, then the day's 5 are used up
    assert [a.allow("1.1.1.1", now=60 * 10 + i) for i in range(3)] == [True] * 3
    assert [b.allow("1.1.1.1", now=60 * 11 + i) for i in range(3)] == [True, True, False]
    assert not a.allow("1.1.1.1", now=60 * 12)
    # many addresses together hit the service-wide limit (8 per minute; 1.1.1.1 already used 0 in this minute)
    ok = [a.allow(f"10.0.0.{i}", now=60 * 20) for i in range(10)]
    assert ok.count(True) == 8


def test_redis_outage_falls_back_to_memory(rules):
    redis = FakeUpstash()
    redis.down = True
    limiter = ratelimit.Limiter(ratelimit.RedisCounter("https://r.test", "t0ken", session=redis))
    assert [limiter.allow("1.2.3.4", now=5) for _ in range(4)] == [True, True, True, False]


def test_memory_window_slides():
    m = ratelimit.MemoryCounter()
    assert all(m.hit("k", 2, 60, now=t) for t in (0, 1))
    assert not m.hit("k", 2, 60, now=2)
    assert m.hit("k", 2, 60, now=100)


def test_from_env_uses_redis_when_configured(monkeypatch):
    monkeypatch.setenv("UPSTASH_REDIS_REST_URL", "https://r.test/")
    monkeypatch.setenv("UPSTASH_REDIS_REST_TOKEN", "t")
    assert ratelimit.Limiter.from_env().redis.url == "https://r.test"
    monkeypatch.delenv("UPSTASH_REDIS_REST_URL")
    monkeypatch.delenv("UPSTASH_REDIS_REST_TOKEN")
    monkeypatch.setenv("KV_REST_API_URL", "https://kv.test")
    monkeypatch.setenv("KV_REST_API_TOKEN", "t")
    assert ratelimit.Limiter.from_env().redis.url == "https://kv.test"


def test_client_ip_on_vercel_ignores_forged_forwarded_for():
    h = {"x-forwarded-for": "6.6.6.6", "x-vercel-forwarded-for": "203.0.113.7"}
    assert ratelimit.client_ip(h, "10.0.0.1", on_vercel=True) == "203.0.113.7"


def test_client_ip_behind_one_proxy_uses_the_address_the_proxy_added():
    h = {"x-forwarded-for": "6.6.6.6, 203.0.113.7"}             # visitor typed 6.6.6.6, the proxy appended the rest
    assert ratelimit.client_ip(h, "10.0.0.1", on_vercel=False) == "203.0.113.7"
    assert ratelimit.client_ip({"x-real-ip": "6.6.6.6"}, "198.51.100.2", on_vercel=False) == "198.51.100.2"
    assert ratelimit.client_ip({}, None, on_vercel=False) == "unknown"
