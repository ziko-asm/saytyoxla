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
    def __init__(self, data, status_code=200):
        self.data = data
        self.status_code = status_code

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


@pytest.mark.parametrize("raw", ["humble-wolf-1.upstash.io", "https://humble-wolf-1.upstash.io/", ' "https://humble-wolf-1.upstash.io" ',
                                 "'humble-wolf-1.upstash.io'\n"])
def test_pasted_url_forms_are_accepted(raw):
    assert ratelimit.clean_url(raw) == "https://humble-wolf-1.upstash.io"


def test_pasted_token_forms_are_accepted():
    for raw in ("t0ken", ' "t0ken" ', "Bearer t0ken", "'t0ken'\n"):
        assert ratelimit.clean_token(raw) == "t0ken"


def test_bare_host_from_the_console_reaches_redis(rules):
    redis = FakeUpstash()
    limiter = ratelimit.Limiter(ratelimit.RedisCounter("r.test", ' "t0ken" ', session=redis))
    assert limiter.allow("1.2.3.4", now=5) and redis.store       # counted in Redis, not in memory


class Refusing:
    def __init__(self, response):
        self.response = response

    def post(self, *args, **kwargs):
        return self.response


@pytest.mark.parametrize("response, cause", [
    (FakeResponse({"error": "WRONGPASS invalid or missing auth token"}, status_code=401), "HTTP 401: WRONGPASS"),
    (FakeResponse([{"error": "NOPERM this user has no permissions to run the 'incr' command"}]), "NOPERM"),
])
def test_redis_errors_are_logged_with_their_cause_and_fall_back(rules, caplog, response, cause):
    limiter = ratelimit.Limiter(ratelimit.RedisCounter("https://r.test", "secret-token", session=Refusing(response)))
    assert [limiter.allow("1.2.3.4", now=5) for _ in range(4)] == [True, True, True, False]
    assert cause in caplog.text and "secret-token" not in caplog.text


# --------------------------------------------------------------- shared report cache and /health
class FakeRedis:
    def __init__(self):
        self.data, self.fail = {}, False

    def command(self, *parts):
        if self.fail:
            raise ratelimit.RedisError("down")
        if parts[0] == "SET":
            self.data[parts[1]] = parts[2]
            assert parts[3:] == ("EX", "600")
            return "OK"
        return self.data.get(parts[1])

    def hit(self, key, limit, window, now=None):
        if self.fail:
            raise ratelimit.RedisError("down")
        return True


def test_report_cache_is_shared_between_instances(monkeypatch):
    from web import app as webapp
    redis = FakeRedis()
    monkeypatch.setattr(webapp, "limiter", ratelimit.Limiter(redis))
    webapp._cache.clear()
    webapp.cache_put("https://a.az/", {"score": 90, "summary": "Əla"})
    webapp._cache.clear()                               # another instance: its memory is empty
    assert webapp.cache_get("https://a.az/") == {"score": 90, "summary": "Əla"}
    assert all(k.startswith("saytyoxla:cache:") and "a.az" not in k for k in redis.data)
    webapp._cache.clear()
    redis.fail = True                                   # Redis down: no cache, but no error either
    assert webapp.cache_get("https://a.az/") is None
    webapp.cache_put("https://b.az/", {"score": 1})
    assert webapp.cache_get("https://b.az/") == {"score": 1}
    webapp._cache.clear()


def test_health_says_whether_limits_are_shared(monkeypatch):
    from fastapi.testclient import TestClient

    from web import app as webapp
    client = TestClient(webapp.app)
    monkeypatch.setattr(webapp, "limiter", ratelimit.Limiter())
    assert client.get("/health").json() == {"status": "ok", "limits": "per-instance"}
    redis = FakeRedis()
    limiter = ratelimit.Limiter(redis)
    monkeypatch.setattr(webapp, "limiter", limiter)
    assert client.get("/health").json()["limits"] == "shared"
    redis.fail = True
    assert limiter.allow("1.2.3.4")                     # falls back to memory
    assert client.get("/health").json()["limits"] == "shared-failing"
