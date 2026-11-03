"""API tests with the scanner replaced by a stub (no network)."""

import pytest
from fastapi.testclient import TestClient

from scanner import UnsafeTarget
from web import app as webapp
from web import ratelimit

client = TestClient(webapp.app)


class FakeReport:
    def to_dict(self):
        return {"url": "https://example.az/", "final_url": "https://example.az/", "score": 88, "grade": "B",
                "summary": "ok", "findings": [], "scanned_at": "2026-10-18T10:00:00+00:00",
                "counts": {"fail": 0, "warn": 1, "ok": 5}}


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    monkeypatch.setattr(webapp, "limiter", ratelimit.Limiter())     # memory counters, no Redis
    webapp._cache.clear()
    calls = []

    def fake_scan(url):
        calls.append(url)
        return FakeReport()

    monkeypatch.setattr(webapp.scanner, "scan", fake_scan)
    return calls


def test_home_page_has_how_to_section():
    r = client.get("/")
    assert r.status_code == 200 and "Saytı necə işlətməli?" in r.text
    assert r.headers["x-frame-options"] == "DENY" and "content-security-policy" in r.headers


def test_scan_returns_report_and_caches(reset):
    a = client.post("/api/scan", json={"url": "example.az"})
    b = client.post("/api/scan", json={"url": "https://example.az"})
    assert a.status_code == 200 and a.json()["grade"] == "B"
    assert a.json()["cached"] is False and b.json()["cached"] is True
    assert {**b.json(), "cached": False} == a.json() and len(reset) == 1


def test_fresh_skips_the_cache_and_replaces_it(reset):
    client.post("/api/scan", json={"url": "example.az"})
    again = client.post("/api/scan", json={"url": "example.az", "fresh": True})
    assert again.status_code == 200 and again.json()["cached"] is False
    assert len(reset) == 2                                    # scanned again, not served from the cache
    after = client.post("/api/scan", json={"url": "example.az"})
    assert after.json()["cached"] is True and len(reset) == 2  # the fresh result is what is cached now


def test_fresh_is_still_rate_limited(monkeypatch):
    monkeypatch.setattr(ratelimit, "RULES", [("ip-minute", 2, 60)])
    codes = [client.post("/api/scan", json={"url": "example.az", "fresh": True}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_fresh_works_in_every_language(reset):
    for lang in ("az", "en", "ru"):
        r = client.post("/api/scan", json={"url": "example.az", "lang": lang, "fresh": True})
        assert r.status_code == 200 and r.json()["cached"] is False


def test_built_front_end_has_the_rescan_button():
    import re
    page = client.get("/")
    js = client.get(re.search(r'src="(/react/assets/[^"]+\.js)"', page.text).group(1)).text
    assert "fresh" in js and "Yenidən yoxla (təzə nəticə)" in js  # react-ui was rebuilt after the change


def test_bad_url_is_400_with_message():
    r = client.post("/api/scan", json={"url": "http://127.0.0.1"})
    assert r.status_code == 400 and r.json()["detail"]


def test_scanner_error_is_400(monkeypatch):
    def boom(url):
        raise UnsafeTarget("Bu ünvan tapılmadı.")
    monkeypatch.setattr(webapp.scanner, "scan", boom)
    r = client.post("/api/scan", json={"url": "nosuch.az"})
    assert r.status_code == 400 and "tapılmadı" in r.json()["detail"]


def test_rate_limit(monkeypatch):
    monkeypatch.setattr(ratelimit, "RULES", [("ip-minute", 2, 60)])
    codes = [client.post("/api/scan", json={"url": f"site{i}.az"}).status_code for i in range(3)]
    assert codes == [200, 200, 429]


def test_scan_responses_are_never_cached_by_the_edge():
    r = client.post("/api/scan", json={"url": "example.az"})
    assert r.headers["cache-control"] == "no-store"


def test_hashed_assets_are_cached_for_a_year():
    asset = next((webapp.REACT / "assets").glob("*.js")).name
    r = client.get(f"/react/assets/{asset}")
    assert r.status_code == 200 and "immutable" in r.headers["cache-control"]
    assert "s-maxage=300" in client.get("/").headers["cache-control"]


def test_report_cache_is_bounded(monkeypatch):
    monkeypatch.setattr(webapp, "CACHE_MAX", 3)
    for i in range(5):
        webapp.cache_put(f"https://s{i}.az/", {"n": i})
    assert list(webapp._cache) == ["https://s2.az/", "https://s3.az/", "https://s4.az/"]


def test_robots_and_sitemap():
    r = client.get("/robots.txt")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert "Sitemap: https://saytyoxla.vercel.app/sitemap.xml" in r.text and "Disallow: /api/" in r.text
    s = client.get("/sitemap.xml")
    assert s.status_code == 200 and "xml" in s.headers["content-type"]
    assert "<loc>https://saytyoxla.vercel.app/</loc>" in s.text


def test_llms_txt_is_utf8():
    r = client.get("/llms.txt")
    assert r.status_code == 200 and "charset=utf-8" in r.headers["content-type"]
    assert "SaytYoxla" in r.text and "təhlükəsizliyini" in r.text


def test_google_verification_only_for_listed_file(monkeypatch):
    monkeypatch.setattr(webapp.seo, "GOOGLE_VERIFY_FILES", {"google0123456789abcdef.html"})
    ok = client.get("/google0123456789abcdef.html")
    assert ok.status_code == 200 and ok.text == "google-site-verification: google0123456789abcdef.html"
    assert client.get("/googleffffffffffffffff.html").status_code == 404
    assert client.get("/whatever.html").status_code == 404


def test_health_still_works_after_catch_all():
    assert client.get("/health").json() == {"status": "ok"}


def test_home_page_has_seo_tags():
    t = client.get("/").text
    assert '<link rel="canonical" href="https://saytyoxla.vercel.app/">' in t
    assert '"@type": "FAQPage"' in t and 'og:image' in t


def test_cors_allows_ayfar_only():
    pre = {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"}
    ok = client.options("/api/scan", headers={"Origin": "https://ayfar.vercel.app", **pre})
    assert ok.status_code == 200 and ok.headers["access-control-allow-origin"] == "https://ayfar.vercel.app"
    bad = client.options("/api/scan", headers={"Origin": "https://evil.example", **pre})
    assert "access-control-allow-origin" not in bad.headers


def test_classic_page_and_beta_redirect():
    assert '<form id="form"' in client.get("/classic").text
    r = client.get("/beta", follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"] == "/"


def test_react_home_page_and_assets():
    page = client.get("/")
    assert page.status_code == 200 and '<div id="root">' in page.text
    assert "application/ld+json" in page.text and "Tez-tez verilən suallar" in page.text  # SEO content stays in the HTML
    assert "<h1>" in page.text and "Saytı necə işlətməli?" in page.text  # heading and guide are in the raw HTML too
    import re
    js = re.search(r'src="(/react/assets/[^"]+\.js)"', page.text).group(1)
    css = re.search(r'href="(/react/assets/[^"]+\.css)"', page.text).group(1)
    assert client.get(js).status_code == 200 and client.get(css).status_code == 200


def test_language_pages():
    for path, lang, word in (("/en/", "en", "How to use it"), ("/ru/", "ru", "Как пользоваться?")):
        r = client.get(path)
        assert r.status_code == 200 and f'<html lang="{lang}">' in r.text and word in r.text
        assert 'hreflang="az"' in r.text and f'saytyoxla.vercel.app{path}"' in r.text
    r = client.get("/en", follow_redirects=False)
    assert r.status_code == 301 and r.headers["location"].endswith("/en/")
    sm = client.get("/sitemap.xml").text
    assert "/en/</loc>" in sm and "/ru/</loc>" in sm and 'hreflang="ru"' in sm


def test_survey_pages(monkeypatch, tmp_path):
    import shutil
    from pathlib import Path

    from web import survey
    data = tmp_path / "stats.json"
    shutil.copy(Path(__file__).parent / "survey_sample.json", data)
    monkeypatch.setattr(survey, "DATA", data)
    survey.stats.cache_clear()
    for path, lang in (("/hesabat/", "az"), ("/en/report/", "en"), ("/ru/otchet/", "ru")):
        r = client.get(path)
        assert r.status_code == 200 and f'<html lang="{lang}">' in r.text and "<table>" in r.text
        assert ".az" not in r.text.replace("ayfar.vercel.app", "")   # no site is named
    assert client.get("/hesabat", follow_redirects=False).headers["location"].endswith("/hesabat/")
    assert "/en/report/</loc>" in client.get("/sitemap.xml").text


def test_indexnow_key_file():
    from web import seo
    assert client.get(f"/{seo.INDEXNOW_KEY}.txt").text == seo.INDEXNOW_KEY
    assert client.get("/wrong.txt").status_code == 404


def test_head_is_answered_like_get():
    for path in ("/", "/en/", "/classic", "/robots.txt"):
        r = client.head(path)
        assert r.status_code == 200 and r.content == b"", path
    assert client.head("/no-such-page").status_code == 404
