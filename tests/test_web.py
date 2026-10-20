"""API tests with the scanner replaced by a stub (no network)."""

import pytest
from fastapi.testclient import TestClient

from scanner import UnsafeTarget
from web import app as webapp

client = TestClient(webapp.app)


class FakeReport:
    def to_dict(self):
        return {"url": "https://example.az/", "final_url": "https://example.az/", "score": 88, "grade": "B",
                "summary": "ok", "findings": [], "scanned_at": "2026-10-18T10:00:00+00:00",
                "counts": {"fail": 0, "warn": 1, "ok": 5}}


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    webapp._hits.clear()
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
    assert b.json() == a.json() and len(reset) == 1


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
    monkeypatch.setattr(webapp, "RATE_LIMIT", 2)
    codes = [client.post("/api/scan", json={"url": f"site{i}.az"}).status_code for i in range(3)]
    assert codes == [200, 200, 429]


def test_allow_window_expires():
    webapp._hits.clear()
    assert all(webapp.allow("1.2.3.4", now=t) for t in range(webapp.RATE_LIMIT))
    assert not webapp.allow("1.2.3.4", now=webapp.RATE_LIMIT)
    assert webapp.allow("1.2.3.4", now=1000)


def test_robots_and_sitemap():
    r = client.get("/robots.txt")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert "Sitemap: https://saytyoxla.onrender.com/sitemap.xml" in r.text and "Disallow: /api/" in r.text
    s = client.get("/sitemap.xml")
    assert s.status_code == 200 and "xml" in s.headers["content-type"]
    assert "<loc>https://saytyoxla.onrender.com/</loc>" in s.text


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
    assert '<link rel="canonical" href="https://saytyoxla.onrender.com/">' in t
    assert '"@type": "FAQPage"' in t and 'og:image' in t
