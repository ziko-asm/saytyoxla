"""Every text the scanner can show must have an English and a Russian version."""

import re

import pytest
from fastapi.testclient import TestClient

import scanner
from scanner import checks, i18n
from scanner.report import build
from tests.test_scanner import BAD_HTML, ctx

AZ_LETTERS = re.compile(r"[əğışçöüƏĞİŞÇÖÜ]")

# Contexts that between them reach every branch of every check.
VARIANTS = [
    {},
    {"final_url": "http://example.az/", "cert": None, "http_to_https": False, "headers": {},
     "html": BAD_HTML, "html_bytes": 2_000_000, "elapsed_ms": 6000, "txt_records": {"spf": [], "dmarc": []}},
    {"http_to_https": None, "cert": {"error": "certificate has expired"}, "elapsed_ms": 2000,
     "html_bytes": 500_000, "txt_records": {"spf": None, "dmarc": None},
     "headers": {"server": "Apache/2.4.1", "x-powered-by": "PHP/7.4"}},
    {"cert": {"days_left": 3, "expires": "2026-11-04", "error": None}, "html": BAD_HTML,
     "txt_records": {"spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=none"]}},
    {"cert": {"days_left": 15, "expires": "2026-11-16", "error": None},
     "html": "<title>Hi</title><meta name='description' content='short'>"},
    {"html": "", "html_bytes": 0},
    {"final_url": "https://shop.vercel.app/", "input_url": "https://shop.vercel.app/", "host": "shop.vercel.app"},
    {"cert": {"error": "self-signed certificate"}},
    {"cert": {"error": "Hostname mismatch, certificate is not valid for 'x'."}},
    {"cert": {"error": "certificate revoked"}},
    {"cert": {"error": "unable to get local issuer certificate"}},
    {"cert": {"error": "SSLError"}},
    {"cert": {"days_left": 3, "expires": "2026-11-04", "error": None}, "headers": {}},
    {"headers": {"x-frame-options": "DENY", "strict-transport-security": "max-age=1"}, "http_to_https": False},
    {"headers": {"x-frame-options": "DENY", "x-content-type-options": "nosniff", "content-security-policy": "x"}},
    {"headers": {"strict-transport-security": "max-age=60", "x-content-type-options": "x", "referrer-policy": "unsafe-url",
                 "content-security-policy": "script-src 'self' 'unsafe-inline'"}},
    {"headers": {"content-security-policy": "script-src 'self' 'unsafe-eval'"}},
    {"headers": {"content-security-policy": "script-src *"}},
    {"headers": {"content-security-policy": "frame-ancestors 'none'"}},
    {"headers": {"content-security-policy-report-only": "default-src 'self'"}},
    {"cookies": ["a=1"]},
    {"cookies": ["a=1; Secure; SameSite=Lax"]},
    {"cert": {"unknown": True}, "dkim": None, "robots": None, "sitemap": None},
    {"dkim": [], "sitemap": False, "robots": "User-agent: *\nDisallow: /\n",
     "html": "<html><body><h1>A</h1><h1>B</h1></body></html>"},
    {"html": "<html><head><meta name='robots' content='noindex'></head><body></body></html>"},
    {"html": "<html><head><title>Bir tətbiq səhifəsi</title></head><body><script src='/a.js'></script></body></html>"},
    {"txt_records": {"spf": [], "dmarc": ["v=DMARC1; p=reject"], "dmarc_parent": "example.az"}},
    {"txt_records": {"spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=none"], "dmarc_parent": "example.az"}},
    {"html_bytes": 60_000, "cert": {"days_left": 80, "expires": "2027-01-01", "error": None, "alpn": "http/1.1"}},
    {"html_bytes": 60_000, "headers": {"content-encoding": "gzip"},
     "html": "<html><body><p>" + "söz " * 100 + "</p><img src='a.jpg'></body></html>"},
]

ERRORS = [
    "Saytın ünvanını yazın, məsələn: example.az", "Yalnız http və https ünvanları yoxlanılır.",
    "Ünvanda istifadəçi adı və ya şifrə olmamalıdır.", "Ünvan düzgün görünmür. Nümunə: example.az",
    "Yalnız standart portlar (80, 443) yoxlanılır.", "Bu ünvan tapılmadı. Yazılışı yoxlayın.",
    "Bu ünvan daxili şəbəkəyə aiddir və yoxlanıla bilməz.",
    "Çox sayda yoxlama etdiniz. Bir dəqiqə gözləyib yenidən cəhd edin.",
    "Ünvan çox uzundur. Yalnız domeni yazın, məsələn: example.az",
    "Sayt çox sayda yönləndirmə edir.",
] + [scanner.status_message(c) for c in (401, 403, 404, 429, 500, 503, 418)] \
  + [scanner.error_message(e) for e in ("SSLError", "ConnectTimeout", "ReadTimeout", "ConnectionError", "TooManyRedirects")]


def all_texts():
    out = set()
    for v in VARIANTS:
        c = ctx(**v)
        r = build(c, checks.run_checks(c))
        out.update({r.summary, r.score_note})
        for f in r.findings:
            out.update({f.category, f.title, f.detail, f.fix})
    return out - {""}


def test_variants_reach_every_status():
    seen = set()
    for v in VARIANTS:
        c = ctx(**v)
        seen.update((f.id, f.status) for f in checks.run_checks(c))
    for fid in ("https", "cert", "http_redirect", "hsts", "dmarc", "speed", "size", "title", "description",
                "compression", "http2", "img_alt", "schema"):
        assert len({s for i, s in seen if i == fid}) >= 2, fid


@pytest.mark.parametrize("lang", ["en", "ru"])
def test_every_finding_text_is_translated(lang):
    missing = [s for s in all_texts() if not i18n.known(s)]
    assert not missing, missing
    for s in all_texts():
        t = i18n.text(s, lang)
        assert t != s
        # page titles are quoted as-is, so only check text outside quotes
        assert not AZ_LETTERS.search(re.sub(r"[\"«].*[\"»]", "", t)), t


@pytest.mark.parametrize("lang", ["en", "ru"])
@pytest.mark.parametrize("msg", ERRORS)
def test_every_error_is_translated(msg, lang):
    t = i18n.text(msg, lang)
    assert i18n.known(msg) and t != msg and not AZ_LETTERS.search(t), t


def test_milliseconds_are_translated():
    assert i18n.text("Server 120 millisaniyəyə cavab verdi.", "en") == "The server responded in 120 milliseconds."
    assert i18n.text("Server 120 millisaniyəyə cavab verdi.", "ru") == "Сервер ответил за 120 мс."


def test_dynamic_values_survive():
    assert i18n.text("Server 2.3 saniyəyə cavab verdi.", "en") == "The server responded in 2.3 seconds."
    assert "14" in i18n.text("Sertifikatın vaxtı 14 gün sonra bitir.", "ru")
    assert i18n.text("2 ciddi problem və 3 təkmilləşdirmə tövsiyəsi tapıldı.", "ru") == \
        "Найдено серьёзных проблем: 2, рекомендаций по улучшению: 3."


def test_lang_of_falls_back_to_az():
    assert [i18n.lang_of(x) for x in ("en", "RU", "ru-RU", "de", "", None)] == ["en", "ru", "ru", "az", "az", "az"]


def test_api_translates_report_and_keeps_cache_in_az(monkeypatch):
    from web import app as webapp
    from web import ratelimit
    webapp._cache.clear()
    monkeypatch.setattr(webapp, "limiter", ratelimit.Limiter())
    c = ctx(**VARIANTS[1])
    monkeypatch.setattr(webapp.scanner, "scan", lambda url: build(c, checks.run_checks(c)))
    client = TestClient(webapp.app)
    en = client.post("/api/scan", json={"url": "example.az", "lang": "en"}).json()
    ru = client.post("/api/scan", json={"url": "example.az", "lang": "ru"}).json()
    az = client.post("/api/scan", json={"url": "example.az"}).json()
    assert en["lang"] == "en" and en["findings"][0]["category"] in ("Security", "E-mail", "Speed", "Mobile and Google")
    assert "Найдено" in ru["summary"] and "tapıldı" in az["summary"]
    assert en["score"] == ru["score"] == az["score"]


def test_api_translates_errors():
    from web import app as webapp
    client = TestClient(webapp.app)
    r = client.post("/api/scan", json={"url": "ftp://example.az", "lang": "en"})
    assert r.status_code == 400 and r.json()["detail"] == "Only http and https addresses can be checked."
