"""The "Sayt haqqında ümumi məlumat" page: served, one searchable text, numbers match the scanner."""

import re
from pathlib import Path

from fastapi.testclient import TestClient

from scanner import report
from web import app as webapp
from web import glossary

client = TestClient(webapp.app)


def test_page_is_served_with_search_and_script():
    r = client.get("/lugat/")
    assert r.status_code == 200
    assert 'id="gl-q"' in r.text and "/static/glossary.js" in r.text
    assert '<link rel="canonical" href="https://saytyoxla.vercel.app/lugat/">' in r.text
    assert '<link rel="alternate" hreflang="en" href="https://saytyoxla.vercel.app/en/glossary/">' in r.text
    assert "Amma sayt qurmaq kifayət deyil" in r.text
    assert client.get("/lugat", follow_redirects=False).status_code == 301
    assert client.get("/static/glossary.js").status_code == 200


def test_every_term_has_unique_id_and_enough_text():
    ids = re.findall(r'<section class="term" id="([^"]+)"', glossary.body())
    assert len(ids) == len(set(ids)) >= 50
    for _, terms in glossary.SECTIONS:
        for id_, title, _keys, body in terms:
            assert len(body) > 60, id_


def test_sitemap_lists_page():
    assert "https://saytyoxla.vercel.app/lugat/</loc>" in client.get("/sitemap.xml").text


def test_scoring_numbers_match_the_code():
    """The page quotes the core protections and the cap values; fail here if the scanner changes them."""
    assert report.CORE_PROTECTIONS == ("http_redirect", "hsts", "framing", "nosniff", "csp")
    src = Path(report.__file__).read_text(encoding="utf-8")
    for cap in ("39", "59", "74", "89"):
        assert cap in src and cap in glossary.body()


LANGS = {"az": "/lugat/", "en": "/en/glossary/", "ru": "/ru/slovar/"}


def test_every_language_is_served_in_its_own_words():
    marks = {"az": "Amma sayt qurmaq kifayət deyil", "en": "But building a website is not enough", "ru": "Но сделать сайт недостаточно"}
    for lang, path in LANGS.items():
        r = client.get(path)
        assert r.status_code == 200 and f'<html lang="{lang}">' in r.text and marks[lang] in r.text, lang
        assert f'<link rel="canonical" href="https://saytyoxla.vercel.app{path}">' in r.text
        assert r.text.count('rel="alternate"') == 4 and 'property="og:image"' in r.text
        assert 'data-found="' in r.text and "{n}" in r.text and "{title}" in r.text
        assert client.get(path.rstrip("/"), follow_redirects=False).status_code == 301
        assert f"https://saytyoxla.vercel.app{path}</loc>" in client.get("/sitemap.xml").text
    for lang in ("en", "ru"):                                   # no Azerbaijani sentence left behind
        text = re.sub(r"<[^>]+>", " ", glossary.body(lang))
        assert not re.search(r"[əğıƏĞİ]", text.replace("Ziya", "")), (lang, re.findall(r"\S*[əğıƏĞİ]\S*", text)[:5])


def test_the_three_texts_have_the_same_terms_in_the_same_order():
    """A link with #dmarc must work in every language, and a term added to one must be added to all."""
    ids = {lang: [t[0] for _, terms in glossary.UI[lang]["sections"] for t in terms] for lang in LANGS}
    assert ids["az"] == ids["en"] == ids["ru"]
    assert len({len(glossary.UI[lang]["sections"]) for lang in LANGS}) == 1
    for lang in LANGS:
        assert 'id="sayt-nedir"' in glossary.UI[lang]["intro"]
        for _, terms in glossary.UI[lang]["sections"]:
            for id_, title, keys, body in terms:
                assert title and keys and len(body) > 60, (lang, id_)
                assert body.count("<p>") == body.count("</p>") and body.count("<b>") == body.count("</b>"), (lang, id_)


def test_points_quoted_in_the_text_match_the_scanner_in_every_language():
    from scanner import checks
    from tests.test_scanner import ctx
    findings = checks.run_checks(ctx())
    scored, total = sum(1 for f in findings if f.weight), sum(f.weight for f in findings)
    weight = {f.id: f.weight for f in findings}
    where = {"https": "https", "hsts": "hsts", "csp": "csp", "spf": "spf", "viewport": "viewport", "noindex": "indexing",
             "nosniff": "nosniff", "x-frame-options": "framing", "server-versiya": "disclosure", "qarisiq-mezmun": "mixed",
             "cookie-qoruma": "cookies", "http-https-yonlendirme": "http_redirect", "referrer-policy": "referrer", "dmarc": "dmarc"}
    for lang in LANGS:
        terms = {t[0]: t[3] for _, ts in glossary.UI[lang]["sections"] for t in ts}
        how = terms["bal-hesablanma"]
        for n in (len(findings), scored, total, 39, 59, 74, 89):
            assert re.search(rf"\b{n}\b", how), (lang, n)
        for term, check in where.items():
            assert re.search(rf"\b{weight[check]}\b", terms[term]), (lang, term, weight[check])
        speed = terms["cavab-vaxti"]
        for n in (1500, 4000, 300, 1000, 500):
            assert str(n) in speed, (lang, n)


def test_survey_numbers_in_the_text_come_from_the_published_statistics():
    from web import survey
    everyone = survey.stats()["all"]
    for lang, path in LANGS.items():
        text = client.get(path).text
        assert "[[survey" not in text, lang
        assert str(everyone["n"]) in text and f'{survey.has_csp(everyone)}%' in text and f'{everyone["pass"]["dmarc"]}%' in text, lang
