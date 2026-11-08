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
    assert 'rel="alternate"' not in r.text                       # Azerbaijani only, no hreflang pairs
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
