"""The compare page: three languages, words for the script, routes and links."""

import json
import re
from pathlib import Path

import pytest

from web import compare, pages, seo

AZ_LETTERS = re.compile(r"[əğışçöüƏĞİŞÇÖÜ]")
STATIC = Path(compare.__file__).parent / "static"


def words_of(html: str) -> dict:
    return json.loads(re.search(r'<script type="application/json" id="cmp-data">(.*?)</script>', html, re.DOTALL).group(1))


@pytest.mark.parametrize("lang", ["az", "en", "ru"])
def test_page_in_every_language(lang):
    html = compare.page(lang)
    path = pages.COMPARE_PATHS[lang]
    assert f'<html lang="{lang}">' in html and "<h1>" in html and 'id="cmp-form"' in html
    assert f'<link rel="canonical" href="{seo.SITE_URL}{path}">' in html
    for other in pages.COMPARE_PATHS.values():
        assert f'href="{other}"' in html                        # the language switch stays on this page
    assert 'property="og:image"' in html and f'property="og:url" content="{seo.SITE_URL}{path}"' in html
    assert html.count('name="u"') == 2 and '/static/compare.js' in html
    data = words_of(html)
    assert data["lang"] == lang and data["max"] == compare.MAX_SITES == len(data["labels"]) == len(data["placeholders"])


def test_every_language_has_the_same_words_and_none_is_left_in_azerbaijani():
    keys = set(compare.WORDS["az"])
    for lang in ("en", "ru"):
        assert set(compare.WORDS[lang]) == keys and set(compare.PAGE[lang]) == set(compare.PAGE["az"])
        text = json.dumps([compare.WORDS[lang], compare.PAGE[lang], compare.META[lang]], ensure_ascii=False)
        assert not AZ_LETTERS.search(text), lang
    for lang, words in compare.WORDS.items():
        for key in ("leader", "tie", "passed", "show_all"):     # the script fills these in
            assert sorted(re.findall(r"\{(\w+)\}", words[key])) == sorted(re.findall(r"\{(\w+)\}", compare.WORDS["az"][key])), (lang, key)


def test_script_uses_only_words_the_page_gives_it():
    js = (STATIC / "compare.js").read_text(encoding="utf-8")
    used = set(re.findall(r"\bw\.(\w+)", js)) | {f"st_{k}" for k in ("ok", "warn", "fail", "info", "none")} | {"fail", "warn", "ok"}
    assert used <= set(compare.WORDS["az"]), used - set(compare.WORDS["az"])
    assert set(compare.WORDS["az"]) <= used, set(compare.WORDS["az"]) - used
    assert "innerHTML" not in js                                # server text is written as text, never as HTML


def test_words_cannot_close_the_data_block(monkeypatch):
    monkeypatch.setitem(compare.WORDS["az"], "done", "</script><b>x")
    block = compare.data_block("az")
    assert "</script>" not in block and json.loads(block)["words"]["done"] == "</script><b>x"


def test_page_passes_our_own_length_checks():
    for lang in ("az", "en", "ru"):
        title, desc, _, _ = compare.META[lang]
        assert 10 <= len(title + " | SaytYoxla") <= 70 and 50 <= len(desc) <= 170, lang


def test_sitemap_and_llms_list_the_page():
    for path in pages.COMPARE_PATHS.values():
        assert f"<loc>{seo.SITE_URL}{path}</loc>" in seo.sitemap_xml()
    assert "/muqayise/" in seo.llms_txt()


def test_routes_redirects_and_links():
    from fastapi.testclient import TestClient

    from web import app as webapp
    client = TestClient(webapp.app)
    for lang, path in pages.COMPARE_PATHS.items():
        r = client.get(path)
        assert r.status_code == 200 and f'<html lang="{lang}">' in r.text and "content-security-policy" in r.headers
        assert client.get(path.rstrip("/"), follow_redirects=False).headers["location"].endswith(path)
    assert client.get("/static/compare.js").status_code == 200
    for home, lang in (("/", "az"), ("/en/", "en"), ("/ru/", "ru"), ("/haqqimizda/", "az"), ("/en/report/", "en")):
        assert f'href="{pages.COMPARE_PATHS[lang]}"' in client.get(home).text, home
