"""The safe injection and XSS probe: detection works, and the requests it sends are read-only and non-destructive."""

import re
from types import SimpleNamespace

import pytest

from scanner import deep, injection, page_audit

OK_PAGE = b"<html><body><h1>Shop</h1>" + b"<p>a line of content</p>" * 40 + b"</body></html>"
SMALL = b"<html><body><h1>Shop</h1><p>no results</p></body></html>"
SQL_ERROR = b"<html><body>You have an error in your SQL syntax; check the manual</body></html>"


def fake_site(url):
    """A deliberately vulnerable server, path-aware like a real one: each endpoint has only its own flaw."""
    from urllib.parse import parse_qs, unquote, urlsplit
    parts = urlsplit(url)
    q = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
    v = unquote(next(iter(q.values()), ""))
    if parts.path == "/err":
        return (500, SQL_ERROR) if v.count("'") % 2 == 1 else (200, OK_PAGE)
    if parts.path == "/bool":
        return (200, SMALL) if ("1'='2" in v or v.rstrip().endswith("1=2")) else (200, OK_PAGE)
    if parts.path == "/xss":
        return 200, b"<html><body>Searched: " + v.encode() + b"</body></html>"
    return 200, b"<html><body>Searched: " + v.replace("<", "").replace("'", "").encode() + OK_PAGE + b"</body></html>"


def test_set_param_changes_only_that_value():
    assert injection.set_param("https://a.az/p?id=1&x=2", "id", "9") == "https://a.az/p?id=9&x=2"
    assert injection.set_param("https://a.az/p", "q", "9") == "https://a.az/p?q=9"


def test_error_based_needs_the_quote_to_cause_it():
    assert injection.error_based_sqli(OK_PAGE, SQL_ERROR, OK_PAGE) is True
    assert injection.error_based_sqli(SQL_ERROR, SQL_ERROR, OK_PAGE) is False   # error was there already
    assert injection.error_based_sqli(OK_PAGE, SQL_ERROR, SQL_ERROR) is False   # balanced pair errors too: not us


def test_boolean_based_needs_true_like_base_and_false_different():
    status = {"base": 200, "str_true": 200, "str_false": 200, "num_true": 200, "num_false": 200}
    body = {"base": OK_PAGE, "str_true": OK_PAGE, "str_false": SMALL, "num_true": OK_PAGE, "num_false": SMALL}
    assert injection.boolean_based_sqli(status, body) is True
    body["str_false"] = body["num_false"] = OK_PAGE        # nothing changes: not injectable
    assert injection.boolean_based_sqli(status, body) is False


def test_reflected_xss_only_on_raw_brackets():
    m = "sytxabc"
    assert injection.reflected_xss(m, b"Searched: <sytxabc> here") is True
    assert injection.reflected_xss(m, b"Searched: &lt;sytxabc&gt; here") is False


@pytest.mark.parametrize(("path", "param", "sqli", "xss"), [
    ("/err", "q", "error", False), ("/bool", "id", "boolean", False), ("/xss", "name", "", True), ("/safe", "q", "", False),
])
def test_probe_param_against_a_fake_vulnerable_site(path, param, sqli, xss):
    got = injection.probe_param(f"https://a.az{path}?{param}=1", param, fake_site)
    assert got["sqli"] == sqli
    assert got["xss"] == xss


def test_the_probe_never_sends_a_destructive_or_executable_payload():
    sent = []
    def record(url):
        sent.append(url)
        return 200, OK_PAGE
    injection.probe_param("https://a.az/p?id=1", "id", record)
    banned = re.compile(r"drop\b|delete\b|update\b|insert\b|union\b|sleep\s*\(|benchmark\s*\(|truncate\b|<script|onerror|onload", re.IGNORECASE)
    from urllib.parse import unquote
    for url in sent:
        assert not banned.search(unquote(url)), url
    assert sent and all(u.startswith("https://a.az/p?id=") for u in sent)     # GET only, same endpoint


def test_a_site_that_stops_answering_yields_no_finding():
    answers = iter([(200, OK_PAGE), None])
    assert injection.probe_param("https://a.az/p?id=1", "id", lambda u: next(answers, None)) == {"sqli": "", "xss": False}


def test_collect_targets_covers_links_and_get_forms_without_duplicates():
    links = ["https://a.az/p?id=1", "https://a.az/p?id=2", "https://a.az/s?q=x"]
    forms = [("https://a.az/find", ["term", "term"])]
    targets = injection.collect_targets(links, forms)
    assert ("https://a.az/p?id=1", "id") in targets
    assert sum(1 for _, p in targets if p == "id") == 1        # /p?id seen once
    assert ("https://a.az/find?term=1", "term") in targets


def test_get_form_targets_are_get_only_and_same_host():
    page = page_audit.parse('<form method="get" action="/find"><input name="q"><input name="x"></form>'
                            '<form method="post" action="/login"><input name="pw" type="password"></form>'
                            '<form method="get" action="https://other.net/x"><input name="z"></form>')
    assert page_audit.get_form_targets(page, "https://a.az/", "a.az") == [("https://a.az/find", ["q", "x"])]


def test_csrf_missing_only_flags_a_password_post_with_no_token():
    plain = page_audit.parse('<form method="post"><input type="password" name="pw"></form>')
    assert page_audit.csrf_missing(plain) == 1
    tokened = page_audit.parse('<form method="post"><input type="hidden" name="csrf_token" value="x"><input type="password" name="pw"></form>')
    assert page_audit.csrf_missing(tokened) == 0
    search = page_audit.parse('<form method="get"><input name="q"></form>')
    assert page_audit.csrf_missing(search) == 0


# ---- the module as a whole
def test_probe_refuses_without_ownership(monkeypatch):
    monkeypatch.setattr(deep, "is_owner", lambda h: False)
    monkeypatch.setattr(deep, "_read_page", lambda u: pytest.fail("read a page without proof"))
    with pytest.raises(deep.UnsafeTarget):
        deep.probe("a.az")


def test_probe_reports_a_real_hit_for_a_verified_owner(monkeypatch):
    monkeypatch.setattr(deep, "is_owner", lambda h: True)
    home = (SimpleNamespace(status_code=200, headers={"content-type": "text/html"}),
            "https://a.az/", [], 0, b'<a href="/err?q=1">x</a><form method="post"><input type="password" name="pw"></form>', None)
    monkeypatch.setattr(deep, "_read_page", lambda u: home)
    monkeypatch.setattr(deep, "_probe_send", lambda url, deadline: fake_site(url))
    got = {i["id"]: i for i in deep.probe("a.az")["items"]}
    assert got["sqli_found"]["params"]["method"] == "error"
    assert got["sqli_found"]["params"]["param"] == "q"
    assert got["csrf_missing"]["params"]["count"] == 1
    assert "hunter" not in str(got)       # never echoes page content


def test_probe_is_clean_on_a_safe_site(monkeypatch):
    monkeypatch.setattr(deep, "is_owner", lambda h: True)
    home = (SimpleNamespace(status_code=200, headers={"content-type": "text/html"}), "https://a.az/", [], 0, b'<a href="/s?q=1">x</a>', None)
    monkeypatch.setattr(deep, "_read_page", lambda u: home)
    monkeypatch.setattr(deep, "_probe_send", lambda url, deadline: (200, OK_PAGE))      # same page whatever we send
    got = {i["id"] for i in deep.probe("a.az")["items"]}
    assert "probe_clean" in got and "sqli_found" not in got and "xss_found" not in got
