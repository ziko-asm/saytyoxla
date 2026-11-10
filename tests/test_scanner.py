"""Scanner tests on hand-made pages: no network needed."""

import time

import pytest

import scanner
from scanner import assets, checks
from scanner.models import FAIL, INFO, OK, WARN, Context
from scanner.report import build, grade, score
from scanner.safety import UnsafeTarget, check_host_is_public, is_public_ip, normalize

GOOD_HTML = """<html lang="az"><head><title>Detalların mexaniki emalı | Bakı</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Ф1750 mm-ədək detalların mexaniki emalı. 40 illik usta təcrübəsi. Əlaqə: 050 000 00 00.">
<meta property="og:title" content="Detallar"><meta property="og:image" content="https://example.az/a.png">
<link rel="canonical" href="https://example.az/">
<link rel="stylesheet" href="https://cdn.example.com/a.css">
<script type="application/ld+json">{"@context": "https://schema.org", "@type": "LocalBusiness", "name": "Detallar"}</script>
</head><body><h1>Detalların emalı</h1><img src="/a.jpg" alt="Torna dəzgahı"></body></html>"""

BAD_HTML = """<html><head><meta name="generator" content="WordPress 5.2.1"></head>
<body><img src="http://example.az/a.jpg"><script src="http://cdn.example.com/x.js"></script></body></html>"""


def ctx(**kw):
    base = {"input_url": "https://example.az/", "final_url": "https://example.az/", "host": "example.az",
            "status_code": 200, "elapsed_ms": 400, "html": GOOD_HTML, "html_bytes": len(GOOD_HTML),
            "http_to_https": True,
            "cert": {"days_left": 80, "issuer": "Let's Encrypt", "expires": "2027-01-01", "error": None, "tls": "TLSv1.3",
                     "alpn": "h2"},
            "robots": "User-agent: *\nAllow: /\n", "sitemap": True, "dkim": ["google"],
            "assets": {"items": [{"kind": kind, "url": f"https://example.az/{kind}{n}", "bytes": 30_000, "cached": True, "own": True}
                                 for kind in ("style", "script", "image") for n in range(2)],
                       "found": 6, "blocking": 0, "images": 2, "lazy": 1},
            "headers": {"strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff",
                        "referrer-policy": "strict-origin", "x-frame-options": "SAMEORIGIN",
                        "content-security-policy": "default-src 'self'", "server": "nginx"},
            "txt_records": {"spf": ["v=spf1 include:_spf.google.com ~all"], "dmarc": ["v=DMARC1; p=reject"]}}
    base.update(kw)
    return Context(**base)


def by_id(findings):
    return {f.id: f for f in findings}


# --------------------------------------------------------------- safety
@pytest.mark.parametrize("raw,expected", [
    ("example.az", "https://example.az/"),
    ("  HTTP://Example.AZ/page ", "http://example.az/page"),
    ("https://www.shop.com.az", "https://www.shop.com.az/"),
])
def test_normalize_ok(raw, expected):
    assert normalize(raw) == expected


@pytest.mark.parametrize("raw", ["", "ftp://example.az", "https://user:pw@example.az", "localhost",
                                 "https://example.az:8080", "http://127.0.0.1", "not a url"])
def test_normalize_rejects(raw):
    with pytest.raises(UnsafeTarget):
        normalize(raw)


@pytest.mark.parametrize("ip,public", [("8.8.8.8", True), ("10.0.0.5", False), ("192.168.1.1", False),
                                       ("127.0.0.1", False), ("169.254.169.254", False), ("::1", False)])
def test_public_ip(ip, public):
    assert is_public_ip(ip) is public


def test_host_resolving_to_private_ip_is_blocked():
    def fake(host, port):
        return [(None, None, None, None, ("10.1.2.3", 0))]

    with pytest.raises(UnsafeTarget):
        check_host_is_public("intranet.example.az", resolver=fake)


# --------------------------------------------------------------- checks
def test_well_configured_site_scores_high():
    f = by_id(checks.run_checks(ctx()))
    assert all(x.status == OK for x in f.values()), [x.id for x in f.values() if x.status != OK]
    assert score(list(f.values())) == 100


def test_badly_configured_site():
    c = ctx(final_url="http://example.az/", http_to_https=False, cert=None, headers={"x-powered-by": "PHP/7.2.1"},
            html=BAD_HTML, html_bytes=len(BAD_HTML), elapsed_ms=5200,
            txt_records={"spf": [], "dmarc": ["v=DMARC1; p=none"]})
    f = by_id(checks.run_checks(c))
    assert f["https"].status == FAIL and f["spf"].status == FAIL and f["viewport"].status == FAIL
    assert f["dmarc"].status == WARN and f["http_redirect"].status == WARN
    assert f["speed"].status == FAIL
    assert "PHP/7.2.1" in f["disclosure"].detail and "WordPress 5.2.1" in f["disclosure"].detail
    assert all(x.fix for x in f.values() if x.status in (FAIL, WARN))
    assert build(c, list(f.values())).score < 40


def test_mixed_content_counts_insecure_resources():
    c = ctx(html=BAD_HTML)
    assert by_id(checks.run_checks(c))["mixed"].status == WARN
    assert "2 fayl" in by_id(checks.run_checks(c))["mixed"].detail


def test_certificate_expiry_levels():
    for days, st in [(3, FAIL), (10, WARN), (60, OK)]:
        c = ctx(cert={"days_left": days, "issuer": "", "expires": "x", "error": None})
        assert by_id(checks.run_checks(c))["cert"].status == st


def test_dns_failure_is_not_counted_against_site():
    f = by_id(checks.run_checks(ctx(txt_records={"spf": None, "dmarc": None})))
    assert f["spf"].status == "info" and f["spf"].penalty == 0


def test_email_checks_skipped_on_free_hosting_domains():
    c = ctx(final_url="https://shop.vercel.app/", txt_records={"spf": [], "dmarc": []})
    f = by_id(checks.run_checks(c))
    assert f["spf"].status == "info" and f["dmarc"].status == "info" and f["spf"].penalty == 0


def test_empty_page_is_not_punished_for_missing_tags():
    f = by_id(checks.run_checks(ctx(html="", html_bytes=0)))
    assert f["viewport"].status == "info" and f["title"].status == "info" and f["viewport"].penalty == 0


def test_error_status_is_reported(monkeypatch):
    monkeypatch.setattr(scanner, "check_host_is_public", lambda host: None)
    monkeypatch.setattr(scanner, "collect", lambda url: ctx(input_url=url, status_code=404))
    with pytest.raises(UnsafeTarget, match="404"):
        scanner.scan("example.az")


def test_blocked_status_explains_bot_protection(monkeypatch):
    monkeypatch.setattr(scanner, "check_host_is_public", lambda host: None)
    monkeypatch.setattr(scanner, "collect", lambda url: ctx(input_url=url, status_code=403))
    with pytest.raises(UnsafeTarget, match="bot qorumas"):
        scanner.scan("lalafo.az")


@pytest.mark.parametrize("raw,expected", [
    ("münchen.de", "https://xn--mnchen-3ya.de/"),
    ("https://президент.рф/", "https://xn--d1abbgf6aiiy.xn--p1ai/"),
])
def test_normalize_accepts_local_letters(raw, expected):
    assert normalize(raw) == expected


def test_normalize_accepts_azerbaijani_letters():
    host = normalize("şəki.az").split("/")[2]
    assert host.startswith("xn--") and host.encode("ascii").decode("idna") == "şəki.az"


@pytest.mark.parametrize("raw", ["example.az:abc", "https://[bad", "a" * 64 + ".az", "xn--.az."])
def test_normalize_rejects_broken_addresses_without_crashing(raw):
    with pytest.raises(UnsafeTarget):
        normalize(raw)


def test_report_shows_local_letters():
    r = _report(final_url="https://xn--mnchen-3ya.de/")
    assert r.final_url == "https://xn--mnchen-3ya.de/" and r.display_url == "https://münchen.de/"
    assert _report().display_url == "https://example.az/"


def test_svg_titles_are_not_the_page_title():
    html = """<html><head><title>GitHub · Change is constant</title></head><body>
    <svg><title>Duolingo</title></svg><svg><title>FedEx</title></svg></body></html>"""
    assert checks.parse(html).title == "GitHub · Change is constant"
    assert checks.parse("<svg><title>Logo</title></svg><title>Real</title>").title == "Real"
    assert checks.parse("<title>First</title><title>Second</title>").title == "First"


@pytest.mark.parametrize("ms,text", [(0.4, "Server 0 millisaniyəyə"), (120, "Server 120 millisaniyəyə"), (2300, "Server 2.3 saniyəyə")])
def test_response_time_text(ms, text):
    assert text in by_id(checks.run_checks(ctx(elapsed_ms=ms)))["speed"].detail


def test_invalid_certificate_is_a_plain_finding_and_not_https_ok():
    f = by_id(checks.run_checks(ctx(cert={"days_left": None, "issuer": "", "expires": None,
                                          "error": "certificate has expired"})))
    assert f["cert"].status == FAIL and "vaxtı bitib" in f["cert"].detail and "certificate has" not in f["cert"].detail
    assert f["https"].status == FAIL


def test_missing_description_is_not_a_serious_problem():
    f = by_id(checks.run_checks(ctx(html="<title>Kifayət qədər uzun başlıq</title>")))
    assert f["description"].status == WARN


def test_subdomain_is_covered_by_parent_dmarc():
    records = {"spf": [], "dmarc": ["v=DMARC1; p=quarantine; sp=reject"], "dmarc_parent": "example.az"}
    f = by_id(checks.run_checks(ctx(txt_records=records)))
    assert f["dmarc"].status == OK and "example.az" in f["dmarc"].detail
    assert f["spf"].status == "info" and f["spf"].penalty == 0


def test_parent_dmarc_uses_subdomain_policy():
    weak_sub = {"spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject; sp=none"], "dmarc_parent": "example.az"}
    assert by_id(checks.run_checks(ctx(txt_records=weak_sub)))["dmarc"].status == WARN
    no_sp = {"spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=none"], "dmarc_parent": "example.az"}
    assert by_id(checks.run_checks(ctx(txt_records=no_sp)))["dmarc"].status == WARN


def test_own_dmarc_ignores_subdomain_policy():
    # "sp=none" comes first and contains "p=", but the domain's own policy is p=reject
    records = {"spf": ["v=spf1 -all"], "dmarc": ["v=DMARC1; sp=none; p=reject"]}
    assert by_id(checks.run_checks(ctx(txt_records=records)))["dmarc"].status == OK


def test_subdomain_without_any_dmarc_still_fails():
    f = by_id(checks.run_checks(ctx(txt_records={"spf": [], "dmarc": [], "dmarc_parent": None})))
    assert f["dmarc"].status == FAIL and f["spf"].status == FAIL


def _report(**kw):
    c = ctx(**kw)
    return build(c, checks.run_checks(c))


def test_site_without_https_gets_f_whatever_else_passes():
    r = _report(final_url="http://example.az/", cert=None)
    assert r.score == 39 and r.grade == "F" and "39" in r.score_note


def test_invalid_certificate_gets_f():
    r = _report(cert={"days_left": None, "issuer": "", "expires": None, "error": "certificate has expired"})
    assert r.score <= 39 and r.grade == "F" and r.score_note


def test_certificate_about_to_expire_is_capped():
    r = _report(cert={"days_left": 3, "issuer": "", "expires": "x", "error": None})
    assert r.score == 59 and r.grade == "D" and "59" in r.score_note


@pytest.mark.parametrize("value,status", [("max-age=31536000", OK), ("max-age=15552000; includeSubDomains", OK),
                                          ("max-age=3600", WARN), ("max-age=0", WARN), ("nonsense", WARN)])
def test_hsts_time_matters(value, status):
    headers = {**ctx().headers, "strict-transport-security": value}
    assert by_id(checks.run_checks(ctx(headers=headers)))["hsts"].status == status


@pytest.mark.parametrize("policy,status", [
    ("default-src 'self'", OK),
    ("default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'", OK),
    ("script-src 'self' 'nonce-abc' 'unsafe-inline'", OK),
    ("script-src 'self' 'unsafe-inline'", WARN),
    ("default-src 'self' 'unsafe-eval'", WARN),
    ("default-src *", WARN),
    ("script-src https:", WARN),
    ("frame-ancestors 'none'", WARN),
])
def test_csp_quality(policy, status):
    headers = {**ctx().headers, "content-security-policy": policy}
    assert by_id(checks.run_checks(ctx(headers=headers)))["csp"].status == status


def test_report_only_csp_blocks_nothing():
    headers = {k: v for k, v in ctx().headers.items() if k != "content-security-policy"}
    f = by_id(checks.run_checks(ctx(headers={**headers, "content-security-policy-report-only": "default-src 'self'"})))
    assert f["csp"].status == WARN and "report-only" in f["csp"].detail


@pytest.mark.parametrize("header,value,fid,status", [
    ("x-content-type-options", "nosniff", "nosniff", OK), ("x-content-type-options", "yes", "nosniff", WARN),
    ("referrer-policy", "no-referrer", "referrer", OK), ("referrer-policy", "unsafe-url", "referrer", WARN),
    ("referrer-policy", "unsafe-url, strict-origin", "referrer", OK),
    ("x-frame-options", "DENY", "framing", OK), ("x-frame-options", "ALLOWALL", "framing", WARN),
])
def test_header_values_matter(header, value, fid, status):
    headers = {**ctx().headers, header: value}
    assert by_id(checks.run_checks(ctx(headers=headers)))[fid].status == status


def test_frame_ancestors_counts_unless_it_allows_everyone():
    base = {k: v for k, v in ctx().headers.items() if k != "x-frame-options"}
    good = {**base, "content-security-policy": "default-src 'self'; frame-ancestors 'none'"}
    bad = {**base, "content-security-policy": "default-src 'self'; frame-ancestors *"}
    assert by_id(checks.run_checks(ctx(headers=good)))["framing"].status == OK
    assert by_id(checks.run_checks(ctx(headers=bad)))["framing"].status == WARN


@pytest.mark.parametrize("cookie,status", [
    ("a=1; Path=/; Secure; SameSite=Lax", OK),
    ("a=1; Path=/", WARN),
    ("a=1; Secure", WARN),
    ("PHPSESSID=1; Secure; SameSite=Lax", WARN),
    ("PHPSESSID=1; Secure; SameSite=Lax; HttpOnly", OK),
])
def test_cookie_flags(cookie, status):
    assert by_id(checks.run_checks(ctx(cookies=[cookie])))["cookies"].status == status


def test_cookie_problem_names_the_cookies_but_not_their_values():
    f = by_id(checks.run_checks(ctx(cookies=["visitor=secret-value; Path=/"])))["cookies"]
    assert "visitor" in f.detail and "secret-value" not in f.detail


def test_no_cookies_is_fine():
    assert by_id(checks.run_checks(ctx(cookies=[])))["cookies"].status == OK


def test_dkim_absence_is_never_counted_against_a_site():
    assert by_id(checks.run_checks(ctx(dkim=["google"])))["dkim"].status == OK
    missing = by_id(checks.run_checks(ctx(dkim=[])))["dkim"]
    assert missing.status == "info" and missing.penalty == 0 and "sübut etmir" in missing.detail
    assert by_id(checks.run_checks(ctx(dkim=None)))["dkim"].status == "info"


@pytest.mark.parametrize("robots,blocked", [
    ("User-agent: *\nDisallow: /\n", True),
    ("User-agent: *\nDisallow: /admin/\n", False),
    ("User-agent: BadBot\nDisallow: /\n", False),
    ("User-agent: BadBot\nDisallow: /\n\nUser-agent: *\nDisallow:\n", False),
    ("User-agent: *\nDisallow: /\nAllow: /\n", False),
    ("", False),
])
def test_robots_blocking_everyone(robots, blocked):
    assert checks.blocks_everyone(robots) is blocked
    assert (by_id(checks.run_checks(ctx(robots=robots)))["indexing"].status == FAIL) is blocked


@pytest.mark.parametrize("tag", ['<meta name="robots" content="noindex, nofollow">', '<meta name="robots" content="none">'])
def test_noindex_is_serious(tag):
    html = GOOD_HTML.replace("</head>", tag + "</head>")
    assert by_id(checks.run_checks(ctx(html=html)))["indexing"].status == FAIL


def test_noindex_header_is_serious():
    headers = {**ctx().headers, "x-robots-tag": "noindex"}
    assert by_id(checks.run_checks(ctx(headers=headers)))["indexing"].status == FAIL


def test_unknown_crawler_files_are_not_counted():
    f = by_id(checks.run_checks(ctx(robots=None, sitemap=None)))
    assert f["indexing"].status == "info" and f["sitemap"].status == "info"


def test_missing_sitemap_is_a_recommendation():
    assert by_id(checks.run_checks(ctx(sitemap=False)))["sitemap"].status == WARN


def test_page_basics():
    bare = by_id(checks.run_checks(ctx(html="<html><head><title>Kifayət qədər uzun başlıq</title></head><body>"
                                            "<h1>A</h1><h1>B</h1></body></html>")))
    assert bare["h1"].status == WARN and "2 əsas" in bare["h1"].detail
    assert bare["lang"].status == WARN and bare["canonical"].status == WARN and bare["og"].status == WARN


def test_page_built_by_javascript_is_not_blamed_for_missing_tags():
    html = '<html lang="az"><head><title>App</title></head><body><div id="root"></div><script src="/a.js"></script></body></html>'
    f = by_id(checks.run_checks(ctx(html=html)))
    assert all(f[i].status == "info" and f[i].penalty == 0 for i in ("description", "h1", "canonical", "og"))
    assert "JavaScript" in f["h1"].detail


def test_page_with_real_text_and_scripts_is_judged_normally():
    html = f'<html><head><title>Mətn</title></head><body><script src="/a.js"></script><p>{"söz " * 100}</p></body></html>'
    f = by_id(checks.run_checks(ctx(html=html)))
    assert f["h1"].status == WARN and f["description"].status == WARN


def test_uncompressed_page_is_a_recommendation_unless_it_is_tiny():
    big = {"html_bytes": 60_000}
    assert by_id(checks.run_checks(ctx(**big)))["compression"].status == WARN
    for encoding in ("gzip", "br", "zstd"):
        headers = {**ctx().headers, "content-encoding": encoding}
        assert by_id(checks.run_checks(ctx(headers=headers, **big)))["compression"].status == OK
    assert by_id(checks.run_checks(ctx(html_bytes=900)))["compression"].status == OK


@pytest.mark.parametrize("protocol,status", [("h2", OK), ("http/1.1", WARN), (None, "info")])
def test_http2_comes_from_the_tls_handshake(protocol, status):
    cert = {**ctx().cert, "alpn": protocol}
    f = by_id(checks.run_checks(ctx(cert=cert)))["http2"]
    assert f.status == status and (f.penalty > 0) is (status == WARN)


def test_http2_is_not_judged_without_https_or_a_readable_certificate():
    assert by_id(checks.run_checks(ctx(final_url="http://example.az/", cert=None)))["http2"].status == "info"
    broken = {"days_left": None, "issuer": "", "expires": None, "error": "certificate has expired"}
    assert by_id(checks.run_checks(ctx(cert=broken)))["http2"].status == "info"


def test_images_without_a_description_are_counted():
    html = ('<html><body><p>' + "söz " * 100 + '</p><img src="a.jpg"><img src="b.jpg" alt="Mağaza">'
            '<img src="line.png" alt=""><img src="pixel.gif" width="1" height="1"></body></html>')
    f = by_id(checks.run_checks(ctx(html=html)))["img_alt"]
    assert f.status == WARN and "sayı: 1 (cəmi 3)" in f.detail and f.fix
    assert by_id(checks.run_checks(ctx(html="<html><body><p>Mətn</p></body></html>")))["img_alt"].status == OK


def test_structured_data_is_found_as_json_ld_or_microdata():
    text = "<p>" + "söz " * 100 + "</p>"
    assert by_id(checks.run_checks(ctx(html=f"<html><body>{text}</body></html>")))["schema"].status == WARN
    micro = f'<html><body><div itemscope itemtype="https://schema.org/Store">{text}</div></body></html>'
    assert by_id(checks.run_checks(ctx(html=micro)))["schema"].status == OK
    assert by_id(checks.run_checks(ctx()))["schema"].status == OK


def test_a_data_block_does_not_make_a_page_look_built_by_javascript():
    html = '<html><head><script type="application/ld+json">{}</script></head><body><p>Qısa</p></body></html>'
    f = by_id(checks.run_checks(ctx(html=html)))
    assert checks.parse(html).scripts == 0 and f["h1"].status == WARN and f["description"].status == WARN


def test_core_protections_cap_the_grade():
    base = {"strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer", "x-frame-options": "DENY", "content-security-policy": "default-src 'self'"}
    drop = lambda *names: {k: v for k, v in base.items() if k not in names}
    assert _report(headers=drop("content-security-policy")).grade == "A"       # one gap keeps an A
    two = _report(headers=drop("content-security-policy", "x-frame-options"))
    assert two.score == 89 and two.grade == "B" and "2 əsas" in two.score_note
    four = _report(headers=drop("content-security-policy", "x-frame-options", "x-content-type-options",
                                "strict-transport-security"))
    assert four.score == 74 and four.grade == "C" and "4 əsas" in four.score_note


def test_no_note_when_the_cap_changes_nothing():
    r = _report()
    assert r.score == 100 and r.score_note == ""
    low = _report(final_url="http://example.az/", cert=None, http_to_https=False, headers={}, html=BAD_HTML,
                  html_bytes=2_000_000, elapsed_ms=6000, txt_records={"spf": [], "dmarc": []}, sitemap=False, assets=None)
    assert low.score < 39 and low.score_note == ""


def test_grade_and_report_order():
    assert [grade(s) for s in (95, 80, 65, 45, 10)] == ["A", "B", "C", "D", "F"]
    c = ctx(txt_records={"spf": [], "dmarc": []})
    r = build(c, checks.run_checks(c))
    assert r.findings[0].status == FAIL and "ciddi problem" in r.summary
    d = r.to_dict()
    assert d["counts"]["fail"] == 2 and d["grade"] in "ABCDF"


def test_scan_end_to_end_without_network(monkeypatch):
    monkeypatch.setattr(scanner, "check_host_is_public", lambda host: None)
    monkeypatch.setattr(scanner, "collect", lambda url: ctx(input_url=url))
    r = scanner.scan("example.az")
    assert r.score == 100 and r.grade == "A"


def test_scan_reports_unreachable_site(monkeypatch):
    monkeypatch.setattr(scanner, "check_host_is_public", lambda host: None)
    monkeypatch.setattr(scanner, "collect", lambda url: Context(input_url=url, error="ConnectTimeout"))
    with pytest.raises(UnsafeTarget, match="vaxtında cavab vermədi"):
        scanner.scan("example.az")


@pytest.mark.parametrize("error", ["SSLError", "ConnectTimeout", "ReadTimeout", "ConnectionError", "ChunkedEncodingError"])
def test_error_messages_never_show_exception_names(error):
    assert error not in scanner.error_message(error) and "açılmadı" in scanner.error_message(error)


# --------------------------------------------------------------- what the page downloads
ASSET_HTML = """<html><head><link rel="stylesheet" href="/a.css"><script src="/a.js"></script><script src="/b.js" defer></script>
<script type="module" src="/m.js"></script><script type="application/ld+json">{}</script><script src="/a.js"></script>
</head><body><img src="img/p.jpg" loading="lazy"><img src="data:image/png;base64,AAAA"><img src="https://cdn.example.com/q.png">
<script src="/late.js"></script></body></html>"""


def test_assets_are_listed_once_with_blocking_scripts_counted():
    files, page = assets.listed(ASSET_HTML, "https://example.az/shop/")
    assert files == [("style", "https://example.az/a.css"), ("script", "https://example.az/a.js"), ("script", "https://example.az/b.js"),
                     ("script", "https://example.az/m.js"), ("script", "https://example.az/late.js"),
                     ("image", "https://example.az/shop/img/p.jpg"), ("image", "https://cdn.example.com/q.png")]
    assert page.blocking == 2 and page.lazy == 1      # a.js twice in <head>; defer, module and the body script do not block


def test_assets_collect_keeps_unanswered_files_unknown():
    sizes = {"https://example.az/a.css": {"bytes": 5000, "cached": True, "type": "text/css"}}
    got = assets.collect(ASSET_HTML, "https://example.az/", measure=lambda url, verify, deadline: sizes.get(url))
    by_url = {i["url"]: i for i in got["items"]}
    assert by_url["https://example.az/a.css"] == {"kind": "style", "url": "https://example.az/a.css", "bytes": 5000, "cached": True, "own": True}
    assert by_url["https://example.az/a.js"]["bytes"] is None
    assert by_url["https://cdn.example.com/q.png"]["own"] is False
    assert got["found"] == 7 and got["blocking"] == 2


def test_asset_request_refuses_internal_addresses():
    """A page can name any address as its picture; it must not make the scanner call an internal one."""
    internal = lambda host: (_ for _ in ()).throw(UnsafeTarget("internal"))
    assert assets.measure("https://intranet.example.az/x.png", True, time.monotonic() + 5, resolve=internal) is None
    assert assets.measure("http://example.az:8080/x.png", True, time.monotonic() + 5) is None
    assert assets.measure("file:///etc/passwd", True, time.monotonic() + 5) is None


@pytest.mark.parametrize(("headers", "cached"), [
    ({"cache-control": "public, max-age=31536000"}, True), ({"cache-control": "max-age=0"}, False),
    ({"cache-control": "no-cache"}, False), ({"expires": "Thu, 01 Jan 2099 00:00:00 GMT"}, True), ({}, False),
    ({"cache-control": "immutable"}, True), ({"cache-control": "no-store, max-age=600"}, False)])
def test_asset_caching_header(headers, cached):
    assert assets._cached(headers) is cached


def _with_assets(items, **kw):
    return ctx(assets={"items": items, "found": kw.pop("found", len(items)), "blocking": kw.pop("blocking", 0), "images": 0, "lazy": 0}, **kw)


def test_heavy_page_and_images_are_reported():
    big = [{"kind": "image", "url": f"https://example.az/foto{n}.jpg", "bytes": 2_400_000, "cached": False, "own": True} for n in range(3)]
    f = by_id(checks.run_checks(_with_assets(big, blocking=5)))
    assert f["weight"].status == FAIL and "7.2 MB" in f["weight"].detail
    assert f["img_weight"].status == FAIL and "foto0.jpg" in f["img_weight"].detail
    assert f["blocking"].status == WARN and f["asset_cache"].status == WARN


def test_unmeasured_assets_cost_no_points():
    unknown = [{"kind": "script", "url": "https://example.az/a.js", "bytes": None, "cached": False, "own": True}]
    for c in (ctx(assets=None), _with_assets(unknown)):
        f = by_id(checks.run_checks(c))
        assert f["weight"].status == INFO and f["asset_cache"].status == INFO
    assert "ən azı" in by_id(checks.run_checks(_with_assets(
        [{"kind": "script", "url": "https://example.az/a.js", "bytes": 1000, "cached": True, "own": True}], found=80)))["weight"].detail


def test_other_companies_files_do_not_count_against_caching():
    cdn = [{"kind": "script", "url": f"https://cdn.example.com/{n}.js", "bytes": 1000, "cached": False, "own": False} for n in range(6)]
    assert by_id(checks.run_checks(_with_assets(cdn)))["asset_cache"].status == INFO
