"""The Tools page: narrow checks that never open the site's page. No network."""

import pytest
from fastapi.testclient import TestClient

from scanner import UnsafeTarget, fetch, tools
from web import app as webapp
from web import pages, ratelimit

client = TestClient(webapp.app)
GOOD_CERT = {"days_left": 80, "issuer": "Let's Encrypt", "expires": "2027-01-01", "error": None, "tls": "TLSv1.3"}


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    monkeypatch.setattr(webapp, "limiter", ratelimit.Limiter())
    webapp._cache.clear()
    monkeypatch.setattr(tools, "resolve_public", lambda host: "93.184.216.34")


def _no_page_load(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("a tool must not open the site's page")
    monkeypatch.setattr(fetch, "_get", forbidden)


def _dns(monkeypatch, table):
    monkeypatch.setattr(fetch, "txt_records", lambda name: table.get(name, []))


def test_ssl_reports_the_certificate_without_opening_the_page(monkeypatch):
    _no_page_load(monkeypatch)
    monkeypatch.setattr(fetch, "cert_info", lambda host, ip: GOOD_CERT)
    r = tools.ssl_check("https://www.example.az/some/page")
    assert r["host"] == "www.example.az" and r["facts"]["issuer"] == "Let's Encrypt" and r["facts"]["days_left"] == 80
    assert {f["id"]: f["status"] for f in r["findings"]} == {"cert": "ok", "tls": "ok"}


def test_ssl_explains_a_bad_certificate(monkeypatch):
    monkeypatch.setattr(fetch, "cert_info", lambda host, ip: {"days_left": None, "issuer": "", "expires": None,
                                                              "error": "certificate has expired"})
    cert = next(f for f in tools.ssl_check("example.az")["findings"] if f["id"] == "cert")
    assert cert["status"] == "fail" and "vaxtı bitib" in cert["detail"]


@pytest.mark.parametrize("error", ["ConnectionRefusedError", "TimeoutError", "SSLError"])
def test_ssl_on_a_site_without_https_is_a_plain_message(monkeypatch, error):
    monkeypatch.setattr(fetch, "cert_info", lambda host, ip: {"days_left": None, "issuer": "", "expires": None, "error": error})
    with pytest.raises(UnsafeTarget, match="HTTPS") as e:
        tools.ssl_check("example.az")
    assert error not in str(e.value)


def test_ssl_refuses_private_addresses(monkeypatch):
    def private(host):
        raise UnsafeTarget("Bu ünvan daxili şəbəkəyə aiddir və yoxlanıla bilməz.")
    monkeypatch.setattr(tools, "resolve_public", private)
    r = client.post("/api/tool", json={"url": "intranet.example.az", "tool": "ssl"})
    assert r.status_code == 400 and "daxili" in r.json()["detail"]


def test_email_reads_only_dns(monkeypatch):
    _no_page_load(monkeypatch)
    _dns(monkeypatch, {"example.az": ["v=spf1 -all", "other"], "_dmarc.example.az": ["v=DMARC1; p=reject"],
                       "google._domainkey.example.az": ["v=DKIM1; p=ABC"]})
    r = tools.email_check("www.example.az")
    assert r["host"] == "example.az"
    assert r["facts"]["spf"] == ["v=spf1 -all"] and r["facts"]["dmarc"] == ["v=DMARC1; p=reject"] and r["facts"]["dkim"] == ["google"]
    assert {f["id"]: f["status"] for f in r["findings"]} == {"spf": "ok", "dmarc": "ok", "dkim": "ok"}


def test_email_shows_the_parent_domains_rule(monkeypatch):
    _dns(monkeypatch, {"_dmarc.example.az": ["v=DMARC1; p=reject"]})
    r = tools.email_check("docs.example.az")
    assert r["facts"]["dmarc_parent"] == "example.az" and r["facts"]["dmarc"] == ["v=DMARC1; p=reject"]


def test_email_on_a_misspelled_domain_says_so(monkeypatch):
    _dns(monkeypatch, {})

    def missing(host):
        raise UnsafeTarget("Bu ünvan tapılmadı. Yazılışı yoxlayın.")
    monkeypatch.setattr(tools, "check_host_is_public", missing)
    with pytest.raises(UnsafeTarget, match="tapılmadı"):
        tools.email_check("yazilis-sehvi.az")


def test_api_runs_translates_and_caches(monkeypatch):
    calls = []

    def cert(host, ip):
        calls.append(host)
        return GOOD_CERT
    monkeypatch.setattr(fetch, "cert_info", cert)
    a = client.post("/api/tool", json={"url": "example.az", "tool": "ssl", "lang": "en"}).json()
    assert a["cached"] is False and a["findings"][0]["title"] == "SSL certificate" and "csp" in a["benchmarks"]
    assert client.post("/api/tool", json={"url": "example.az", "tool": "ssl", "lang": "ru"}).json()["cached"] is True
    assert client.post("/api/tool", json={"url": "example.az", "tool": "ssl", "fresh": True}).json()["cached"] is False
    assert len(calls) == 2


def test_api_is_rate_limited(monkeypatch):
    monkeypatch.setattr(ratelimit, "RULES", [("ip-minute", 1, 60)])
    monkeypatch.setattr(fetch, "cert_info", lambda host, ip: GOOD_CERT)
    codes = [client.post("/api/tool", json={"url": f"s{i}.az", "tool": "ssl"}).status_code for i in range(2)]
    assert codes == [200, 429]


@pytest.mark.parametrize("body", [{"url": "example.az", "tool": "nope"}, {"url": "example.az"}, {"url": "a" * 301, "tool": "ssl"}])
def test_api_refuses_bad_requests_with_one_sentence(body):
    r = client.post("/api/tool", json=body)
    assert r.status_code == 422 and isinstance(r.json()["detail"], str)


def test_api_refuses_bad_addresses():
    assert client.post("/api/tool", json={"url": "http://127.0.0.1", "tool": "email"}).status_code == 400


@pytest.mark.parametrize("lang", ["az", "en", "ru"])
def test_tools_pages_have_their_own_addresses(lang):
    path = pages.TOOLS_PATHS[lang]
    t = client.get(path).text
    assert f'<link rel="canonical" href="https://saytyoxla.vercel.app{path}">' in t
    assert f"<title>{pages.TOOLS_META[lang][1]}</title>" in t and f"<h1>{pages.TOOLS_META[lang][3]}</h1>" in t
    for other in pages.TOOLS_PATHS.values():
        assert f'href="https://saytyoxla.vercel.app{other}"' in t
    assert client.get(path.rstrip("/"), follow_redirects=False).headers["location"].endswith(path)
    assert f"<loc>https://saytyoxla.vercel.app{path}</loc>" in client.get("/sitemap.xml").text
    assert 'href="#main"' in t and "/react/assets/" in t


def test_built_front_end_has_the_tools():
    import re
    main = client.get(re.search(r'src="(/react/assets/[^"]+\.js)"', client.get("/").text).group(1)).text
    assert "Alətlər" in main and "BEGIN:VCALENDAR" not in main                     # the home page stays light
    chunks = "".join(f.read_text(encoding="utf-8") for f in (webapp.REACT / "assets").glob("*.js"))
    assert "/api/tool" in chunks and "_dmarc" in chunks and "BEGIN:VCALENDAR" in chunks
