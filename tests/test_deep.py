"""Deep analysis: decisions on known answers, with DNS and the network replaced. No test touches the internet."""

import base64
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from scanner import deep, fetch
from scanner.safety import UnsafeTarget
from web import app as app_module

TEXT = (Path(__file__).parent.parent / "react-ui" / "src" / "deepText.ts").read_text(encoding="utf-8")
SOURCE = (Path(__file__).parent.parent / "scanner" / "deep.py").read_text(encoding="utf-8")


def ids(result):
    return {i["id"]: i for i in result["items"]}


def a_record(*ips):
    return [SimpleNamespace(address=ip) for ip in ips]


def fake_dns(table):
    """table: {(name, type): (state, answers)}; anything else does not exist."""
    return lambda name, rdtype, lifetime=4: table.get((name, rdtype), ("nx", []))


def test_every_item_has_words_in_three_languages():
    used = set(re.findall(r'_item\("(\w+)"', SOURCE))
    assert len(used) > 50
    for lang in ("AZ", "EN", "RU"):
        block = TEXT.split(f"const {lang}: Words = ")[1].split("\nconst ")[0]
        missing = [code for code in used if not re.search(rf"\b{code}: \[", block)]
        assert not missing, f"{lang} has no words for {missing}"


def test_certificate_names_keep_only_real_subdomains(monkeypatch):
    monkeypatch.setattr(deep, "_cert_spotter", lambda d: {"*.a.az", "www.a.az", "A.az", "evil-a.az", "x.a.az.", "bad_name.a.az", "b.other.az"})
    assert deep.certificate_names("a.az") == {"a.az", "www.a.az", "x.a.az"}


def test_certificate_names_fall_back_and_admit_failure(monkeypatch):
    def down(_):
        raise deep.requests.ConnectionError()
    monkeypatch.setattr(deep, "_cert_spotter", down)
    monkeypatch.setattr(deep, "_crt_sh", lambda d: {"m.a.az"})
    assert deep.certificate_names("a.az") == {"m.a.az"}
    monkeypatch.setattr(deep, "_crt_sh", down)
    assert deep.certificate_names("a.az") is None


def test_surface_says_so_when_the_logs_do_not_answer(monkeypatch):
    monkeypatch.setattr(deep, "certificate_names", lambda d: None)
    assert list(ids(deep.surface("a.az"))) == ["surface_unavailable"]


def test_cname_to_a_removed_service_is_a_takeover_risk(monkeypatch):
    monkeypatch.setattr(fetch, "dns_lookup", fake_dns({("old.a.az", "CNAME"): ("ok", [SimpleNamespace(target="gone.herokuapp.com.")])}))
    assert deep.inspect_host("old.a.az")["flag"] == "takeover"


def test_cname_to_an_unknown_missing_name_is_only_dangling(monkeypatch):
    monkeypatch.setattr(fetch, "dns_lookup", fake_dns({("old.a.az", "CNAME"): ("ok", [SimpleNamespace(target="gone.example.net.")])}))
    assert deep.inspect_host("old.a.az")["flag"] == "dangling"


def test_a_dns_failure_is_not_called_dangling(monkeypatch):
    table = {("x.a.az", "CNAME"): ("ok", [SimpleNamespace(target="y.example.net.")]), ("y.example.net", "A"): ("error", [])}
    monkeypatch.setattr(fetch, "dns_lookup", fake_dns(table))
    assert deep.inspect_host("x.a.az")["flag"] == ""


def test_provider_message_counts_only_with_its_own_cname(monkeypatch):
    table = {("p.a.az", "CNAME"): ("ok", [SimpleNamespace(target="me.github.io.")]), ("p.a.az", "A"): ("ok", a_record("185.199.108.153")),
             ("me.github.io", "A"): ("ok", a_record("185.199.108.153"))}
    monkeypatch.setattr(fetch, "dns_lookup", fake_dns(table))
    page = {"body": b"<h1>There isn't a GitHub Pages site here.</h1>"}
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (None, "", 0, [], page["body"], None))
    assert deep.inspect_host("p.a.az")["flag"] == "takeover"
    page["body"] = b"<h1>My project</h1>"
    assert deep.inspect_host("p.a.az")["flag"] == ""


def test_live_admin_name_is_flagged_and_a_lookalike_is_not(monkeypatch):
    table = {("admin.a.az", "A"): ("ok", a_record("8.8.8.8")), ("administrators-guide.a.az", "A"): ("ok", a_record("8.8.8.8"))}
    monkeypatch.setattr(fetch, "dns_lookup", fake_dns(table))
    assert deep.inspect_host("admin.a.az")["flag"] == "sensitive"
    assert deep.inspect_host("administrators-guide.a.az")["flag"] == ""
    assert deep.inspect_host("test.a.az")["flag"] == ""     # the name is sensitive but nothing answers


def test_private_address_in_public_dns_is_flagged(monkeypatch):
    monkeypatch.setattr(fetch, "dns_lookup", fake_dns({("db.a.az", "A"): ("ok", a_record("10.0.0.5"))}))
    assert deep.inspect_host("db.a.az")["flag"] == "private"


def txt(records):
    def lookup(name):
        return records.get(name, [])
    return lookup


def test_spf_lookups_are_counted_through_includes(monkeypatch):
    monkeypatch.setattr(fetch, "txt_records", txt({
        "a.az": ["v=spf1 a mx include:one.net include:two.net -all"],
        "one.net": ["v=spf1 ip4:1.1.1.1 include:three.net ~all"],
        "two.net": ["v=spf1 exists:x.net a:y.net -all"],
        "three.net": ["v=spf1 mx -all"],
    }))
    # a, mx, two includes; one include in one.net; mx in three.net; exists and a in two.net
    assert deep.spf_tree("a.az") == {"lookups": 8, "void": 0, "unknown": False}


def test_spf_loop_ends(monkeypatch):
    monkeypatch.setattr(fetch, "txt_records", txt({"a.az": ["v=spf1 include:b.az -all"], "b.az": ["v=spf1 include:a.az -all"]}))
    assert deep.spf_tree("a.az")["lookups"] == 2


def test_spf_redirect_and_void_lookups(monkeypatch):
    monkeypatch.setattr(fetch, "txt_records", txt({"a.az": ["v=spf1 redirect=b.az"], "b.az": ["v=spf1 include:gone.net -all"]}))
    assert deep.spf_tree("a.az") == {"lookups": 2, "void": 1, "unknown": False}


def key_of(size):
    return base64.b64encode(b"x" * size).decode().rstrip("=")


@pytest.mark.parametrize(("size", "bits"), [(162, 1024), (294, 2048), (550, 4096)])
def test_dkim_size(size, bits):
    assert deep.dkim_bits(f"v=DKIM1; k=rsa; p={key_of(size)}") == bits


def test_dkim_ed25519_and_junk():
    assert deep.dkim_bits(f"v=DKIM1; k=ed25519; p={key_of(32)}") == 256
    assert deep.dkim_bits("v=DKIM1; k=rsa") is None


def run_mail(monkeypatch, spf, dmarc, parent=None, mx=("none", []), dkim=None):
    monkeypatch.setattr(fetch, "txt_records", txt({"a.az": spf}))
    monkeypatch.setattr(fetch, "dmarc_records", lambda d: (dmarc, parent))
    monkeypatch.setattr(deep, "_dkim_records", lambda d: dkim if dkim is not None else {})
    monkeypatch.setattr(deep, "_mta_sts_mode", lambda d: None)
    monkeypatch.setattr(fetch, "dns_lookup", fake_dns({("a.az", "MX"): mx}))
    return ids(deep.mail("a.az"))


def test_without_dmarc_policy_mail_can_be_faked(monkeypatch):
    got = run_mail(monkeypatch, ["v=spf1 -all"], ["v=DMARC1; p=none"])
    assert got["spoof_open"]["status"] == "fail"
    assert got["spf_ok"]["status"] == "ok"


def test_reject_policy_blocks_faking_and_forgives_missing_spf(monkeypatch):
    got = run_mail(monkeypatch, [], ["v=DMARC1; p=reject"])
    assert got["spoof_blocked"]["status"] == "ok"
    assert got["spf_missing"]["status"] == "info"


def test_partial_policy_is_not_called_blocked(monkeypatch):
    got = run_mail(monkeypatch, ["v=spf1 -all"], ["v=DMARC1; p=reject; pct=20"])
    assert got["spoof_partial"]["params"]["percent"] == 20
    assert "spoof_blocked" not in got


def test_parent_subdomain_policy_decides(monkeypatch):
    assert "spoof_open" in run_mail(monkeypatch, ["v=spf1 -all"], ["v=DMARC1; p=reject; sp=none"], parent="b.az")


def test_spf_plus_all_and_duplicate(monkeypatch):
    assert run_mail(monkeypatch, ["v=spf1 +all"], [])["spf_pass_all"]["status"] == "fail"
    assert run_mail(monkeypatch, ["v=spf1 -all", "v=spf1 ~all"], [])["spf_multiple"]["params"]["count"] == 2


def test_lookups_that_failed_claim_nothing(monkeypatch):
    monkeypatch.setattr(fetch, "txt_records", lambda name: None)
    monkeypatch.setattr(fetch, "dmarc_records", lambda d: (None, None))
    monkeypatch.setattr(deep, "_dkim_records", lambda d: None)
    monkeypatch.setattr(deep, "_mta_sts_mode", lambda d: None)
    monkeypatch.setattr(fetch, "dns_lookup", lambda *a, **k: ("error", []))
    assert set(ids(deep.mail("a.az"))) == {"dns_unavailable"}


def test_platform_subdomain_is_not_judged_for_mail():
    assert set(ids(deep.mail("me.vercel.app"))) == {"mail_platform"}


def test_library_versions_come_only_from_stated_addresses():
    html = """<script src="/js/jquery-3.3.1.min.js"></script><script src="https://cdn.jsdelivr.net/npm/bootstrap@4.1.0/dist/js/bootstrap.min.js"></script>
    <script src="/lodash.js"></script><script src="/js/main.js?ver=9.9.9"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.18.1/moment.min.js"></script>"""
    found = deep.detect_libraries(html)
    assert found["jquery"] == "3.3.1"
    assert found["bootstrap"] == "4.1.0"
    assert found["moment"] == "2.18.1"
    assert "lodash" not in found


def test_wordpress_style_version_parameter():
    assert deep.detect_libraries('<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>') == {"jquery": "3.7.1"}


def page(monkeypatch, body=b"<html></html>", headers=None, status=200, vulns=None):
    response = SimpleNamespace(status_code=status, headers=headers or {})
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (response, "https://a.az/", 0, [], body, None))
    monkeypatch.setattr(deep, "osv_vulns", lambda n, v: vulns)


def test_old_php_is_named_with_its_date(monkeypatch):
    page(monkeypatch, headers={"X-Powered-By": "PHP/7.4.33"})
    got = deep.tech("a.az")
    assert ids(got)["eol_runtime"]["params"] == {"name": "PHP", "version": "7.4", "date": "2022-11-28"}


def test_supported_php_is_only_visible(monkeypatch):
    page(monkeypatch, headers={"X-Powered-By": "PHP/8.4.1"})
    assert ids(deep.tech("a.az"))["version_shown"]["status"] == "warn"


def test_known_vulnerability_needs_a_database_answer(monkeypatch):
    html = b'<script src="/jquery-3.3.1.min.js"></script>'
    page(monkeypatch, html, vulns={"count": 3, "high": 1, "ids": ["GHSA-1"]})
    assert ids(deep.tech("a.az"))["vuln_library"]["status"] == "fail"
    page(monkeypatch, html, vulns={"count": 3, "high": 0, "ids": ["GHSA-1"]})
    assert ids(deep.tech("a.az"))["vuln_library"]["status"] == "warn"
    page(monkeypatch, html, vulns=None)
    got = ids(deep.tech("a.az"))
    assert "osv_unavailable" in got and "vuln_library" not in got and "tech_clean" not in got


def test_blocked_page_says_nothing_about_the_site(monkeypatch):
    page(monkeypatch, status=403)
    result = deep.tech("a.az")
    assert ids(result)["page_blocked"]["params"]["status"] == 403
    assert result["data"]["csp"] is None


def test_blocklist_refusing_this_resolver_is_not_clean(monkeypatch):
    table = {("dbltest.com.dbl.spamhaus.org", "A"): ("ok", a_record("127.255.255.254")),
             ("a.az.dbl.spamhaus.org", "A"): ("nx", []), ("a.az", "A"): ("ok", a_record("8.8.8.8"))}
    monkeypatch.setattr(fetch, "dns_lookup", fake_dns(table))
    got = deep.reputation("a.az")
    assert "rep_unknown" in ids(got)
    assert got["data"]["checked"] == []


def test_blocklist_with_a_working_test_entry_can_be_trusted(monkeypatch):
    table = {("test.surbl.org.multi.surbl.org", "A"): ("ok", a_record("127.0.0.254")), ("a.az", "A"): ("ok", a_record("8.8.8.8"))}
    monkeypatch.setattr(fetch, "dns_lookup", fake_dns(table))
    assert ids(deep.reputation("a.az"))["rep_clean"]["params"]["lists"] == "SURBL"
    table[("a.az.multi.surbl.org", "A")] = ("ok", a_record("127.0.0.16"))
    assert ids(deep.reputation("a.az"))["rep_listed"]["params"] == {"list": "SURBL", "target": "a.az"}


def test_ownership_token_differs_per_host_and_is_stable():
    assert deep.ownership_token("a.az") == deep.ownership_token("a.az")
    assert deep.ownership_token("a.az") != deep.ownership_token("www.a.az")


def test_active_refuses_without_proof(monkeypatch):
    monkeypatch.setattr(fetch, "txt_records", lambda name: [])
    def no_file(*a, **k):
        raise deep.requests.ConnectionError()
    monkeypatch.setattr(fetch, "_get", no_file)
    monkeypatch.setattr(deep, "_port_open", lambda *a: pytest.fail("a port was touched without proof"))
    with pytest.raises(UnsafeTarget):
        deep.active("a.az")


def test_ownership_by_dns_and_by_file(monkeypatch):
    token = deep.ownership_token("a.az")
    monkeypatch.setattr(fetch, "txt_records", lambda name: [token] if name == "_saytyoxla-verify.a.az" else [])
    assert deep.is_owner("a.az")
    monkeypatch.setattr(fetch, "txt_records", lambda name: [])
    ok = SimpleNamespace(status_code=200)
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (ok, "https://a.az/.well-known/saytyoxla.txt", 0, [], token.encode(), None))
    assert deep.is_owner("a.az")


def test_redirect_to_another_site_proves_nothing(monkeypatch):
    token = deep.ownership_token("a.az")
    monkeypatch.setattr(fetch, "txt_records", lambda name: [])
    ok = SimpleNamespace(status_code=200)
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (ok, "https://evil.az/x.txt", 0, [], token.encode(), None))
    assert not deep.is_owner("a.az")


def test_soft_404_is_not_an_exposed_file(monkeypatch):
    ok = SimpleNamespace(status_code=200)
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (ok, "https://a.az/.env", 0, [], b"<html>Page not found</html>", None))
    assert not deep._probe_path("https://a.az", "a.az", "/.env", deep.EXPOSED["/.env"][1])
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (ok, "https://a.az/.env", 0, [], b"DB_PASSWORD=hunter2\n", None))
    assert deep._probe_path("https://a.az", "a.az", "/.env", deep.EXPOSED["/.env"][1])


def test_active_report_never_carries_file_content(monkeypatch):
    monkeypatch.setattr(deep, "is_owner", lambda h: True)
    monkeypatch.setattr(deep, "resolve_public", lambda h: "8.8.8.8")
    monkeypatch.setattr(deep, "_port_open", lambda ip, port: port == 6379)
    ok = SimpleNamespace(status_code=200)
    monkeypatch.setattr(fetch, "_get", lambda url, **k: (ok, url, 0, [], b"DB_PASSWORD=hunter2\n", None))
    result = deep.active("a.az")
    assert "hunter2" not in str(result)
    got = ids(result)
    assert got["exposed_file"]["status"] == "fail"
    assert got["open_port"]["params"] == {"port": 6379, "service": "Redis"}


def test_active_clean(monkeypatch):
    monkeypatch.setattr(deep, "is_owner", lambda h: True)
    monkeypatch.setattr(deep, "resolve_public", lambda h: "8.8.8.8")
    monkeypatch.setattr(deep, "_port_open", lambda ip, port: False)
    missing = SimpleNamespace(status_code=404)
    monkeypatch.setattr(fetch, "_get", lambda url, **k: (missing, url, 0, [], b"", None))
    assert set(ids(deep.active("a.az"))) == {"active_clean"}


def test_endpoint_keeps_private_targets_out():
    client = TestClient(app_module.app)
    for url in ("http://localhost", "127.0.0.1", "http://169.254.169.254/"):
        for module in deep.MODULES:
            assert client.post("/api/deep", json={"url": url, "module": module}).status_code == 400


def test_endpoint_rejects_unknown_module():
    assert TestClient(app_module.app).post("/api/deep", json={"url": "a.az", "module": "shell"}).status_code == 422


def test_active_is_never_cached(monkeypatch):
    calls = []
    def fake(raw):
        calls.append(raw)
        return {"module": "active", "host": "a.az", "items": [], "data": {}}
    monkeypatch.setitem(deep.MODULES, "active", fake)
    client = TestClient(app_module.app)
    for _ in range(2):
        assert client.post("/api/deep", json={"url": "cache-test.az", "module": "active"}).status_code == 200
    assert len(calls) == 2


def test_module_failure_gives_a_sentence_not_a_trace(monkeypatch):
    def broken(raw):
        raise RuntimeError("secret detail")
    monkeypatch.setitem(deep.MODULES, "tech", broken)
    r = TestClient(app_module.app).post("/api/deep", json={"url": "broken-module.az", "module": "tech", "lang": "en"})
    assert r.status_code == 502
    assert "secret" not in r.text and "right now" in r.json()["detail"]


def test_ownership_endpoint_tells_what_to_publish():
    data = TestClient(app_module.app).post("/api/ownership", json={"url": "https://www.a.az/x"}).json()
    assert data["dns_name"] == "_saytyoxla-verify.www.a.az"
    assert data["token"] == deep.ownership_token("www.a.az")
