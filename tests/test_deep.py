"""Deep analysis: decisions on known answers, with DNS and the network replaced. No test touches the internet."""

import base64
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests
from fastapi.testclient import TestClient

from scanner import cve, deep, fetch, monitor, page_audit, tlsprobe
from scanner.safety import UnsafeTarget
from web import app as app_module

TEXT = (Path(__file__).parent.parent / "react-ui" / "src" / "deepText.ts").read_text(encoding="utf-8")
SOURCE = (Path(__file__).parent.parent / "scanner" / "deep.py").read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def no_internet(monkeypatch):
    def refuse(*a, **k):
        raise requests.ConnectionError()
    monkeypatch.setattr(requests, "get", refuse)
    monkeypatch.setattr(deep, "_cors_reflects", lambda base, ip: False)
    monkeypatch.setattr(deep, "_axfr_open", lambda domain: "")
    cve._memory.clear()


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


def test_certificate_names_keep_only_real_subdomains():
    entries = [{"names": ["*.a.az", "www.a.az", "A.az", "evil-a.az", "x.a.az.", "bad_name.a.az", "b.other.az"]}]
    assert deep.certificate_names(entries, "a.az") == {"a.az", "www.a.az", "x.a.az"}


def test_certificate_log_falls_back_and_admits_failure(monkeypatch):
    def down(_):
        raise deep.requests.ConnectionError()
    monkeypatch.setattr(deep, "_cert_spotter", down)
    monkeypatch.setattr(deep, "_crt_sh", lambda d: [{"names": ["m.a.az"]}])
    assert deep._certificate_log("a.az") == [{"names": ["m.a.az"]}]
    monkeypatch.setattr(deep, "_crt_sh", down)
    assert deep._certificate_log("a.az") is None


def test_certificate_stats_tell_history_and_what_is_valid_now():
    stats = deep.certificate_stats([{"from": "2020-01-01", "to": "2020-04-01", "issuer": "B"}, {"from": "2999-01-01", "to": "2999-04-01", "issuer": "A"}, {"from": "2998-01-01", "to": "2999-02-01", "issuer": "A"}])
    assert stats == {"count": 3, "active": 2, "first": "2020-01-01", "last": "2999-01-01", "next_expiry": "2999-02-01", "issuers": ["A", "B"]}


def test_spf_steps_show_the_tree(monkeypatch):
    monkeypatch.setattr(fetch, "txt_records", txt({"a.az": ["v=spf1 mx include:b.net -all"], "b.net": ["v=spf1 a -all"]}))
    steps = []
    deep.spf_tree("a.az", steps=steps)
    assert steps == [{"domain": "a.az", "depth": 0, "lookups": 2}, {"domain": "b.net", "depth": 1, "lookups": 1}]


def test_osv_names_the_version_that_fixes_all(monkeypatch):
    answer = {"vulns": [{"id": "A", "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.5.0"}]}]}]},
                        {"id": "B", "database_specific": {"severity": "HIGH"}, "affected": [{"ranges": [{"events": [{"fixed": "3.10.1"}]}]}]}]}
    monkeypatch.setattr(deep.requests, "post", lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: answer))
    assert deep.osv_vulns("jquery", "3.3.1") == {"count": 2, "high": 1, "ids": ["A", "B"], "fixed": "3.10.1"}


def test_report_lists_every_blocklist_including_unavailable(monkeypatch):
    table = {("test.surbl.org.multi.surbl.org", "A"): ("ok", a_record("127.0.0.254")), ("a.az", "A"): ("ok", a_record("8.8.8.8"))}
    monkeypatch.setattr(fetch, "dns_lookup", fake_dns(table))
    rows = {r["list"]: r["state"] for r in deep.reputation("a.az")["data"]["table"]}
    assert rows == {"Spamhaus DBL": "unavailable", "SURBL": "clean", "Spamhaus SBL/XBL": "unavailable", "SpamCop": "unavailable"}


def test_surface_says_so_when_the_logs_do_not_answer(monkeypatch):
    monkeypatch.setattr(deep, "_certificate_log", lambda d: None)
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
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (None, "", [], 0, page["body"], None))
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
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (response, "https://a.az/", [], 0, body, None))
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


# ---- answers of real providers, as read on 5 November 2026
@pytest.mark.parametrize(("target", "page", "flag"), [
    ("x.github.io", "There isn't a GitHub Pages site here.", "takeover"),
    ("x.pantheonsite.io", "<title>404 - Unknown site</title>", "takeover"),
    ("x.readthedocs.io", "404 Project not found", "takeover"),
    ("x.ghost.io", "Domain error Failed to resolve DNS path for this host", "takeover"),
    ("x.herokuapp.com", "no such app", "takeover"),             # the case differs between pages
    ("x.netlify.app", "Not Found - Request ID: 01M6", "dead"),  # gone, but the provider keeps the name tied to its owner
    ("x.vercel.app", "DEPLOYMENT_NOT_FOUND", "dead"),
    ("x.myshopify.com", "Store unavailable", "dead"),
    ("x.github.io", "My real project", ""),
    ("x.netlify.app", "My real project", ""),
])
def test_provider_answers(monkeypatch, target, page, flag):
    table = {("h.a.az", "CNAME"): ("ok", [SimpleNamespace(target=target + ".")]), (target, "A"): ("ok", a_record("8.8.8.8")), ("h.a.az", "A"): ("ok", a_record("8.8.8.8"))}
    monkeypatch.setattr(fetch, "dns_lookup", fake_dns(table))
    monkeypatch.setattr(fetch, "_get", lambda *a, **k: (None, "", [], 0, page.encode(), None))
    assert deep.inspect_host("h.a.az")["flag"] == flag


def test_client_hello_is_well_formed():
    hello = tlsprobe.client_hello("a.az", tlsprobe.TLS10, (0x000A,))
    assert hello[:3] == b"\x16\x03\x01" and hello[5] == 1
    assert int.from_bytes(hello[3:5], "big") == len(hello) - 5
    assert hello[9:11] == bytes(tlsprobe.TLS10)
    assert b"a.az" in hello


def server_hello(version, cipher, session=b""):
    body = bytes(version) + b"\x00" * 32 + bytes([len(session)]) + session + cipher.to_bytes(2, "big") + b"\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def test_server_answers_are_read_exactly():
    assert tlsprobe.read_answer(server_hello((3, 1), 0x000A)) == ((3, 1), 0x000A)
    assert tlsprobe.read_answer(server_hello((3, 3), 0xC02F, b"x" * 32)) == ((3, 3), 0xC02F)
    assert tlsprobe.read_answer(b"\x15\x03\x03\x00\x02\x02\x28") is None      # an alert is a refusal
    assert tlsprobe.read_answer(b"") is None


@pytest.mark.parametrize(("answer", "expected"), [(((3, 3), 0x000A), "3DES"), (((3, 3), 0x0005), "RC4"), (((3, 3), 0x0001), "NULL"), (((3, 3), 0xC02F), False), (False, False), (None, None)])
def test_weak_cipher_names_the_family(monkeypatch, answer, expected):
    monkeypatch.setattr(tlsprobe, "_ask", lambda *a, **k: answer)
    assert tlsprobe.weak_cipher("a.az", "8.8.8.8") == expected


def test_a_server_answering_another_version_does_not_speak_this_one(monkeypatch):
    monkeypatch.setattr(tlsprobe, "_ask", lambda *a, **k: ((3, 3), 0xC02F))
    assert tlsprobe.accepts_version("a.az", "8.8.8.8", tlsprobe.TLS10) is False


def nvd_answer(*scores):
    vulns = [{"cve": {"id": f"CVE-{i}", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]}}} for i, score in enumerate(scores)]
    return SimpleNamespace(status_code=200, json=lambda: {"vulnerabilities": vulns})


def test_server_cves_put_the_worst_first(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: nvd_answer(5.0, 9.8, 7.0))
    assert cve.server_cves("nginx", "1.10.3") == {"count": 3, "high": 2, "ids": ["CVE-1", "CVE-2", "CVE-0"]}


def test_a_vague_or_unknown_version_matches_nothing(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **k: pytest.fail("asked NVD about nothing"))
    assert cve.server_cves("nginx", "1") is None
    assert cve.server_cves("unknown-server", "1.2.3") is None


def test_plugins_are_read_from_the_page():
    html = '<script src="/wp-content/plugins/contact-form-7/a.js?ver=5.1"></script><link href="/wp-content/plugins/woo/x.css"><img src="/wp-content/themes/astra/i.png">'
    assert cve.detect_plugins(html) == {"contact-form-7": "5.1", "woo": ""}
    assert cve.detect_theme(html) == "astra"


def test_wpscan_counts_only_what_still_applies(monkeypatch):
    monkeypatch.setenv("WPSCAN_API_KEY", "k")
    answer = {"p": {"vulnerabilities": [{"id": "a", "fixed_in": "2.0", "references": {"cve": ["2020-1"]}}, {"id": "b", "fixed_in": "1.0"}, {"id": "c", "fixed_in": None}]}}
    monkeypatch.setattr(requests, "get", lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: answer))
    assert cve.plugin_vulns("p", "1.5")["count"] == 2


def test_secrets_are_named_but_their_values_stay_out():
    assert page_audit.find_secrets(b"var k='AKIAIOSFODNN7EXAMPLE'") == ["AWS"]
    assert page_audit.find_secrets(b"-----BEGIN RSA PRIVATE KEY-----") == ["private key"]
    assert page_audit.find_secrets(b"var maps='AIzaSyPublicBrowserKey'; sk_test_abc") == []


def test_script_banner_finds_a_version_the_address_hides():
    assert page_audit.banner_versions(b"/*! jQuery v1.12.4 | (c) jQuery */")["jquery"] == "1.12.4"
    assert page_audit.banner_versions(b"//! version : 2.18.1")["moment"] == "2.18.1"
    assert page_audit.banner_versions(b"function a(){}") == {}


def test_password_form_over_plain_http_is_caught():
    page = page_audit.parse('<form action="http://a.az/in" method="post"><input type="password"></form>')
    assert page_audit.audit_forms(page, "https://a.az/")["password_plain"] == 1
    safe = page_audit.parse('<form action="/in" method="post"><input type="password"></form>')
    assert page_audit.audit_forms(safe, "https://a.az/")["password_plain"] == 0
    assert page_audit.audit_forms(safe, "http://a.az/")["password_plain"] == 1


def test_form_posting_to_a_stranger_is_named():
    page = page_audit.parse('<form action="https://evil.net/x" method="post"></form><form action="https://pay.a.az/x" method="post"></form>')
    assert page_audit.audit_forms(page, "https://www.a.az/")["outside"] == ["evil.net"]


def test_only_outside_scripts_need_a_signature():
    page = page_audit.parse('<script src="/own.js"></script><script src="https://cdn.a.az/x.js"></script>'
                            '<script src="https://cdn.net/a.js"></script><script src="https://safe.net/b.js" integrity="sha384-x"></script>')
    got = page_audit.outside_resources(page, "https://a.az/")
    assert got["hosts"] == ["cdn.net", "safe.net"] and got["unsigned"] == ["cdn.net"]


def test_header_quality():
    got = page_audit.audit_headers({"content-security-policy": "script-src 'self' 'unsafe-inline'", "strict-transport-security": "max-age=300"})
    assert got["csp_unsafe"] == ["'unsafe-inline'"] and got["hsts_short"] and "x-frame-options" in got["missing"]
    assert page_audit.audit_headers({"strict-transport-security": "max-age=31536000"})["hsts_short"] is False


def test_only_session_cookies_are_judged():
    cookies = [{"name": "PHPSESSID", "secure": False, "httponly": True}, {"name": "theme", "secure": False, "httponly": False}, {"name": "auth_token", "secure": True, "httponly": True}]
    assert page_audit.audit_cookies(cookies, True) == ["PHPSESSID"]


def test_robots_paths_that_look_private():
    assert page_audit.robots_paths("User-agent: *\nDisallow: /admin/\nDisallow: /search\nDisallow: /backup.sql") == ["/admin/", "/backup.sql"]


def test_page_with_no_https_is_still_read(monkeypatch):
    response = SimpleNamespace(status_code=200, headers={"Server": "nginx/1.19.0"})
    def answer(url, **k):
        if url.startswith("https://"):
            raise requests.ConnectionError()
        return (response, url, [], 0, b"<html></html>", None)
    monkeypatch.setattr(fetch, "_get", answer)
    assert ids(deep.tech("a.az"))["version_shown"]["params"]["name"] == "nginx"


def test_spamhaus_key_changes_only_the_zone(monkeypatch):
    monkeypatch.delenv("SPAMHAUS_DQS_KEY", raising=False)
    assert deep._zone("dbl.spamhaus.org") == "dbl.spamhaus.org"
    monkeypatch.setenv("SPAMHAUS_DQS_KEY", "abc")
    assert deep._zone("zen.spamhaus.org") == "abc.zen.dq.spamhaus.net"
    assert deep._zone("multi.surbl.org") == "multi.surbl.org"


def test_safe_browsing_listed_and_clean(monkeypatch):
    monkeypatch.setattr(fetch, "dns_lookup", fake_dns({}))
    monkeypatch.setattr(deep, "_safe_browsing", lambda d: {"threats": ["MALWARE"]})
    got = deep.reputation("a.az")
    assert ids(got)["safe_browsing_listed"]["params"]["threats"] == "MALWARE"
    monkeypatch.setattr(deep, "_safe_browsing", lambda d: {"threats": []})
    assert ids(deep.reputation("a.az"))["rep_clean"]["params"]["lists"] == "Google Safe Browsing"


def test_safe_browsing_says_nothing_without_a_key(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_KEY", raising=False)
    assert deep._safe_browsing("a.az") is None


def test_crawl_refuses_without_proof(monkeypatch):
    monkeypatch.setattr(deep, "is_owner", lambda h: False)
    monkeypatch.setattr(deep, "_read_page", lambda u: pytest.fail("a page was read without proof"))
    with pytest.raises(UnsafeTarget):
        deep.crawl("a.az")


def test_crawl_stays_on_the_site_and_reports_paths_only(monkeypatch):
    monkeypatch.setattr(deep, "is_owner", lambda h: True)
    site = {
        "https://a.az/": b'<a href="/about">a</a><a href="https://other.az/x">o</a><a href="/file.pdf">f</a><a href="/logout">l</a>',
        "https://a.az/about": b'<script>var k="AKIAIOSFODNN7EXAMPLE"</script><a href="/">h</a>Fatal error</b>',
    }
    read = []
    def page(url):
        read.append(url)
        return (SimpleNamespace(status_code=200, headers={"content-type": "text/html"}), url, [], 5, site[url], None)
    monkeypatch.setattr(deep, "_read_page", page)
    result = deep.crawl("a.az")
    assert sorted(read) == ["https://a.az/", "https://a.az/about"]
    got = ids(result)
    assert got["js_secret"]["params"] == {"kind": "AWS", "path": "/about"}
    assert got["error_shown"]["params"]["paths"] == "/about"
    assert "AKIA" not in str(result)


def test_active_finds_open_directories_without_soft_404s(monkeypatch):
    monkeypatch.setattr(deep, "is_owner", lambda h: True)
    monkeypatch.setattr(deep, "resolve_public", lambda h: "8.8.8.8")
    monkeypatch.setattr(deep, "_port_open", lambda ip, port: port == 443)
    ok = SimpleNamespace(status_code=200)
    monkeypatch.setattr(fetch, "_get", lambda url, **k: (ok, url, [], 0, b"<title>Index of /uploads</title>" if url == "https://a.az/uploads/" else b"<html>home</html>", None))
    got = deep.active("a.az")
    assert [i["params"]["path"] for i in got["items"] if i["id"] == "dir_listing"] == ["/uploads/"]
    assert "exposed_file" not in ids(got)


# ---- watching
@pytest.fixture
def watching(monkeypatch):
    for name, value in {"MONITOR_SECRET": "s" * 32, "BREVO_API_KEY": "b", "MONITOR_FROM": "me@a.az", "CRON_SECRET": "c", "KV_REST_API_URL": "https://r", "KV_REST_API_TOKEN": "t"}.items():
        monkeypatch.setenv(name, value)
    store = {"sets": {}, "keys": {}}
    def redis(*commands):
        out = []
        for cmd in commands:
            if cmd[0] == "SET":
                store["keys"][cmd[1]] = cmd[2]; out.append("OK")
            elif cmd[0] == "GET":
                out.append(store["keys"].get(cmd[1]))
            elif cmd[0] == "DEL":
                store["keys"].pop(cmd[1], None); out.append(1)
            elif cmd[0] == "SADD":
                store["sets"].setdefault(cmd[1], set()).add(cmd[2]); out.append(1)
            elif cmd[0] == "SREM":
                store["sets"].get(cmd[1], set()).discard(cmd[2]); out.append(1)
            elif cmd[0] == "SMEMBERS":
                out.append(sorted(store["sets"].get(cmd[1], set())))
        return out
    monkeypatch.setattr(monitor, "_redis", redis)
    mails = []
    monkeypatch.setattr(monitor, "send_mail", lambda to, subject, text: mails.append((to, subject, text)) or True)
    return store, mails


def test_watching_is_off_without_accounts(monkeypatch):
    for name in ("MONITOR_SECRET", "BREVO_API_KEY", "MONITOR_FROM", "CRON_SECRET", "UPSTASH_REDIS_REST_URL", "KV_REST_API_URL"):
        monkeypatch.delenv(name, raising=False)
    assert not monitor.enabled()
    client = TestClient(app_module.app)
    assert client.get("/api/monitor/status").json() == {"enabled": False}
    assert client.post("/api/monitor", json={"url": "a.az", "email": "a@a.az"}).status_code == 503


def test_tokens_cannot_be_forged_reused_for_another_action_or_outlive(watching):
    token = monitor.sign("confirm", "a.az", "x@a.az", "az")
    assert monitor.read_token(token, "confirm") == ("a.az", "x@a.az", "az")
    assert monitor.read_token(token, "stop") is None
    assert monitor.read_token(token[:-2] + "AA", "confirm") is None
    assert monitor.read_token(monitor.sign("confirm", "a.az", "x@a.az", "az", life=-5), "confirm") is None


def test_only_the_owner_can_subscribe(watching, monkeypatch):
    _, mails = watching
    monkeypatch.setattr(deep, "is_owner", lambda h: False)
    assert monitor.subscribe("a.az", "x@a.az", "az", "https://s") == "Əvvəlcə saytın sizə aid olduğunu təsdiqləyin."
    assert monitor.subscribe("a.az", "not an address", "az", "https://s") == "E-poçt ünvanı düzgün deyil."
    assert mails == []


def test_subscribing_needs_the_mailbox_to_confirm(watching, monkeypatch):
    store, mails = watching
    monkeypatch.setattr(deep, "is_owner", lambda h: True)
    assert monitor.subscribe("a.az", "x@a.az", "en", "https://s") == ""
    assert not store["keys"]            # nothing kept before the address itself says yes
    token = re.search(r"t=(\S+)", mails[0][2]).group(1)
    assert monitor.confirm(token) == "en"
    assert len(store["keys"]) == 1


def test_stop_deletes_the_address(watching):
    store, _ = watching
    monitor.confirm(monitor.sign("confirm", "a.az", "x@a.az", "az"))
    assert monitor.stop(monitor.sign("stop", "a.az", "x@a.az", "az")) == "az"
    assert not store["keys"] and not store["sets"]["saytyoxla:mon:all"]


def test_first_look_is_silent_then_changes_are_named():
    now = {"hosts": ["a.x.az"], "problems": ["p1"], "days": 80}
    assert monitor.changes(None, now) == {"hosts": [], "new": 0, "solved": 0, "cert": None}
    later = {"hosts": ["a.x.az", "new.x.az"], "problems": ["p2"], "days": 79}
    assert monitor.changes(now, later) == {"hosts": ["new.x.az"], "new": 1, "solved": 1, "cert": None}


def test_certificate_warning_comes_once():
    assert monitor.changes({"hosts": [], "problems": [], "days": 15}, {"hosts": [], "problems": [], "days": 14})["cert"] == 14
    assert monitor.changes({"hosts": [], "problems": [], "days": 14}, {"hosts": [], "problems": [], "days": 13})["cert"] is None


def test_a_part_that_failed_does_not_read_as_solved(monkeypatch):
    monkeypatch.setitem(deep.MODULES, "surface", lambda h: {"items": [{"id": "surface_unavailable", "status": "info", "params": {}}], "data": {"hosts": []}})
    assert monitor.snapshot("a.az") is None


def test_run_mails_only_on_change_and_checks_a_few(watching, monkeypatch):
    _, mails = watching
    for i in range(4):
        monitor.confirm(monitor.sign("confirm", f"s{i}.az", "x@a.az", "az"))
    monkeypatch.setattr(monitor, "snapshot", lambda h: {"hosts": [], "problems": [], "days": 80})
    assert monitor.run("https://s", now=1000000) == {"checked": 2, "sent": 0}
    assert monitor.run("https://s", now=1000001) == {"checked": 2, "sent": 0}
    assert monitor.run("https://s", now=1000002) == {"checked": 0, "sent": 0}     # all seen today
    monkeypatch.setattr(monitor, "snapshot", lambda h: {"hosts": ["new.az"], "problems": [], "days": 80})
    assert monitor.run("https://s", now=1000000 + monitor.CHECK_EVERY + 5)["sent"] == 2
    assert "new.az" in mails[0][2] and "/monitor/stop?t=" in mails[0][2]


def test_timer_needs_its_secret(watching, monkeypatch):
    client = TestClient(app_module.app)
    assert client.post("/api/cron/monitor").status_code == 401
    assert client.post("/api/cron/monitor", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/api/cron/monitor", headers={"Authorization": "Bearer c"}).status_code == 200


def test_bad_links_say_so():
    client = TestClient(app_module.app)
    assert client.get("/monitor/confirm?t=nonsense").status_code == 400
    assert client.get("/monitor/stop").status_code == 400
