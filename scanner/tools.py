"""
Single-purpose checks for the Tools page. They never open the site's page, so they also work on sites
whose bot protection turns the full scan away: the SSL tool only reads the certificate, the e-mail tool
only reads public DNS records.
"""

from __future__ import annotations

from dataclasses import asdict

from scanner import checks, fetch
from scanner.models import Context
from scanner.safety import UnsafeTarget, check_host_is_public, normalize, resolve_public

NO_HTTPS = "Bu ünvanda təhlükəsiz bağlantı (HTTPS) açılmadı. Sayt HTTPS işlətmir və ya sertifikat oxuna bilmədi."


def _host(raw: str) -> str:
    return normalize(raw).split("/")[2]


def _result(kind: str, host: str, findings: list, facts: dict) -> dict:
    return {"kind": kind, "host": host, "summary": "", "findings": [asdict(f) for f in findings], "facts": facts}


def ssl_check(raw: str) -> dict:
    host = _host(raw)
    cert = fetch.cert_info(host, resolve_public(host))
    error = cert.get("error")
    # A certificate problem is a sentence with spaces; a failed connection is only an exception's name
    if error and " " not in error:
        raise UnsafeTarget(NO_HTTPS)
    ctx = Context(input_url=f"https://{host}/", final_url=f"https://{host}/", host=host, cert=cert)
    findings = [checks.certificate(ctx, None), checks.tls_version(ctx, None)]
    return _result("ssl", host, findings, {"issuer": cert.get("issuer") or "", "expires": cert.get("expires") or "",
                                           "days_left": cert.get("days_left"), "tls": cert.get("tls") or ""})


def email_check(raw: str) -> dict:
    host = _host(raw)
    domain = fetch.mail_domain(host)
    spf = fetch.txt_records(domain)
    dmarc, parent = fetch.dmarc_records(domain)
    dkim = fetch.dkim_selectors(domain)
    if not spf and not dmarc and not dkim:          # a typo looks just like a domain with no records
        check_host_is_public(host)
    ctx = Context(input_url=f"https://{host}/", final_url=f"https://{host}/", host=host, dkim=dkim,
                  txt_records={"spf": spf, "dmarc": dmarc, "dmarc_parent": parent})
    findings = [checks.spf(ctx, None), checks.dmarc(ctx, None), checks.dkim(ctx, None)]
    return _result("email", domain, findings, {
        "spf": [r for r in spf or [] if r.lower().startswith("v=spf1")],
        "dmarc": [r for r in dmarc or [] if r.lower().startswith("v=dmarc1")],
        "dmarc_parent": parent or "",
        "dkim": dkim or [],
    })


TOOLS = {"ssl": ssl_check, "email": email_check}
