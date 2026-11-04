"""
Search-engine files for SaytYoxla: robots.txt, sitemap.xml, llms.txt and the
Google Search Console HTML-file verification.

Kept free of FastAPI imports so it can be tested on its own.
Set SITE_URL in the environment when the site moves to its own domain.
"""

from __future__ import annotations

import os
import re

SITE_URL = os.getenv("SITE_URL", "https://saytyoxla.vercel.app").rstrip("/")
LASTMOD = "2026-11-05"          # bump when the front page changes

# Google Search Console "HTML file" verification. Only the exact file names listed
# here (or in the GOOGLE_VERIFY_FILES env var, comma-separated) are served, so no
# other Google account can claim the site.
GOOGLE_VERIFY_FILES = {"googlebec6d226088bfeac.html"}
GOOGLE_VERIFY_FILES |= {f.strip() for f in os.getenv("GOOGLE_VERIFY_FILES", "").split(",") if f.strip()}
_GOOGLE_NAME = re.compile(r"google[0-9a-f]{8,32}\.html")

# AI and search crawlers we explicitly welcome (everything is allowed anyway;
# naming them makes the intent clear to anyone reading the file).
_BOTS = ["Googlebot", "Bingbot", "GPTBot", "OAI-SearchBot", "ChatGPT-User", "PerplexityBot",
         "ClaudeBot", "Claude-SearchBot", "Google-Extended", "YandexBot"]


def robots_txt() -> str:
    lines = ["User-agent: *", "Allow: /", "Disallow: /api/", ""]
    for bot in _BOTS:
        lines += [f"User-agent: {bot}", "Allow: /", "Disallow: /api/", ""]
    lines.append(f"Sitemap: {SITE_URL}/sitemap.xml")
    return "\n".join(lines) + "\n"


PAGES = ["/", "/en/", "/ru/"]        # the same page in az, en, ru


def sitemap_xml() -> str:
    alts = "".join(f'    <xhtml:link rel="alternate" hreflang="{l}" href="{SITE_URL}{p}"/>\n'
                   for l, p in zip(("az", "en", "ru"), PAGES))
    urls = "".join(f"  <url>\n    <loc>{SITE_URL}{p}</loc>\n    <lastmod>{LASTMOD}</lastmod>\n{alts}  </url>\n"
                   for p in PAGES)
    from web.survey import PATHS as REPORT
    ralts = "".join(f'    <xhtml:link rel="alternate" hreflang="{l}" href="{SITE_URL}{p}"/>\n' for l, p in REPORT.items())
    report = "".join(f"  <url>\n    <loc>{SITE_URL}{p}</loc>\n    <lastmod>{LASTMOD}</lastmod>\n{ralts}  </url>\n"
                     for p in REPORT.values())
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n'
        + urls + report + _info_urls() + "</urlset>\n"
    )


def _info_urls() -> str:
    from web.pages import PATHS as INFO
    from web.pages import TOOLS_PATHS
    out = ""
    for by_lang in [TOOLS_PATHS, *INFO.values()]:
        alts = "".join(f'    <xhtml:link rel="alternate" hreflang="{l}" href="{SITE_URL}{p}"/>\n' for l, p in by_lang.items())
        out += "".join(f"  <url>\n    <loc>{SITE_URL}{p}</loc>\n    <lastmod>{LASTMOD}</lastmod>\n{alts}  </url>\n"
                       for p in by_lang.values())
    return out


def llms_txt() -> str:
    return f"""# SaytYoxla — saytı pulsuz yoxlama aləti (Azərbaycan)

> SaytYoxla istənilən saytın təhlükəsizliyini, SSL sertifikatını, e-poçt qorumasını (SPF, DMARC), sürətini və telefona uyğunluğunu 30 saniyəyə pulsuz yoxlayır və nəticəni sadə Azərbaycan dilində izah edir (nəticə ingilis və rus dilində də var). Qeydiyyat tələb olunmur.

## Nəyi yoxlayır
- Təhlükəsizlik: HTTPS, sertifikatın bitmə tarixi, TLS versiyası, HTTP→HTTPS yönləndirmə, HSTS, clickjacking qorunması, nosniff, CSP-nin keyfiyyəti, Referrer-Policy, cookie qoruması, server versiyasının açıqlanması, qarışıq məzmun
- E-poçt: SPF, DMARC və geniş yayılmış adlarda DKIM qeydləri (saxta məktublara qarşı)
- Sürət: serverin cavab vaxtı, HTML həcmi
- Telefon və Google: viewport, başlıq (title), təsvir, H1, səhifənin dili, canonical, sosial şəbəkə kartı, noindex, robots.txt, sitemap

## Necə işləyir
- Nəticə 0–100 bal və A–F qiyməti ilə verilir; hər problemin altında necə düzəldiləcəyi yazılır
- Yalnız açıq məlumatlara baxılır: əsas səhifə, robots.txt və sitemap.xml bir dəfə açılır, sertifikat və açıq DNS qeydləri oxunur. Gizli yollar yoxlanılmır, heç nə sındırılmağa çalışılmır
- Hesabatı PDF kimi saxlamaq və WhatsApp ilə göndərmək olar

## Kim üçündür
Azərbaycandakı kiçik bizneslər, sayt sahibləri və saytları quran proqramçılar.

## Müəllif
Ziya Azizov — https://www.linkedin.com/in/ziya-azizov-91bba638a

## Səhifələr
- [SaytYoxla]({SITE_URL}/): saytı yoxlama forması, bələdçi və tez-tez verilən suallar
- [Azərbaycan saytlarının təhlükəsizlik vəziyyəti]({SITE_URL}/hesabat/): yüzdən çox açıq saytın passiv yoxlamasının ümumi nəticələri (sayt adları olmadan)
- [Alətlər]({SITE_URL}/aletler/): SSL, DMARC, SPF, DKIM, başlıqlar və cookie-ləri ayrıca yoxlamaq; DMARC, SPF, CSP, başlıqlar, robots.txt, meta teqlər, sitemap, security.txt və yönləndirmə generatorları
- [Haqqımızda]({SITE_URL}/haqqimizda/), [Məxfilik]({SITE_URL}/mexfilik/), [Şərtlər]({SITE_URL}/sertler/)
- [SaytYoxla in English]({SITE_URL}/en/): the same free website check in English
- [SaytYoxla на русском]({SITE_URL}/ru/): та же бесплатная проверка сайта на русском
"""


# IndexNow (Bing, Yandex): this public key file proves we own the site when we ping new URLs.
INDEXNOW_KEY = "078eda7fa1a6336d062cc39d377fe282"


def indexnow_key(filename: str) -> str | None:
    return INDEXNOW_KEY if filename == f"{INDEXNOW_KEY}.txt" else None


def google_verification(filename: str) -> str | None:
    """Body for an allowed Google verification file such as 'google1a2b3c.html', else None."""
    if filename not in GOOGLE_VERIFY_FILES or not _GOOGLE_NAME.fullmatch(filename):
        return None
    return f"google-site-verification: {filename}"
