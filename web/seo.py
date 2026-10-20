"""
Search-engine files for SaytYoxla: robots.txt, sitemap.xml, llms.txt and the
Google Search Console HTML-file verification.

Kept free of FastAPI imports so it can be tested on its own.
Set SITE_URL in the environment when the site moves to its own domain.
"""

from __future__ import annotations

import os
import re

SITE_URL = os.getenv("SITE_URL", "https://saytyoxla.onrender.com").rstrip("/")
LASTMOD = "2026-10-20"          # bump when the front page changes

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


def sitemap_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <url>\n    <loc>{SITE_URL}/</loc>\n    <lastmod>{LASTMOD}</lastmod>\n  </url>\n"
        "</urlset>\n"
    )


def llms_txt() -> str:
    return f"""# SaytYoxla — saytı pulsuz yoxlama aləti (Azərbaycan)

> SaytYoxla istənilən saytın təhlükəsizliyini, SSL sertifikatını, e-poçt qorumasını (SPF, DMARC), sürətini və telefona uyğunluğunu 30 saniyəyə pulsuz yoxlayır və nəticəni sadə Azərbaycan dilində izah edir. Qeydiyyat tələb olunmur.

## Nəyi yoxlayır
- Təhlükəsizlik: HTTPS, sertifikatın bitmə tarixi, HTTP→HTTPS yönləndirmə, HSTS, clickjacking qorunması, nosniff, CSP, Referrer-Policy, server versiyasının açıqlanması, qarışıq məzmun
- E-poçt: SPF və DMARC qeydləri (saxta məktublara qarşı)
- Sürət: serverin cavab vaxtı, səhifənin həcmi
- Telefon və Google: viewport, səhifə başlığı (title), təsvir (meta description)

## Necə işləyir
- Nəticə 0–100 bal və A–F qiyməti ilə verilir; hər problemin altında necə düzəldiləcəyi yazılır
- Yalnız açıq məlumatlara baxılır: əsas səhifə bir dəfə açılır, sertifikat və açıq DNS qeydləri oxunur. Gizli yollar yoxlanılmır, heç nə sındırılmağa çalışılmır
- Hesabatı PDF kimi saxlamaq və WhatsApp ilə göndərmək olar

## Kim üçündür
Azərbaycandakı kiçik bizneslər, sayt sahibləri və saytları quran proqramçılar.

## Müəllif
Ziya Azizov — https://www.linkedin.com/in/ziya-azizov-91bba638a

## Səhifələr
- [SaytYoxla]({SITE_URL}/): saytı yoxlama forması, bələdçi və tez-tez verilən suallar
"""


def google_verification(filename: str) -> str | None:
    """Body for an allowed Google verification file such as 'google1a2b3c.html', else None."""
    if filename not in GOOGLE_VERIFY_FILES or not _GOOGLE_NAME.fullmatch(filename):
        return None
    return f"google-site-verification: {filename}"
