"""
The public survey page: how well Azerbaijani websites do on SaytYoxla's passive checks.

Only aggregate numbers are published (web/survey_stats.json). The list of scanned sites and
their individual results stay private; owners can check their own site on the home page.

    page("az") -> HTML for /hesabat/, page("en") -> /en/report/, page("ru") -> /ru/otchet/
"""

from __future__ import annotations

import json
from functools import lru_cache
from html import escape
from pathlib import Path

from scanner import i18n
from web.pages import ICON_LINKS, SKIP, footer_links

SITE ="https://saytyoxla.vercel.app"
DATA = Path(__file__).parent / "survey_stats.json"
PATHS = {"az": "/hesabat/", "en": "/en/report/", "ru": "/ru/otchet/"}
HOMES = {"az": "/", "en": "/en/", "ru": "/ru/"}

SECTORS = {
    "bank": ("Banklar", "Banks", "Банки"),
    "uni": ("Universitetlər", "Universities", "Университеты"),
    "gov": ("Dövlət qurumları", "Government", "Госорганы"),
    "news": ("Xəbər saytları", "News sites", "Новостные сайты"),
    "shop": ("Onlayn mağazalar", "Online shops", "Интернет-магазины"),
    "tel": ("Telekom operatorları", "Telecom operators", "Операторы связи"),
    "health": ("Səhiyyə", "Healthcare", "Медицина"),
}

# check id -> the Azerbaijani title the scanner uses (translated through scanner.i18n)
CHECKS = {
    "https": "Təhlükəsiz bağlantı (HTTPS)", "http_redirect": "HTTP-dən HTTPS-ə yönləndirmə",
    "hsts": "Məcburi HTTPS (HSTS)", "framing": "Saxta çərçivəyə qarşı qoruma",
    "nosniff": "Fayl tipinin qorunması", "csp": "Kənar skriptlərə nəzarət (CSP)",
    "referrer": "Keçid məlumatının qorunması", "disclosure": "Proqram versiyasının gizlədilməsi",
    "mixed": "Qarışıq məzmun", "spf": "E-poçt göndərən icazəsi (SPF)",
    "dmarc": "Saxta məktuba qarşı qoruma (DMARC)", "speed": "Serverin cavab sürəti",
    "viewport": "Telefona uyğunluq", "title": "Səhifə başlığı", "description": "Google üçün təsvir",
    # measured since the page-weight checks (scanner/assets.py); statistics gathered before them have no such rows
    "weight": "Səhifənin tam çəkisi", "img_weight": "Ağır şəkillər", "blocking": "Səhifəni gözlədən skriptlər",
    "asset_cache": "Faylların brauzerdə saxlanması (keş)", "compression": "Səhifənin sıxılması (gzip)",
    "http2": "Sürətli protokol (HTTP/2)",
}

MONTHS = {
    "az": ["yanvar", "fevral", "mart", "aprel", "may", "iyun", "iyul", "avqust", "sentyabr", "oktyabr", "noyabr", "dekabr"],
    "en": ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
           "November", "December"],
    "ru": ["января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября",
           "ноября", "декабря"],
}


def L(lang: str, az: str, en: str, ru: str) -> str:
    return {"az": az, "en": en, "ru": ru}[lang]


@lru_cache(maxsize=1)
def stats() -> dict:
    return json.loads(DATA.read_text(encoding="utf-8"))


def benchmarks() -> dict:
    """Check id -> % of surveyed sites that pass it, shown next to a site's own problems. Empty until published."""
    return stats()["all"]["pass"] if DATA.exists() else {}


def sample_size() -> int:
    """How many sites the benchmarks are measured on."""
    return stats()["all"]["n"] if DATA.exists() else 0


def has_csp(m: dict) -> int:
    """% of sites with any Content-Security-Policy. Statistics from before the count was kept only know how many pass."""
    return 100 - m.get("csp_missing", 100 - m["pass"]["csp"])


def date_text(iso: str, lang: str) -> str:
    y, m, d = (int(x) for x in iso.split("-"))
    return f"{d} {MONTHS[lang][m - 1]} {y}"


def _bars(p: dict, lang: str) -> str:
    rows = sorted(p.items(), key=lambda kv: kv[1])
    out = []
    for cid, v in rows:
        name = escape(i18n.text(CHECKS[cid], lang))
        out.append(f'<li><span class="bl">{name}</span>'
                   f'<span class="bt" role="img" aria-label="{v}%"><i style="width:{max(v, 1)}%"></i></span>'
                   f'<b class="bv">{v}%</b></li>')
    return "\n".join(out)


def _table(s: dict, lang: str) -> str:
    head = [L(lang, "Sahə", "Sector", "Сфера"), L(lang, "Sayt", "Sites", "Сайтов"),
            L(lang, "Orta bal", "Avg. score", "Средний балл"), "HSTS", "CSP",
            L(lang, "DMARC (bloklayır)", "DMARC (enforced)", "DMARC (блокирует)"), "SPF"]
    rows = []
    for key, m in sorted(s["sectors"].items(), key=lambda kv: -kv[1]["avg"]):
        name = SECTORS[key][("az", "en", "ru").index(lang)]
        p = m["pass"]
        rows.append(f"<tr><th scope=\"row\">{name}</th><td>{m['n']}</td><td><b>{m['avg']}</b></td>"
                    f"<td>{p['hsts']}%</td><td>{has_csp(m)}%</td><td>{p['dmarc']}%</td><td>{p['spf']}%</td></tr>")
    a = s["all"]
    rows.append(f"<tr class=\"tot\"><th scope=\"row\">{L(lang, 'Hamısı', 'All', 'Все')}</th><td>{a['n']}</td>"
                f"<td><b>{a['avg']}</b></td><td>{a['pass']['hsts']}%</td><td>{has_csp(a)}%</td>"
                f"<td>{a['pass']['dmarc']}%</td><td>{a['pass']['spf']}%</td></tr>")
    ths = "".join(f'<th scope="col">{h}</th>' for h in head)
    return f"<table><thead><tr>{ths}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def _grades(a: dict, lang: str) -> str:
    n = a["n"]
    cells = []
    for g in "ABCDF":
        k = a["grades"].get(g, 0)
        cells.append(f'<li><b class="g g{g}">{g}</b><span>{k}</span><small>{round(100 * k / n)}%</small></li>')
    return "".join(cells)


def page(lang: str) -> str:
    s = stats()
    a, p = s["all"], s["all"]["pass"]
    when = date_text(s["dates"][-1], lang)
    blocked, unreach = s["skipped"].get("blocked", 0), s["skipped"].get("unreachable", 0)
    tls = s["skipped"].get("tls", 0)
    ranked = sorted(s["sectors"].items(), key=lambda kv: -kv[1]["avg"])
    sname = lambda k: SECTORS[k][("az", "en", "ru").index(lang)]
    (best, bm), (worst, wm) = ranked[0], ranked[-1]
    # sectors where at least 90% / under 50% of sites block fake e-mails (DMARC enforced)
    good = [k for k, m in ranked if m["pass"]["dmarc"] >= 90]
    weak = [k for k, m in sorted(s["sectors"].items(), key=lambda kv: kv[1]["pass"]["dmarc"]) if m["pass"]["dmarc"] < 50]

    def names(keys, i, joiner):
        n = [SECTORS[k][i].lower() for k in keys]
        return (", ".join(n[:-1]) + joiner + n[-1]) if len(n) > 1 else (n[0] if n else "")
    good_az, weak_az = names(good, 0, " və ").capitalize(), names(weak, 0, " və ")
    good_en, weak_en = names(good, 1, " and ").capitalize(), names(weak, 1, " and ")
    good_ru, weak_ru = names(good, 2, " и "), names(weak, 2, " и ")
    no_dmarc = a["dmarc_missing"] + a["dmarc_none"]
    # The heading must follow the numbers: five points between the best and the worst sector is not "a lot"
    wide = bm["avg"] - wm["avg"] >= 10
    gap_az = "Sahələr arasında fərq böyükdür." if wide else "Orta bal sahələr üzrə yaxındır, qoruma ayarları isə fərqlidir."
    gap_en = "Sectors differ a lot." if wide else "Average scores are close across sectors, but the protections differ."
    gap_ru = "Сферы сильно различаются." if wide else "Средний балл по сферам близок, но защита различается."
    # Sites that failed on TLS never reached the percentages, so "100% on HTTPS" must say so where it is claimed
    tls_note = L(lang,
                 f" Daha {tls} sayt isə TLS/sertifikat xətası ilə ümumiyyətlə açılmadı və bu faizə daxil deyil.",
                 f" Another {tls} did not open at all because of a TLS/certificate error and are not in this percentage.",
                 f" Ещё {tls} сайтов вообще не открылись из-за ошибки TLS/сертификата и в этот процент не входят.") if tls else ""
    # The stored scores come from before the score limits (scanner/report.py); only a new scan can update them
    scale_note = L(lang,
                   " Bal və qiymətlər köhnə bal şkalası ilə hesablanıb, indiki yoxlamada bu saytların balı daha aşağı ola bilər.",
                   " Scores and grades use the previous scale; the same sites may score lower in a check today.",
                   " Баллы и оценки рассчитаны по прежней шкале; сегодня у этих сайтов балл может быть ниже.") if s.get("old_scale") else ""
    sectors =", ".join(SECTORS[k][("az", "en", "ru").index(lang)].lower() for k in SECTORS if k in s["sectors"])

    title = L(lang, f"Azərbaycan saytlarının təhlükəsizlik vəziyyəti: {a['n']} sayt yoxlandı",
              f"How secure are Azerbaijani websites? {a['n']} sites checked",
              f"Насколько защищены сайты Азербайджана: проверено {a['n']} сайтов")
    desc = L(lang,
             f"{a['n']} Azərbaycan saytının passiv yoxlaması: banklar, dövlət, xəbər saytları. "
             f"{100 - has_csp(a)}%-ində CSP, {100 - p['hsts']}%-ində HSTS yoxdur; {no_dmarc}%-i saxta məktubları bloklamır.",
             f"A passive check of {a['n']} Azerbaijani websites: banks, universities, government, news and more. "
             f"{100 - has_csp(a)}% have no CSP, {100 - p['hsts']}% no HSTS, and {no_dmarc}% do not block fake e-mails.",
             f"Пассивная проверка {a['n']} сайтов Азербайджана: банки, университеты, госорганы, СМИ и другие. "
             f"У {100 - has_csp(a)}% нет CSP, у {100 - p['hsts']}% нет HSTS, {no_dmarc}% не блокируют поддельные письма.")

    tiles = [
        (f"{a['avg']}", L(lang, "orta bal (100-dən)", "average score (out of 100)", "средний балл (из 100)")),
        (f"{100 - has_csp(a)}%", L(lang, "saytda kənar skriptlərə nəzarət (CSP) yoxdur",
                                 "have no control over third-party scripts (CSP)",
                                 "без контроля сторонних скриптов (CSP)")),
        (f"{no_dmarc}%", L(lang, "domen adından göndərilən saxta məktubları bloklamır (DMARC)",
                           "do not block fake e-mails sent in their name (DMARC)",
                           "не блокируют поддельные письма от своего имени (DMARC)")),
        (f"{100 - p['hsts']}%", L(lang, "brauzerə yalnız HTTPS istifadə etməyi əmr etmir (HSTS)",
                                  "do not force browsers to use HTTPS only (HSTS)",
                                  "не заставляют браузер использовать только HTTPS (HSTS)")),
    ]
    tiles_html = "".join(f'<div class="tile"><b>{v}</b><span>{t}</span></div>' for v, t in tiles)

    findings = L(
        lang,
        [f"<b>Əsaslar yaxşıdır.</b> Açılan {a['n']} saytın {p['https']}%-i HTTPS ilə işləyir, {p['viewport']}%-i telefona uyğundur.{tls_note}",
         f"<b>Əlavə qoruma qatları zəifdir.</b> Yalnız {has_csp(a)}% CSP, {p['hsts']}% HSTS, {p['framing']}% saxta çərçivəyə qarşı qoruma istifadə edir. Bunlar pulsuzdur və bir neçə sətirlik server ayarıdır.",
         f"<b>E-poçt qoruması sahədən asılıdır.</b> Saytların {a['dmarc_missing']}%-ində DMARC ümumiyyətlə yoxdur, {a['dmarc_none']}%-ində isə yalnız müşahidə rejimindədir. {good_az} bu sahədə yaxşıdır, {weak_az} isə geri qalır: onların adından saxta məktub göndərmək asandır.",
         f"<b>{gap_az}</b> Ən yüksək orta bal: {sname(best).lower()} ({bm['avg']}), ən aşağı: {sname(worst).lower()} ({wm['avg']}). {sname(worst)} arasında DMARC-ı saxta məktubları bloklayan sayt payı cəmi {wm['pass']['dmarc']}%-dir.",
         f"<b>Google üçün təsvir.</b> Saytların yalnız {p['description']}%-ində uyğun uzunluqda meta description var."],
        [f"<b>The basics are in place.</b> Of the {a['n']} sites that opened, {p['https']}% use HTTPS and {p['viewport']}% are mobile-friendly.{tls_note}",
         f"<b>Extra layers of protection are thin.</b> Only {has_csp(a)}% use CSP, {p['hsts']}% HSTS and {p['framing']}% clickjacking protection. All of these are free, a few lines of server configuration.",
         f"<b>E-mail protection depends on the sector.</b> {a['dmarc_missing']}% of the sites have no DMARC at all and {a['dmarc_none']}% only monitor. {good_en} do well here, while {weak_en} lag behind: fake e-mails in their name are easy to send.",
         f"<b>{gap_en}</b> The highest average score is in {sname(best).lower()} ({bm['avg']}), the lowest in {sname(worst).lower()} ({wm['avg']}). Among {sname(worst).lower()}, only {wm['pass']['dmarc']}% have a DMARC policy that blocks fake e-mails.",
         f"<b>Descriptions for Google.</b> Only {p['description']}% have a meta description of a useful length."],
        [f"<b>Основа в порядке.</b> Из {a['n']} открывшихся сайтов {p['https']}% работают по HTTPS, {p['viewport']}% адаптированы под телефон.{tls_note}",
         f"<b>Дополнительной защиты мало.</b> CSP используют лишь {has_csp(a)}%, HSTS — {p['hsts']}%, защиту от кликджекинга — {p['framing']}%. Всё это бесплатно и занимает несколько строк настроек сервера.",
         f"<b>Защита почты зависит от сферы.</b> У {a['dmarc_missing']}% сайтов DMARC нет вовсе, у {a['dmarc_none']}% он только в режиме наблюдения. Здесь хорошо справляются: {good_ru}; отстают: {weak_ru} — от их имени легко отправить поддельное письмо.",
         f"<b>{gap_ru}</b> Самый высокий средний балл — {sname(best).lower()} ({bm['avg']}), самый низкий — {sname(worst).lower()} ({wm['avg']}). В сфере «{sname(worst)}» DMARC, блокирующий поддельные письма, есть лишь у {wm['pass']['dmarc']}% сайтов.",
         f"<b>Описание для Google.</b> Только у {p['description']}% есть meta description подходящей длины."],
    )
    if {"weight", "img_weight", "asset_cache"} <= set(p):       # measured since the page-weight checks; older statistics have no such numbers
        findings.append(L(
            lang,
            f"<b>Sürət.</b> Saytların {p['weight']}%-nin əsas səhifəsi faylları ilə birlikdə 2 MB-dan yüngüldür, {p['img_weight']}%-ində 500 KB-dan ağır şəkil yoxdur, {p['asset_cache']}%-i öz fayllarını brauzerdə keşləyir.",
            f"<b>Speed.</b> For {p['weight']}% of the sites the home page with its files weighs under 2 MB, {p['img_weight']}% have no image over 500 KB, and {p['asset_cache']}% let the browser cache their own files.",
            f"<b>Скорость.</b> У {p['weight']}% сайтов главная страница вместе с файлами легче 2 МБ, у {p['img_weight']}% нет изображений тяжелее 500 КБ, {p['asset_cache']}% кэшируют свои файлы в браузере."))
    findings_html = "".join(f"<li>{x}</li>" for x in findings)

    method = L(
        lang,
        f"{when} tarixində {s['scanned']} açıq Azərbaycan saytı ({sectors}) SaytYoxla ilə yoxlanıldı. "
        f"Hər saytın əsas səhifəsi və onun yüklədiyi fayllar bir dəfə açıldı, sertifikat və açıq DNS qeydləri (SPF, DMARC) oxundu, "
        f"heç nə sındırılmağa çalışılmadı. Avtomatik yoxlamaları bloklayan {blocked} sayt və açılmayan {unreach} sayt "
        f"(onlardan {tls}-i TLS/sertifikat xətası ilə) nəticəyə daxil edilmədi; qalan {a['n']} saytın nəticəsi göstərilir. Bu, tam təhlükəsizlik auditi deyil: "
        f"yalnız kənardan görünən ayarlar yoxlanılır. Ayrı-ayrı saytların adları dərc olunmur.",
        f"On {when}, {s['scanned']} public Azerbaijani websites ({sectors}) were checked with SaytYoxla. "
        f"For each site the home page and the files it loads were opened once, and the certificate and public DNS records "
        f"(SPF, DMARC) were read; nothing was probed or attacked. {blocked} sites that block automated checks and "
        f"{unreach} that did not open ({tls} of them with a TLS/certificate error) were left out; the results cover the remaining {a['n']}. This is not a full "
        f"security audit: it only covers settings visible from outside. Individual sites are not named.",
        f"{when} с помощью SaytYoxla проверено {s['scanned']} открытых сайтов Азербайджана ({sectors}). "
        f"У каждого сайта один раз открывались главная страница и файлы, которые она загружает, читались сертификат и открытые "
        f"DNS-записи (SPF, DMARC); ничего не взламывалось. {blocked} сайтов, блокирующих автоматические проверки, "
        f"и {unreach} неоткрывшихся (из них {tls} — с ошибкой TLS/сертификата) в итог не вошли; результаты — по остальным {a['n']}. Это не полный аудит "
        f"безопасности: проверяются только настройки, видимые снаружи. Названия отдельных сайтов не публикуются.",
    )

    # A sector where most of the listed sites did not answer rests on few sites, and the page says which
    thin = [k for k in SECTORS if k in s["sectors"] and 2 * s["sectors"][k]["n"] < s.get("sector_sizes", {}).get(k, 0)]
    if thin:
        i = ("az", "en", "ru").index(lang)
        named = ", ".join(f"{SECTORS[k][i].lower()} ({s['sectors'][k]['n']}/{s['sector_sizes'][k]})" for k in thin)
        method += L(lang,
                    f" Bu sahələrdə saytların yarıdan çoxu avtomatik yoxlamanı blokladı və ya ona cavab vermədi, ona görə nəticə az sayta əsaslanır: {named}.",
                    f" In these sectors more than half of the sites blocked the automated check or did not answer it, so the result rests on few sites: {named}.",
                    f" В этих сферах больше половины сайтов заблокировали автоматическую проверку или не ответили на неё, поэтому результат основан на малом числе сайтов: {named}.")

    alt = "\n".join(f'<link rel="alternate" hreflang="{l}" href="{SITE}{u}">' for l, u in PATHS.items())
    langs = "".join(
        f'<a href="{PATHS[l]}" hreflang="{l}" lang="{l}"{" aria-current=page" if l == lang else ""}>{l.upper()}</a>'
        for l in PATHS)
    ld = json.dumps({
        "@context": "https://schema.org", "@type": "Article", "headline": title, "description": desc,
        "inLanguage": lang, "datePublished": s["dates"][-1], "url": SITE + PATHS[lang],
        "author": {"@type": "Person", "name": "Ziya Azizov", "url": "https://www.linkedin.com/in/ziyaazizov"},
        "publisher": {"@type": "Organization", "name": "SaytYoxla", "url": SITE + "/"},
    }, ensure_ascii=False)
    cta_home = HOMES[lang]

    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title) if len(title) > 58 else escape(title) + " | SaytYoxla"}</title>
<meta name="description" content="{escape(desc)}">
<link rel="canonical" href="{SITE}{PATHS[lang]}">
{alt}
<link rel="alternate" hreflang="x-default" href="{SITE}{PATHS['az']}">
<meta property="og:type" content="article">
<meta property="og:locale" content="{ {"az": "az_AZ", "en": "en_US", "ru": "ru_RU"}[lang] }">
<meta property="og:title" content="{escape(title)}">
<meta property="og:description" content="{escape(desc)}">
<meta property="og:url" content="{SITE}{PATHS[lang]}">
<meta property="og:image" content="{SITE}/static/og-image.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="theme-color" content="#0f2a4a">
<script type="application/ld+json">{ld}</script>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%230f2a4a'/%3E%3Cpath d='M18 33l9 9 19-20' fill='none' stroke='%2334d399' stroke-width='7' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
{ICON_LINKS}
<link rel="preload" href="/static/fonts/inter-4-latin.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="/static/fonts.css">
<style>
:root{{--bg:#f5f7fb;--surface:#fff;--line:#e3e8f0;--line-2:#cfd7e3;--ink:#0f1b2d;--ink-2:#3d4b60;--muted:#5b6779;
--brand:#0f2a4a;--brand-2:#1d4ed8;--track:#e6ebf3;--font:Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);font:400 16px/1.6 var(--font);-webkit-font-smoothing:antialiased}}
a{{color:var(--brand-2)}}
.wrap{{max-width:880px;margin:0 auto;padding:0 16px}}
.top{{background:var(--surface);border-bottom:1px solid var(--line)}}
.top .wrap{{display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:62px;flex-wrap:wrap}}
.brand{{display:flex;align-items:center;gap:10px;color:var(--brand);text-decoration:none;font:800 20px/1 var(--font)}}
.brand b{{color:var(--brand-2)}}
.mark{{width:34px;height:34px;border-radius:10px;background:var(--brand);display:grid;place-items:center}}
.langs{{display:flex;border:1px solid var(--line-2);border-radius:10px;overflow:hidden}}
.langs a{{padding:8px 9px;font:700 13px/1 var(--font);color:var(--ink-2);text-decoration:none}}
.langs a+a{{border-left:1px solid var(--line-2)}}
.langs a[aria-current]{{background:var(--brand);color:#fff}}
h1{{font-size:clamp(28px,5vw,40px);line-height:1.15;letter-spacing:-.02em;margin:36px 0 12px}}
h2{{font-size:22px;letter-spacing:-.01em;margin:40px 0 6px}}
.lead{{color:var(--ink-2);font-size:18px;margin:0 0 6px}}
.meta{{color:var(--muted);font-size:14px;margin:0}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:24px 0 0}}
.tile{{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:16px}}
.tile b{{display:block;font-size:34px;line-height:1.1;letter-spacing:-.02em;color:var(--brand)}}
.tile span{{display:block;color:var(--ink-2);font-size:14px;margin-top:6px}}
.card{{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:18px}}
.sub{{color:var(--muted);font-size:14px;margin:0 0 14px}}
.bars{{list-style:none;margin:0;padding:0;display:grid;gap:10px}}
.bars li{{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr) 44px;align-items:center;gap:12px}}
.bl{{font-size:14px;color:var(--ink)}}
.bt{{height:12px;background:var(--track);border-radius:4px;overflow:hidden}}
.bt i{{display:block;height:100%;background:var(--brand-2);border-radius:0 4px 4px 0}}
.bv{{font-size:14px;text-align:right;font-variant-numeric:tabular-nums}}
@media (max-width:560px){{.bars li{{grid-template-columns:1fr 44px}}.bl{{grid-column:1/-1;margin-bottom:-6px}}}}
.grades{{list-style:none;margin:0;padding:0;display:flex;gap:10px;flex-wrap:wrap}}
.grades li{{display:flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:8px 12px}}
.grades small{{color:var(--muted)}}
.g{{width:28px;height:28px;border-radius:8px;color:#fff;display:grid;place-items:center;font-size:14px}}
.gA{{background:#047857}}.gB{{background:#15803d}}.gC{{background:#b45309}}.gD{{background:#c2410c}}.gF{{background:#b91c1c}}
.tw{{overflow-x:auto;background:var(--surface);border:1px solid var(--line);border-radius:14px}}
table{{border-collapse:collapse;width:100%;font-size:14px;font-variant-numeric:tabular-nums}}
th,td{{padding:10px 12px;text-align:right;border-bottom:1px solid var(--line);white-space:nowrap}}
th:first-child{{text-align:left}}
thead th{{color:var(--muted);font-weight:600}}
tr.tot th,tr.tot td{{border-bottom:0;background:var(--bg)}}
.find{{padding-left:20px;margin:0}} .find li{{margin:0 0 10px}}
.cta{{background:var(--brand);color:#fff;border-radius:16px;padding:22px;margin:40px 0 0;display:flex;gap:16px;align-items:center;justify-content:space-between;flex-wrap:wrap}}
.cta h2{{margin:0 0 4px;font-size:20px}} .cta p{{margin:0;color:#cfdbee}}
.btn{{display:inline-block;background:#f59e0b;color:#231500;font-weight:700;text-decoration:none;padding:12px 18px;border-radius:12px}}
.method{{color:var(--ink-2);font-size:15px}}
footer{{color:var(--muted);font-size:14px;padding:32px 0 40px}}
footer a{{display:inline-block;padding:13px 4px}}
.skip{{position:absolute;left:12px;top:-80px;background:#1d4ed8;color:#fff;padding:12px 16px;border-radius:10px;font-weight:700;text-decoration:none}}
.skip:focus{{top:8px}}
@media (max-width:640px){{.langs a{{display:inline-flex;align-items:center;justify-content:center;min-width:40px;min-height:44px;padding:0 4px}}}}
@media screen and (prefers-color-scheme:dark){{
:root{{color-scheme:dark;--bg:#0b1220;--surface:#131c2e;--line:#26324a;--line-2:#3a4a66;--ink:#e8edf6;--ink-2:#b7c2d6;--muted:#98a6bd;--brand:#1c3a63;--brand-2:#8ab4ff;--track:#26324a}}
.brand{{color:var(--ink)}}
.tile b{{color:var(--ink)}}
}}
</style>
</head>
<body>
<a class="skip" href="#main">{SKIP[lang]}</a>
<header class="top"><div class="wrap">
  <a class="brand" href="{cta_home}"><span class="mark"><svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path d="M9.5 16.2 5.3 12l-1.4 1.4 5.6 5.6 11-11-1.4-1.4z" fill="#34d399"/></svg></span><span>Sayt<b>Yoxla</b></span></a>
  <nav class="langs" aria-label="{L(lang, 'Dil', 'Language', 'Язык')}">{langs}</nav>
</div></header>
<main id="main" class="wrap">
  <h1>{escape(title)}</h1>
  <p class="lead">{L(lang, "Banklar, universitetlər, dövlət qurumları, xəbər saytları və onlayn mağazalar kənardan nə dərəcədə qorunur?",
                     "How well are banks, universities, government bodies, news sites and online shops protected, as seen from outside?",
                     "Насколько хорошо защищены снаружи банки, университеты, госорганы, СМИ и интернет-магазины?")}</p>
  <p class="meta">{L(lang, "Yoxlama tarixi", "Checked on", "Дата проверки")}: {when} · {a['n']} {L(lang, "sayt", "sites", "сайтов")} · {L(lang, "Müəllif", "Author", "Автор")}: Ziya Azizov</p>

  <div class="tiles">{tiles_html}</div>

  <h2>{L(lang, "Əsas nəticələr", "Key findings", "Главные выводы")}</h2>
  <ul class="find">{findings_html}</ul>

  <h2>{L(lang, "Hər yoxlamadan keçən saytların payı", "Share of sites that pass each check", "Доля сайтов, прошедших каждую проверку")}</h2>
  <p class="sub">{L(lang, f"{a['n']} saytdan; ən zəif yoxlamalar yuxarıdadır. SPF və DMARC öz domeni olan saytlar üzrə hesablanıb.",
                   f"Out of {a['n']} sites; the weakest checks are at the top. SPF and DMARC are counted for sites on their own domain.",
                   f"Из {a['n']} сайтов; самые слабые проверки вверху. SPF и DMARC считаются для сайтов на собственном домене.")}</p>
  <div class="card"><ul class="bars">{_bars(p, lang)}</ul></div>

  <h2>{L(lang, "Qiymətlərin bölgüsü", "Grade distribution", "Распределение оценок")}</h2>
  <p class="sub">{L(lang, "A — 90 və yuxarı, B — 75+, C — 60+, D — 40+, F — 40-dan aşağı.",
                   "A is 90 and above, B 75+, C 60+, D 40+, F below 40.",
                   "A — 90 и выше, B — 75+, C — 60+, D — 40+, F — ниже 40.")}{scale_note}</p>
  <ul class="grades">{_grades(a, lang)}</ul>

  <h2>{L(lang, "Sahələr üzrə", "By sector", "По сферам")}</h2>
  <p class="sub">{L(lang, "Orta bal və əsas qoruma ayarı olan saytların payı. Az sayt olan sahələrdə faizləri ehtiyatla oxuyun.", "Average score and the share of sites with each key protection. In sectors with few sites, read the percentages with care.",
                   "Средний балл и доля сайтов с каждой основной защитой. Где сайтов мало, проценты стоит читать осторожно.")}</p>
  <div class="tw" tabindex="0">{_table(s, lang)}</div>

  <div class="cta">
    <div><h2>{L(lang, "Öz saytınız necədir?", "How does your site do?", "А как ваш сайт?")}</h2>
    <p>{L(lang, "Eyni yoxlamanı 30 saniyəyə pulsuz edin və hər problemin həllini görün.",
          "Run the same check for free in 30 seconds and see how to fix each problem.",
          "Пройдите ту же проверку бесплатно за 30 секунд и узнайте, как исправить каждую проблему.")}</p></div>
    <a class="btn" href="{cta_home}">{L(lang, "Saytımı yoxla", "Check my site", "Проверить мой сайт")}</a>
  </div>

  <h2>{L(lang, "Necə yoxlandı", "How it was checked", "Как проверяли")}</h2>
  <p class="method">{method}</p>
</main>
<footer><div class="wrap">SaytYoxla · <a href="https://ayfar.dev/">ayfar.dev</a> · <a href="https://www.linkedin.com/in/ziyaazizov">Ziya Azizov</a> · {footer_links(lang)}</div></footer>
</body>
</html>
"""
