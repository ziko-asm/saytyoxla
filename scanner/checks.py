"""
Individual checks. Each takes the collected Context and returns one Finding.
All text is plain Azerbaijani for business owners, not engineers.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

from scanner.models import FAIL, INFO, OK, WARN, Context, Finding

SEC, MAIL, SPEED, SEO = "Təhlükəsizlik", "E-poçt", "Sürət", "Mobil və Google"


class _Page(HTMLParser):
    """Pulls the few things we need out of the HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._in_title = "", False
        self.meta = {}
        self.insecure = set()

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "meta" and a.get("name"):
            self.meta[a["name"].lower()] = a.get("content", "")
        if tag in ("script", "img", "iframe", "source", "video", "audio"):
            url = a.get("src", "")
        elif tag == "link" and set(a.get("rel", "").lower().split()) & {"stylesheet", "icon"}:
            url = a.get("href", "")
        else:
            url = ""
        if url.startswith("http://"):
            self.insecure.add(url)

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def parse(html: str) -> _Page:
    p = _Page()
    p.feed(html)
    p.title = p.title.strip()
    return p


# ---------------------------------------------------------------- security
def https_used(ctx: Context, page) -> Finding:
    ok = urlsplit(ctx.final_url).scheme == "https"
    return Finding("https", SEC, "Təhlükəsiz bağlantı (HTTPS)", OK if ok else FAIL,
                   "Sayt şifrələnmiş HTTPS bağlantısı ilə açılır." if ok else
                   "Sayt şifrəsiz (http) açılır. Brauzerlər onu \"Təhlükəli deyil\" kimi göstərir.",
                   "" if ok else "Hostinq panelindən pulsuz SSL sertifikatı (Let's Encrypt) qoşun.", 20)


def http_redirect(ctx: Context, page) -> Finding:
    v = ctx.http_to_https
    if v is None:
        return Finding("http_redirect", SEC, "HTTP-dən HTTPS-ə yönləndirmə", INFO,
                       "http:// ünvanı yoxlanıla bilmədi.")
    return Finding("http_redirect", SEC, "HTTP-dən HTTPS-ə yönləndirmə", OK if v else WARN,
                   "http:// ilə yazanlar avtomatik təhlükəsiz versiyaya keçir." if v else
                   "Ünvanı http:// ilə yazan ziyarətçi şifrəsiz versiyada qalır.",
                   "" if v else "Serverdə bütün http sorğularını https-ə yönləndirin (301).", 8)


def certificate(ctx: Context, page) -> Finding:
    c = ctx.cert
    if not c:
        return Finding("cert", SEC, "SSL sertifikatı", INFO, "Sertifikat yoxlanılmadı (sayt https deyil).")
    if c.get("error"):
        return Finding("cert", SEC, "SSL sertifikatı", FAIL,
                       f"Sertifikat etibarsızdır ({c['error']}). Ziyarətçilər xəbərdarlıq görür.",
                       "Sertifikatı yeniləyin və domen adına uyğun olduğunu yoxlayın.", 20)
    d = c["days_left"]
    if d < 7:
        st, txt = FAIL, f"Sertifikatın vaxtı {d} gün sonra bitir."
    elif d < 21:
        st, txt = WARN, f"Sertifikatın vaxtı {d} gün sonra bitir."
    else:
        st, txt = OK, f"Sertifikat etibarlıdır, {d} gün qalıb ({c['expires']})."
    return Finding("cert", SEC, "SSL sertifikatı", st, txt,
                   "" if st == OK else "Sertifikatın avtomatik yenilənməsini qurun.", 15)


def _header_check(fid, title, header, good_detail, bad_detail, fix, weight):
    def check(ctx: Context, page) -> Finding:
        present = header in ctx.headers
        return Finding(fid, SEC, title, OK if present else WARN,
                       good_detail if present else bad_detail, "" if present else fix, weight)
    return check


hsts = _header_check("hsts", "Məcburi HTTPS (HSTS)", "strict-transport-security",
                     "Brauzerlərə sayta yalnız HTTPS ilə girmək əmr olunub.",
                     "Brauzerlərə yalnız HTTPS istifadə etmək əmri verilməyib.",
                     "Server cavabına Strict-Transport-Security başlığını əlavə edin.", 6)
nosniff = _header_check("nosniff", "Fayl tipinin qorunması", "x-content-type-options",
                        "Brauzerin faylları səhv tipdə açması qadağandır.",
                        "X-Content-Type-Options başlığı yoxdur.",
                        "Server cavabına \"X-Content-Type-Options: nosniff\" əlavə edin.", 4)
referrer = _header_check("referrer", "Keçid məlumatının qorunması", "referrer-policy",
                         "Ziyarətçinin hansı səhifədən gəldiyi digər saytlara ötürülmür.",
                         "Referrer-Policy başlığı yoxdur.",
                         "Server cavabına \"Referrer-Policy: strict-origin-when-cross-origin\" əlavə edin.", 2)


def framing(ctx: Context, page) -> Finding:
    ok = "x-frame-options" in ctx.headers or "frame-ancestors" in ctx.headers.get("content-security-policy", "")
    return Finding("framing", SEC, "Saxta çərçivəyə qarşı qoruma", OK if ok else WARN,
                   "Sayt başqa saytın içində gizli açıla bilməz." if ok else
                   "Sayt başqa saytın içinə yerləşdirilib istifadəçini aldatmaq üçün istifadə oluna bilər.",
                   "" if ok else "Server cavabına \"X-Frame-Options: SAMEORIGIN\" əlavə edin.", 5)


def csp(ctx: Context, page) -> Finding:
    ok = "content-security-policy" in ctx.headers
    return Finding("csp", SEC, "Kənar skriptlərə nəzarət (CSP)", OK if ok else WARN,
                   "Saytda hansı skriptlərin işləyə biləcəyi məhdudlaşdırılıb." if ok else
                   "Saytda kənar skriptlərə nəzarət qaydası (CSP) yoxdur.",
                   "" if ok else "Content-Security-Policy başlığını əvvəlcə report-only rejimində qurun.", 4)


VERSION_RE = re.compile(r"\d+\.\d+")


def disclosure(ctx: Context, page) -> Finding:
    leaks = [f"{h}: {ctx.headers[h]}" for h in ("server", "x-powered-by", "x-aspnet-version")
             if h in ctx.headers and VERSION_RE.search(ctx.headers[h])]
    gen = page.meta.get("generator", "")
    if VERSION_RE.search(gen):
        leaks.append(f"generator: {gen}")
    ok = not leaks
    return Finding("disclosure", SEC, "Proqram versiyasının gizlədilməsi", OK if ok else WARN,
                   "Server və sayt proqramlarının versiyaları açıq göstərilmir." if ok else
                   "Sayt istifadə etdiyi proqramların dəqiq versiyasını göstərir: " + "; ".join(leaks)
                   + ". Hücumçular köhnə versiyaların zəifliklərini axtarır.",
                   "" if ok else "Versiya məlumatını gizlədin və proqramları son versiyaya yeniləyin.", 6)


def mixed_content(ctx: Context, page) -> Finding:
    if urlsplit(ctx.final_url).scheme != "https":
        return Finding("mixed", SEC, "Qarışıq məzmun", INFO, "Sayt https olmadığı üçün yoxlanılmadı.")
    n = len(page.insecure)
    return Finding("mixed", SEC, "Qarışıq məzmun", OK if n == 0 else WARN,
                   "Bütün şəkil və skriptlər təhlükəsiz bağlantı ilə yüklənir." if n == 0 else
                   f"{n} fayl şifrəsiz http:// ilə yüklənir; brauzer onları bloklaya bilər.",
                   "" if n == 0 else "Səhifədəki http:// linklərini https:// ilə əvəz edin.", 5)


# ---------------------------------------------------------------- e-mail
# Free hosting addresses: the owner cannot set DNS there and sends no mail from them.
PLATFORM_SUFFIXES = (".vercel.app", ".netlify.app", ".github.io", ".onrender.com", ".herokuapp.com",
                     ".pages.dev", ".web.app", ".firebaseapp.com", ".wixsite.com", ".blogspot.com",
                     ".wordpress.com", ".tilda.ws", ".streamlit.app")
PLATFORM_NOTE = ("Sayt pulsuz platforma ünvanında yerləşir, bu ünvandan e-poçt göndərilmir. "
                 "Öz domeniniz (məsələn, .az) olanda bu yoxlama vacib olacaq.")


def on_platform(ctx: Context) -> bool:
    host = urlsplit(ctx.final_url or ctx.input_url).hostname or ctx.host
    return host.endswith(PLATFORM_SUFFIXES)


def spf(ctx: Context, page) -> Finding:
    if on_platform(ctx):
        return Finding("spf", MAIL, "E-poçt göndərən icazəsi (SPF)", INFO, PLATFORM_NOTE)
    recs = ctx.txt_records.get("spf")
    if recs is None:
        return Finding("spf", MAIL, "E-poçt göndərən icazəsi (SPF)", INFO, "DNS yoxlanıla bilmədi.")
    ok = any(r.lower().startswith("v=spf1") for r in recs)
    return Finding("spf", MAIL, "E-poçt göndərən icazəsi (SPF)", OK if ok else FAIL,
                   "Domen adından kimin məktub göndərə biləcəyi müəyyən edilib." if ok else
                   "Hər kəs sizin domen adınızdan saxta məktub göndərə bilər, məktublarınız isə spam-a düşə bilər.",
                   "" if ok else "DNS-ə SPF qeydi əlavə edin (məsələn, e-poçt provayderinizin verdiyi v=spf1 ... qeydi).", 10)


def dmarc(ctx: Context, page) -> Finding:
    if on_platform(ctx):
        return Finding("dmarc", MAIL, "Saxta məktuba qarşı qoruma (DMARC)", INFO, PLATFORM_NOTE)
    recs = ctx.txt_records.get("dmarc")
    if recs is None:
        return Finding("dmarc", MAIL, "Saxta məktuba qarşı qoruma (DMARC)", INFO, "DNS yoxlanıla bilmədi.")
    rec = next((r for r in recs if r.lower().startswith("v=dmarc1")), None)
    if rec is None:
        return Finding("dmarc", MAIL, "Saxta məktuba qarşı qoruma (DMARC)", FAIL,
                       "Domen adınızdan göndərilən saxta məktublar üçün heç bir qayda yoxdur.",
                       "DNS-ə _dmarc qeydi əlavə edin, əvvəlcə p=none ilə başlayın.", 8)
    policy = re.search(r"p=(\w+)", rec.lower())
    if policy and policy.group(1) == "none":
        return Finding("dmarc", MAIL, "Saxta məktuba qarşı qoruma (DMARC)", WARN,
                       "DMARC var, amma yalnız müşahidə rejimindədir (p=none); saxta məktublar bloklanmır.",
                       "Hesabatları yoxladıqdan sonra siyasəti p=quarantine və ya p=reject edin.", 8)
    return Finding("dmarc", MAIL, "Saxta məktuba qarşı qoruma (DMARC)", OK,
                   "Saxta məktublar qəbul edən tərəfindən bloklanır.", "", 8)


# ---------------------------------------------------------------- speed
def response_time(ctx: Context, page) -> Finding:
    ms = ctx.elapsed_ms or 0
    st = OK if ms < 1500 else WARN if ms < 4000 else FAIL
    return Finding("speed", SPEED, "Serverin cavab sürəti", st,
                   f"Server {ms / 1000:.1f} saniyəyə cavab verdi.",
                   "" if st == OK else "Hostinqi, keşləməni və ağır plaginləri yoxlayın.", 8)


def html_size(ctx: Context, page) -> Finding:
    kb = ctx.html_bytes / 1024
    st = OK if kb < 300 else WARN if kb < 1000 else FAIL
    return Finding("size", SPEED, "Səhifənin həcmi", st, f"Əsas səhifənin HTML həcmi {kb:.0f} KB-dır.",
                   "" if st == OK else "Səhifəyə daxil edilmiş böyük kodları və şəkilləri ayrı fayllara çıxarın.", 4)


# ---------------------------------------------------------------- mobile & search
def viewport(ctx: Context, page) -> Finding:
    ok = "width=device-width" in page.meta.get("viewport", "").replace(" ", "")
    return Finding("viewport", SEO, "Telefona uyğunluq", OK if ok else FAIL,
                   "Sayt telefon ekranına uyğunlaşmaq üçün qurulub." if ok else
                   "Sayt telefonda kiçik və oxunmaz görünə bilər; Google bunu nəzərə alır.",
                   "" if ok else "Səhifəyə <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> əlavə edin.", 8)


def title_tag(ctx: Context, page) -> Finding:
    n = len(page.title)
    st = FAIL if n == 0 else OK if 10 <= n <= 70 else WARN
    return Finding("title", SEO, "Səhifə başlığı", st,
                   "Səhifənin başlığı yoxdur." if n == 0 else f"Başlıq: \"{page.title[:80]}\" ({n} simvol).",
                   "" if st == OK else "Biznesi və xidməti izah edən 10–70 simvollu başlıq yazın.", 5)


def description(ctx: Context, page) -> Finding:
    d = page.meta.get("description", "").strip()
    st = OK if 50 <= len(d) <= 170 else WARN if d else FAIL
    return Finding("description", SEO, "Google üçün təsvir", st,
                   "Google axtarışında görünən təsvir yoxdur." if not d else f"Təsvir {len(d)} simvoldur.",
                   "" if st == OK else "50–170 simvolluq, xidməti və əlaqəni göstərən meta description yazın.", 4)


ALL_CHECKS = [https_used, certificate, http_redirect, hsts, framing, nosniff, csp, referrer,
              disclosure, mixed_content, spf, dmarc, response_time, html_size, viewport,
              title_tag, description]


CONTENT_CHECKS = {"viewport", "title", "description", "mixed"}
EMPTY_NOTE = ("Səhifənin məzmunu oxunmadı (server boş cavab qaytardı). "
              "Bu yoxlama bala təsir etmir; saytı brauzerdə açıb yenidən yoxlayın.")


def run_checks(ctx: Context) -> list[Finding]:
    page = parse(ctx.html)
    findings = [check(ctx, page) for check in ALL_CHECKS]
    if not ctx.html.strip():
        for f in findings:
            if f.id in CONTENT_CHECKS and f.status in (FAIL, WARN):
                f.status, f.detail, f.fix = INFO, EMPTY_NOTE, ""
    return findings
