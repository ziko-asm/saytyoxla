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
        self.title, self._in_title, self._title_seen = "", False, False
        self._svg_depth = 0
        self._hidden_depth = 0      # inside <script> or <style>
        self.meta = {}
        self.properties = set()     # <meta property="og:..."> names
        self.insecure = set()
        self.lang = ""
        self.h1_count = 0
        self.canonical = False
        self.scripts = 0
        self.text_chars = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._hidden_depth += 1
            self.scripts += tag == "script"
        elif tag == "html":
            self.lang = a.get("lang", "").strip()
        elif tag == "h1":
            self.h1_count += 1
        elif tag == "link" and "canonical" in a.get("rel", "").lower().split() and a.get("href"):
            self.canonical = True
        elif tag == "meta" and a.get("property") and a.get("content"):
            self.properties.add(a["property"].lower())
        if tag == "svg":
            self._svg_depth += 1
        elif tag == "title":
            # Only the page's own title: every <svg> icon may carry a <title> of its own
            self._in_title = not self._svg_depth and not self._title_seen
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
        if tag in ("script", "style"):
            self._hidden_depth = max(0, self._hidden_depth - 1)
        elif tag == "svg":
            self._svg_depth = max(0, self._svg_depth - 1)
        elif tag == "title":
            self._title_seen = self._title_seen or self._in_title
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif not self._hidden_depth:
            self.text_chars += len(data.strip())


def parse(html: str) -> _Page:
    p = _Page()
    p.feed(html)
    p.title = p.title.strip()
    return p


# ---------------------------------------------------------------- security
def https_used(ctx: Context, page) -> Finding:
    ok = urlsplit(ctx.final_url).scheme == "https"
    if ok and ctx.cert and ctx.cert.get("error"):
        return Finding("https", SEC, "Təhlükəsiz bağlantı (HTTPS)", FAIL,
                       "Sayt HTTPS ilə açılır, amma sertifikat etibarsız olduğu üçün bu bağlantıya etibar etmək olmur.",
                       "Hostinq panelindən pulsuz SSL sertifikatı (Let's Encrypt) qoşun.", 20)
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


# Fragment of the TLS library's message -> what it means for the site's owner
CERT_ERRORS = [
    ("expired", "Sertifikatın vaxtı bitib. Brauzerlər ziyarətçiyə təhlükəsizlik xəbərdarlığı göstərir."),
    ("self-signed", "Sertifikat özü-imzalıdır, brauzerlər ona etibar etmir və ziyarətçiyə xəbərdarlıq göstərir."),
    ("self signed", "Sertifikat özü-imzalıdır, brauzerlər ona etibar etmir və ziyarətçiyə xəbərdarlıq göstərir."),
    ("hostname mismatch", "Sertifikat bu domen adına verilməyib. Brauzerlər ziyarətçiyə təhlükəsizlik xəbərdarlığı göstərir."),
    ("revoked", "Sertifikat ləğv edilib. Brauzerlər ziyarətçiyə təhlükəsizlik xəbərdarlığı göstərir."),
    ("issuer", "Sertifikatı etibarlı mərkəz təsdiqləmir və ya zəncir tam deyil. Brauzerlər ziyarətçiyə xəbərdarlıq göstərir."),
]
CERT_ERROR_OTHER = "Sertifikat etibarsızdır. Brauzerlər ziyarətçiyə təhlükəsizlik xəbərdarlığı göstərir."


def cert_error_text(error: str) -> str:
    low = error.lower()
    return next((text for fragment, text in CERT_ERRORS if fragment in low), CERT_ERROR_OTHER)


def certificate(ctx: Context, page) -> Finding:
    c = ctx.cert
    if not c:
        return Finding("cert", SEC, "SSL sertifikatı", INFO, "Sertifikat yoxlanılmadı (sayt https deyil).")
    if c.get("unknown"):
        return Finding("cert", SEC, "SSL sertifikatı", INFO, "Sertifikat vaxtında oxuna bilmədi.")
    if c.get("error"):
        return Finding("cert", SEC, "SSL sertifikatı", FAIL, cert_error_text(c["error"]),
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


HSTS_MIN_DAYS = 180


def hsts(ctx: Context, page) -> Finding:
    title = "Məcburi HTTPS (HSTS)"
    fix = "Server cavabına Strict-Transport-Security başlığını əlavə edin."
    value = ctx.headers.get("strict-transport-security")
    if value is None:
        return Finding("hsts", SEC, title, WARN, "Brauzerlərə yalnız HTTPS istifadə etmək əmri verilməyib.", fix, 6)
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    days = int(m.group(1)) // 86400 if m else 0
    if days < HSTS_MIN_DAYS:
        return Finding("hsts", SEC, title, WARN,
                       f"HSTS çox qısa müddətə qurulub ({days} gün), brauzerlər bu əmri tez unudur.",
                       "HSTS müddətini ən azı 180 günə qaldırın (max-age=31536000 tövsiyə olunur).", 6)
    return Finding("hsts", SEC, title, OK, "Brauzerlərə sayta yalnız HTTPS ilə girmək əmr olunub.", "", 6)


def nosniff(ctx: Context, page) -> Finding:
    ok = ctx.headers.get("x-content-type-options", "").strip().lower() == "nosniff"
    missing = "x-content-type-options" not in ctx.headers
    return Finding("nosniff", SEC, "Fayl tipinin qorunması", OK if ok else WARN,
                   "Brauzerin faylları səhv tipdə açması qadağandır." if ok else
                   "X-Content-Type-Options başlığı yoxdur." if missing else
                   "X-Content-Type-Options başlığının dəyəri səhvdir, brauzer onu nəzərə almır.",
                   "" if ok else "Server cavabına \"X-Content-Type-Options: nosniff\" əlavə edin.", 4)


def referrer(ctx: Context, page) -> Finding:
    value = ctx.headers.get("referrer-policy")
    # Several values are a fallback list: the last one a browser knows wins
    last = (value or "").split(",")[-1].strip().lower()
    weak = last in ("unsafe-url", "no-referrer-when-downgrade", "")
    fix = "Server cavabına \"Referrer-Policy: strict-origin-when-cross-origin\" əlavə edin."
    if value is None:
        return Finding("referrer", SEC, "Keçid məlumatının qorunması", WARN, "Referrer-Policy başlığı yoxdur.", fix, 2)
    return Finding("referrer", SEC, "Keçid məlumatının qorunması", WARN if weak else OK,
                   "Referrer-Policy digər saytlara səhifənin tam ünvanını ötürməyə icazə verir." if weak else
                   "Keçid zamanı digər saytlara nə qədər məlumat ötürüldüyü məhdudlaşdırılıb.",
                   fix if weak else "", 2)


def csp_directives(policy: str) -> dict:
    out = {}
    for part in policy.split(";"):
        words = part.strip().split()
        if words:
            out.setdefault(words[0].lower(), [w.lower() for w in words[1:]])
    return out


def framing(ctx: Context, page) -> Finding:
    xfo = ctx.headers.get("x-frame-options", "").strip().lower()
    ancestors = csp_directives(ctx.headers.get("content-security-policy", "")).get("frame-ancestors")
    ok = xfo in ("deny", "sameorigin") or (ancestors is not None and "*" not in ancestors)
    return Finding("framing", SEC, "Saxta çərçivəyə qarşı qoruma", OK if ok else WARN,
                   "Sayt başqa saytın içində gizli açıla bilməz." if ok else
                   "Sayt başqa saytın içinə yerləşdirilib istifadəçini aldatmaq üçün istifadə oluna bilər.",
                   "" if ok else "Server cavabına \"X-Frame-Options: SAMEORIGIN\" əlavə edin.", 5)


def csp_weakness(policy: str) -> str | None:
    """What makes a policy fail to limit scripts, or None if it does limit them."""
    d = csp_directives(policy)
    scripts = d.get("script-src", d.get("default-src"))
    if scripts is None:
        return "skriptlər üçün qayda yoxdur"
    if "'unsafe-inline'" in scripts and not any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in scripts):
        return "unsafe-inline"
    if "'unsafe-eval'" in scripts:
        return "unsafe-eval"
    if any(s in ("*", "https:", "http:", "data:") for s in scripts):
        return "hər yerdən skriptə icazə"
    return None


def csp(ctx: Context, page) -> Finding:
    title = "Kənar skriptlərə nəzarət (CSP)"
    policy = ctx.headers.get("content-security-policy")
    if policy is None:
        report_only = "content-security-policy-report-only" in ctx.headers
        return Finding("csp", SEC, title, WARN,
                       "CSP yalnız müşahidə rejimindədir (report-only), heç nəyi bloklamır." if report_only else
                       "Saytda kənar skriptlərə nəzarət qaydası (CSP) yoxdur.",
                       "Hesabatları yoxladıqdan sonra başlığı Content-Security-Policy adı ilə işə salın." if report_only else
                       "Content-Security-Policy başlığını əvvəlcə report-only rejimində qurun.", 4)
    weakness = csp_weakness(policy)
    if weakness:
        return Finding("csp", SEC, title, WARN, f"CSP var, amma skriptləri az məhdudlaşdırır: {weakness}.",
                       "script-src qaydasından unsafe-inline, unsafe-eval və * dəyərlərini çıxarın, nonce və ya hash işlədin.", 4)
    return Finding("csp", SEC, title, OK, "Saytda hansı skriptlərin işləyə biləcəyi məhdudlaşdırılıb.", "", 4)


SESSION_COOKIE = re.compile(r"sess|auth|token|sid$|login|jwt", re.IGNORECASE)


def cookies(ctx: Context, page) -> Finding:
    title = "Cookie təhlükəsizliyi"
    if not ctx.cookies:
        return Finding("cookies", SEC, title, OK, "Əsas səhifə cookie yazmır.", "", 5)
    secure_site = urlsplit(ctx.final_url).scheme == "https"
    weak = []
    for raw in ctx.cookies:
        name, _, rest = raw.partition("=")
        attrs = {p.split("=")[0].strip().lower() for p in rest.split(";")[1:]}
        # JavaScript needs to read many ordinary cookies, so HttpOnly is only required of login-like ones
        if (secure_site and "secure" not in attrs) or "samesite" not in attrs \
                or (SESSION_COOKIE.search(name) and "httponly" not in attrs):
            weak.append(name.strip())
    if not weak:
        return Finding("cookies", SEC, title, OK, f"Cookie-lər qorunub ({len(ctx.cookies)} ədəd).", "", 5)
    return Finding("cookies", SEC, title, WARN,
                   f"{len(weak)} cookie-də qoruma çatışmır: {', '.join(weak[:3])}.",
                   "Cookie-lərə Secure və SameSite=Lax, giriş cookie-lərinə HttpOnly da əlavə edin.", 5)


def tls_version(ctx: Context, page) -> Finding:
    version = (ctx.cert or {}).get("tls")
    if not version:
        return Finding("tls", SEC, "Şifrələmə versiyası (TLS)", INFO, "TLS versiyası oxunmadı.")
    return Finding("tls", SEC, "Şifrələmə versiyası (TLS)", OK, f"Bağlantı {version.replace('TLSv', 'TLS ')} ilə qurulur.")


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


def dmarc_policy(ctx: Context) -> tuple[str | None, str | None]:
    """The policy that applies to this host and the parent domain it comes from, if any.
    A record inherited from a parent is read through its subdomain policy (sp=), which defaults to p=."""
    rec = next((r for r in ctx.txt_records.get("dmarc") or [] if r.lower().startswith("v=dmarc1")), None)
    if rec is None:
        return None, None
    tags = dict(part.strip().lower().split("=", 1) for part in rec.split(";") if "=" in part)
    parent = ctx.txt_records.get("dmarc_parent")
    return (tags.get("sp") or tags.get("p")) if parent else tags.get("p"), parent


def spf(ctx: Context, page) -> Finding:
    if on_platform(ctx):
        return Finding("spf", MAIL, "E-poçt göndərən icazəsi (SPF)", INFO, PLATFORM_NOTE)
    recs = ctx.txt_records.get("spf")
    if recs is None:
        return Finding("spf", MAIL, "E-poçt göndərən icazəsi (SPF)", INFO, "DNS yoxlanıla bilmədi.")
    ok = any(r.lower().startswith("v=spf1") for r in recs)
    policy, parent = dmarc_policy(ctx)
    if not ok and parent and policy in ("quarantine", "reject"):    # fake mail is already refused by the parent's rule
        return Finding("spf", MAIL, "E-poçt göndərən icazəsi (SPF)", INFO,
                       f"Bu subdomenin öz SPF qeydi yoxdur, amma əsas domenin ({parent}) DMARC qaydası saxta məktubları bloklayır.")
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
    if not any(r.lower().startswith("v=dmarc1") for r in recs):
        return Finding("dmarc", MAIL, "Saxta məktuba qarşı qoruma (DMARC)", FAIL,
                       "Domen adınızdan göndərilən saxta məktublar üçün heç bir qayda yoxdur.",
                       "DNS-ə _dmarc qeydi əlavə edin, əvvəlcə p=none ilə başlayın.", 8)
    policy, parent = dmarc_policy(ctx)
    if policy == "none":
        return Finding("dmarc", MAIL, "Saxta məktuba qarşı qoruma (DMARC)", WARN,
                       f"Əsas domenin ({parent}) DMARC qaydası yalnız müşahidə rejimindədir (p=none); saxta məktublar bloklanmır."
                       if parent else
                       "DMARC var, amma yalnız müşahidə rejimindədir (p=none); saxta məktublar bloklanmır.",
                       "Hesabatları yoxladıqdan sonra siyasəti p=quarantine və ya p=reject edin.", 8)
    return Finding("dmarc", MAIL, "Saxta məktuba qarşı qoruma (DMARC)", OK,
                   f"Bu subdomenin öz qeydi yoxdur, amma əsas domenin ({parent}) DMARC qaydası saxta məktubları bloklayır."
                   if parent else
                   "Saxta məktublar qəbul edən tərəfindən bloklanır.", "", 8)


def dkim(ctx: Context, page) -> Finding:
    title = "E-poçt imzası (DKIM)"
    if on_platform(ctx):
        return Finding("dkim", MAIL, title, INFO, PLATFORM_NOTE)
    if ctx.dkim is None:
        return Finding("dkim", MAIL, title, INFO, "DNS yoxlanıla bilmədi.")
    if ctx.dkim:
        return Finding("dkim", MAIL, title, OK, f"Məktubları imzalayan DKIM açarı tapıldı ({', '.join(ctx.dkim[:3])}).")
    # DNS cannot list the keys, so a key under an unusual name stays invisible: never a problem, only a note
    return Finding("dkim", MAIL, title, INFO, "Geniş yayılmış adlarda DKIM açarı tapılmadı. Bu, DKIM-in olmadığını sübut etmir.")


# ---------------------------------------------------------------- speed
def response_time(ctx: Context, page) -> Finding:
    ms = ctx.elapsed_ms or 0
    st = OK if ms < 1500 else WARN if ms < 4000 else FAIL
    return Finding("speed", SPEED, "Serverin cavab sürəti", st,
                   f"Server {ms:.0f} millisaniyəyə cavab verdi." if ms < 1000 else
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
    st = OK if 50 <= len(d) <= 170 else WARN       # a search snippet, never a "serious problem" next to security
    return Finding("description", SEO, "Google üçün təsvir", st,
                   "Google axtarışında görünən təsvir yoxdur." if not d else f"Təsvir {len(d)} simvoldur.",
                   "" if st == OK else "50–170 simvolluq, xidməti və əlaqəni göstərən meta description yazın.", 4)


def heading(ctx: Context, page) -> Finding:
    n = page.h1_count
    st = OK if n == 1 else WARN
    return Finding("h1", SEO, "Əsas başlıq (H1)", st,
                   "Səhifədə bir əsas başlıq var." if n == 1 else
                   "Səhifədə əsas başlıq (H1) yoxdur." if n == 0 else f"Səhifədə {n} əsas başlıq (H1) var.",
                   "" if st == OK else "Səhifənin mövzusunu izah edən bir H1 başlığı saxlayın.", 2)


def language(ctx: Context, page) -> Finding:
    ok = bool(page.lang)
    return Finding("lang", SEO, "Səhifənin dili", OK if ok else WARN,
                   f"Səhifənin dili göstərilib ({page.lang[:12]})." if ok else "Səhifənin dili göstərilməyib.",
                   "" if ok else "<html> teqinə dili əlavə edin, məsələn: <html lang=\"az\">.", 2)


def canonical(ctx: Context, page) -> Finding:
    return Finding("canonical", SEO, "Əsas ünvan (canonical)", OK if page.canonical else WARN,
                   "Google-a səhifənin əsas ünvanı göstərilib." if page.canonical else
                   "Google-a səhifənin əsas ünvanı göstərilməyib.",
                   "" if page.canonical else "Səhifəyə <link rel=\"canonical\" href=\"...\"> əlavə edin.", 2)


def open_graph(ctx: Context, page) -> Finding:
    ok = {"og:title", "og:image"} <= page.properties
    return Finding("og", SEO, "Sosial şəbəkə kartı", OK if ok else WARN,
                   "Link paylaşılanda başlıq və şəkil görünür." if ok else
                   "Link WhatsApp və Facebook-da paylaşılanda başlıq və ya şəkil görünməyə bilər.",
                   "" if ok else "Səhifəyə og:title və og:image meta teqlərini əlavə edin.", 2)


def blocks_everyone(robots: str) -> bool:
    """Does robots.txt tell every crawler to stay away from the whole site?"""
    agents, in_rules, blocked = [], False, False
    for line in robots.splitlines():
        key, _, value = line.split("#")[0].partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            if in_rules:
                agents, in_rules = [], False
            agents.append(value)
        elif key in ("allow", "disallow"):
            in_rules = True
            if "*" in agents:
                if key == "disallow" and value == "/":
                    blocked = True
                elif key == "allow" and value == "/":
                    return False
    return blocked


def indexing(ctx: Context, page) -> Finding:
    title = "Google-da görünmə icazəsi"
    tags = (page.meta.get("robots", "") + "," + ctx.headers.get("x-robots-tag", "")).lower()
    if "noindex" in tags or "none" in tags.replace(" ", "").split(","):
        return Finding("indexing", SEO, title, FAIL, "Səhifə Google-dan gizlədilib (noindex), axtarışda çıxmayacaq.",
                       "Sayt açıqdırsa, robots meta teqindən və ya X-Robots-Tag başlığından noindex-i çıxarın.", 6)
    if ctx.robots is None:
        return Finding("indexing", SEO, title, INFO, "robots.txt vaxtında oxuna bilmədi.")
    if blocks_everyone(ctx.robots):
        return Finding("indexing", SEO, title, FAIL, "robots.txt bütün sayta girişi bağlayır, sayt axtarışda çıxmayacaq.",
                       "Sayt açıqdırsa, robots.txt-dən \"Disallow: /\" sətrini çıxarın.", 6)
    return Finding("indexing", SEO, title, OK, "Axtarış sistemlərinə sayta baxmaq icazəsi verilib.", "", 6)


def sitemap(ctx: Context, page) -> Finding:
    if ctx.sitemap is None:
        return Finding("sitemap", SEO, "Sayt xəritəsi (sitemap)", INFO, "Sayt xəritəsi vaxtında oxuna bilmədi.")
    return Finding("sitemap", SEO, "Sayt xəritəsi (sitemap)", OK if ctx.sitemap else WARN,
                   "Sayt xəritəsi tapıldı." if ctx.sitemap else "Sayt xəritəsi (sitemap.xml) tapılmadı.",
                   "" if ctx.sitemap else "sitemap.xml yaradın və ünvanını robots.txt-ə yazın.", 2)


ALL_CHECKS = [https_used, certificate, tls_version, http_redirect, hsts, framing, nosniff, csp, referrer, cookies,
              disclosure, mixed_content, spf, dmarc, dkim, response_time, html_size, viewport,
              title_tag, description, heading, language, canonical, open_graph, indexing, sitemap]


CONTENT_CHECKS = {"viewport", "title", "description", "mixed", "h1", "lang", "canonical", "og"}
EMPTY_NOTE = ("Səhifənin məzmunu oxunmadı (server boş cavab qaytardı). "
              "Bu yoxlama bala təsir etmir; saytı brauzerdə açıb yenidən yoxlayın.")
# Pages built by JavaScript fill these in only in a browser, and the scanner does not run scripts
RENDERED_CHECKS = {"title", "description", "h1", "canonical", "og"}
RENDERED_TEXT_LIMIT = 200
RENDERED_NOTE = ("Səhifə JavaScript ilə qurulur, bu məlumat brauzerdə əlavə oluna bilər və burada yoxlanılmadı. "
                 "Bu yoxlama bala təsir etmir.")


def run_checks(ctx: Context) -> list[Finding]:
    page = parse(ctx.html)
    findings = [check(ctx, page) for check in ALL_CHECKS]
    empty = not ctx.html.strip()
    rendered = page.scripts and page.text_chars < RENDERED_TEXT_LIMIT
    for f in findings:
        if f.status not in (FAIL, WARN):
            continue
        if empty and f.id in CONTENT_CHECKS:
            f.status, f.detail, f.fix = INFO, EMPTY_NOTE, ""
        elif rendered and f.id in RENDERED_CHECKS:
            f.status, f.detail, f.fix = INFO, RENDERED_NOTE, ""
    return findings
