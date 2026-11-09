"""
"Sayt haqqında ümumi məlumat": one long plain-text page (Azerbaijani only) with a search box.

The page is ordinary HTML, so it reads fine without JavaScript. web/static/glossary.js adds the search: it
builds its index from the .term blocks below and jumps to the chosen one.

What it says about scoring must stay true of scanner/checks.py and scanner/report.py (tests/test_glossary.py
checks the numbers that are easy to drift).
"""
# ruff: noqa: ISC004  (long paragraphs are written as adjacent string pieces on purpose)

from __future__ import annotations

from html import escape

from web.pages import CONTACT, HOMES, _shell
from web.seo import SITE_URL

PATH = "/lugat/"
TITLE = "Sayt haqqında ümumi məlumat"
DESC = ("Sayt nədir, nə üçün lazımdır? HTTPS, DNS, SPF, DMARC, SSL, XSS, SQL injection və digər anlayışlar sadə dillə izah olunur. "
        "Axtarış xanası ilə lazım olan sözə keçin.")

INTRO = """
<section class="term" id="sayt-nedir" data-k="sayt veb sayt internet reklam satis etibar vitrin">
<h2>Sayt nədir? Nə üçün lazımdır?</h2>
<p>Sayt internetdə sizin rəqəmsal ünvanınızdır. İnsan sizin haqqınızda eşidəndə ilk iş telefonu götürüb axtarır. Orada nəsə tapmırsa, çox vaxt başqasına gedir.</p>
<ul>
<li><b>Reklam üçün.</b> Sayt günün 24 saatı işləyir. Qiymətləri, ünvanı və işlərinizi hər dəfə təkrar izah etmirsiniz, link göndərirsiniz.</li>
<li><b>Satışı artırmaq üçün.</b> Google-da «Bakıda ... sifarişi» yazan adam sizi tapa bilər. Düymə, forma və ya WhatsApp linki ilə birbaşa sifariş verə bilər.</li>
<li><b>İşi asanlaşdırmaq üçün.</b> Eyni suallara dəfələrlə cavab verməyə ehtiyac qalmır. Qeydiyyat, sifariş və ya ödəniş avtomatik gedə bilər.</li>
<li><b>Etibar üçün.</b> Saytı olan firmaya münasibət fərqli olur: «bu iş ciddidir» təəssüratı yaranır. Saytı olmayan və ya brauzerdə «təhlükəsiz deyil» xəbərdarlığı çıxan sayt isə əksinə.</li>
<li><b>İşlərinizi göstərmək üçün.</b> Şəkillər, rəylər və nümunələr bir yerdə durur. Müştəri qərarı daha rahat verir.</li>
</ul>
<p>Amma sayt qurmaq kifayət deyil. Sayt təhlükəsiz, sürətli və telefonda düzgün görünməlidir; e-poçtunuz da başqası tərəfindən saxta yazıla bilməməlidir. Yoxsa müştəri gəlməz, Google aşağı sıralayar, pis halda isə sayt sındırılar. SaytYoxla məhz bunu 30 saniyəyə yoxlayır.</p>
</section>
<p>Aşağıda sayt və onun təhlükəsizliyi ilə bağlı bütün anlayışlar sadə dillə yazılıb. Lazım olanı tapmaq üçün yuxarıdakı axtarış xanasından istifadə edin.</p>
"""

# (section title, [(id, title, extra search words, body html)])
SECTIONS: list[tuple[str, list[tuple[str, str, str, str]]]] = [
    ("1. Əsas anlayışlar", [
        ("internet-sayt-brauzer", "Sayt, brauzer və server nədir?", "veb sayt brauzer server hosting",
         "<p><b>Sayt</b> serverdə saxlanılan fayllardır (mətn, şəkil, kod). <b>Server</b> həmişə yanan və internetə qoşulu kompüterdir. "
         "<b>Brauzer</b> (Chrome, Safari, Firefox) ünvanı yazanda həmin serverdən faylları alıb sizə səhifə kimi göstərir.</p>"),
        ("domen", "Domen nədir?", "domain ad ayfar.dev ünvan .az .com",
         "<p>Domen saytın adıdır, məsələn <i>saytyoxla.vercel.app</i> və ya <i>ayfar.dev</i>. İnsan üçün rahatdır: rəqəmlərlə yazılan IP ünvanı əzbərləmək lazım gəlmir. "
         "Domeni ildə bir dəfə ödəyib icarəyə götürürsünüz. Vaxtında yeniləməsəniz, başqası ala bilər.</p>"),
        ("hosting", "Hosting nədir?", "hostinq server yer icarə vercel",
         "<p>Hosting saytınızın fayllarının durduğu və 24 saat işləyən serverdə icarə etdiyiniz yerdir. Domen ünvandırsa, hosting evin özüdür. "
         "Hostinq şirkətinin sürəti və qorunması saytınızın sürətinə və təhlükəsizliyinə birbaşa təsir edir.</p>"),
        ("ip-unvan", "IP ünvan nədir?", "ip address unvan",
         "<p>IP ünvan internetdə hər cihazın və serverin rəqəmlə yazılan ünvanıdır (məsələn <i>216.198.79.1</i>). Domen adı həmin ünvana çevrilir.</p>"),
        ("dns", "DNS nədir?", "domain name system a record cname txt mx nameserver",
         "<p>DNS internetin telefon kitabçasıdır. Brauzer <i>sayt.az</i> yazılanda DNS-dən soruşur: «bu ad hansı serverdədir?» DNS cavab verir, brauzer həmin serverə gedir. "
         "DNS-də başqa qeydlər də olur: <b>A</b> (domen hansı IP-yə baxır), <b>CNAME</b> (başqa adın təkrarı), <b>MX</b> (e-poçt hansı serverə gedir), <b>TXT</b> (mətn qeydi; SPF, DMARC və sahiblik təsdiqi burada yazılır).</p>"
         "<p>Bu qeydləri domeni aldığınız şirkətin (Namecheap, GoDaddy və s.) panelində dəyişirsiniz. Dəyişiklik bəzən bir neçə dəqiqə, bəzən bir neçə saat gec görünür.</p>"),
        ("http", "HTTP nədir?", "hypertext transfer protocol protokol",
         "<p>HTTP brauzerlə serverin bir-biri ilə danışdığı qaydadır. Problem: HTTP şifrələnmir. Eyni Wi-Fi şəbəkəsindəki biri (kafe, otel) parolu və ya forma məlumatını oxuya və ya dəyişə bilər.</p>"),
        ("https", "HTTPS nədir?", "http secure sifreleme kilid lock ssl tls",
         "<p>HTTPS HTTP-nin şifrələnmiş variantıdır. Ünvanın yanındakı kilid işarəsi odur. Brauzer ilə server arasındakı hər şey şifrələnir, kənardan oxumaq və ya dəyişmək olmur. "
         "Üstəlik HTTPS saytın doğrudan həmin saytın olduğunu sübut edir. HTTPS olmayan saytı brauzer «təhlükəsiz deyil» xəbərdarlığı ilə göstərir və Google bu saytı aşağı sıralayır.</p>"
         "<p>SaytYoxla-da HTTPS ən ağır yoxlamadır (20 bal). HTTPS işləmirsə, ümumi bal 39-dan yuxarı qalxmır.</p>"),
        ("ssl-tls", "SSL və TLS nədir?", "ssl tls sertifikat sifreleme protokol tls 1.2 1.3",
         "<p>TLS HTTPS-i şifrələyən texnologiyadır. SSL onun köhnə adıdır, amma insanlar hələ də «SSL sertifikatı» deyirlər. "
         "Köhnə versiyalar (SSL, TLS 1.0, TLS 1.1) zəifdir və artıq istifadə olunmamalıdır. Hazırda TLS 1.2 və TLS 1.3 normal sayılır.</p>"),
        ("ssl-sertifikat", "SSL sertifikatı nədir?", "sertifikat certificate letsencrypt bitme tarixi etibarli",
         "<p>Sertifikat saytın şəxsiyyət vəsiqəsidir. Onu etibarlı təşkilat (məsələn Let's Encrypt) verir və saytın həqiqətən həmin domenə aid olduğunu təsdiqləyir. "
         "Sertifikatın bitmə tarixi var. Vaxtı bitəndə brauzer ziyarətçiyə böyük qırmızı xəbərdarlıq göstərir və çoxları saytdan çıxır.</p>"
         "<p>Çox hostinq təminatçısı sertifikatı pulsuz verir və özü yeniləyir. Amma bunu yoxlamaq lazımdır. SaytYoxla sertifikatın neçə gün qaldığını göstərir; sertifikat etibarsızdırsa, bal 59-dan yuxarı qalxmır.</p>"),
        ("http-https-yonlendirme", "HTTP-dən HTTPS-ə yönləndirmə nədir?", "redirect yonlendirme 301 http https",
         "<p>İnsan ünvanı <i>http://</i> ilə yazanda sayt onu avtomatik <i>https://</i> variantına keçirməlidir. Bu olmasa, bəzi ziyarətçilər şifrələnməmiş versiyada qalır. SaytYoxla bunu 8 balla yoxlayır.</p>"),
    ]),
    ("2. Təhlükəsizlik başlıqları", [
        ("basliqlar", "HTTP başlıqları (headers) nədir?", "header basliq cavab response",
         "<p>Server səhifəni göndərəndə onunla birlikdə görünməyən qısa təlimatlar da göndərir. Bunlara başlıq deyilir. Bəziləri brauzerə belə deyir: «bu səhifəni çərçivəyə qoyma», «yalnız HTTPS ilə aç». "
         "Bu başlıqlar proqramçı üçün çox asan əlavə olunur, amma çox saytda unudulur. Aşağıdakı hər biri SaytYoxla-nın yoxladığı başlıqdır.</p>"),
        ("hsts", "HSTS nədir?", "strict transport security basliq hsts max-age",
         "<p>HSTS brauzerə deyir: «bu saytla bundan sonra yalnız HTTPS ilə danış». Brauzer bunu yadda saxlayır və hətta insan <i>http://</i> yazsa da şifrələnməmiş sorğu göndərmir. "
         "Beləcə şəbəkədə kimsə əlaqəni HTTP-yə endirməyə (downgrade) çalışsa, alınmır. Düzgün bitiş: <i>max-age</i> ən azı 6 ay olmalıdır. SaytYoxla-da 6 bal.</p>"),
        ("csp", "CSP (Content-Security-Policy) nədir?", "content security policy basliq csp xss script",
         "<p>CSP saytın brauzerə verdiyi siyahıdır: «skriptləri, şəkilləri və şriftləri yalnız bu ünvanlardan yüklə». Hücumçu saytın içinə zərərli skript yerləşdirə bilsə belə, brauzer onu siyahıda olmadığı üçün işlətmir. "
         "Beləliklə CSP XSS hücumlarına qarşı ən güclü təbəqədir. Amma ən çox buraxılan başlıqdır: SaytYoxla-nın 106 saytlıq araşdırmasında yalnız 14%-də CSP var idi. "
         "Yazmaq çətindir, çünki yanlış yazanda sayt sınır. Ona görə də SaytYoxla yalnız CSP-nin olub-olmadığına yox, keyfiyyətinə də baxır («unsafe-inline» kimi zəif qaydalar xəbərdarlıq verir). 4 bal.</p>"),
        ("x-frame-options", "Clickjacking, X-Frame-Options və frame-ancestors nədir?", "clickjacking framing iframe x-frame-options frame-ancestors",
         "<p>Clickjacking hücumunda hücumçu sizin saytınızı görünməz şəkildə öz səhifəsinin içinə qoyur (iframe). İnsan «mükafat al» düyməsinə basdığını düşünür, əslində sizin saytdakı «ödə» və ya «sil» düyməsinə basır. "
         "<b>X-Frame-Options</b> və ya CSP-dəki <b>frame-ancestors</b> başlığı saytın başqa saytların içində açılmasını qadağan edir. SaytYoxla-da 5 bal.</p>"),
        ("nosniff", "X-Content-Type-Options (nosniff) nədir?", "nosniff content type sniffing basliq mime",
         "<p>Brauzer bəzən faylın növünü özü «təxmin edir». Hücumçu şəkil kimi görünən faylın içinə skript qoyub brauzeri onu işlətməyə məcbur edə bilər. <i>nosniff</i> başlığı təxminin qarşısını alır: fayl elan olunan növ kimi qəbul edilir. 4 bal.</p>"),
        ("referrer-policy", "Referrer-Policy nədir?", "referrer policy basliq istinad",
         "<p>İnsan sizin saytdan başqasına keçəndə brauzer «mən buradan gəlirəm» deyə əvvəlki ünvanı ötürür. Ünvanda bəzən şəxsi məlumat (sorğu nömrəsi, token) olur. Bu başlıq nəyin ötürüləcəyini məhdudlaşdırır. 2 bal.</p>"),
        ("cookie-qoruma", "Kuki (cookie) və onun qorunması nədir?", "cookie kuki secure httponly samesite sessiya",
         "<p>Kuki brauzerdə saxlanan kiçik mətn qeydidir; sayt sizi girişdən sonra bununla tanıyır. Kuki oğurlansa, hücumçu sizin adınızla girə bilər. Buna görə üç bayraq lazımdır: "
         "<b>Secure</b> (yalnız HTTPS ilə göndərilir), <b>HttpOnly</b> (JavaScript onu oxuya bilmir, XSS-dən qoruyur) və <b>SameSite</b> (başqa saytdan gələn sorğularda göndərilmir, CSRF-dən qoruyur). SaytYoxla-da 5 bal. "
         "Qeyd: SaytYoxla özü kuki istifadə etmir.</p>"),
        ("server-versiya", "Server versiyasının açıqlanması nədir?", "server basliq x-powered-by versiya disclosure php nginx apache",
         "<p>Bəzi serverlər hər cavabda «mən Apache 2.2.15-əm» və ya «PHP 5.6 ilə işləyirəm» yazır. Hücumçu üçün bu hazır xəritədir: həmin versiyanın bilinən zəifliyini birbaşa axtarır. Versiyanı gizlətmək tək başına qoruma deyil, amma hücumçuya kömək etməmək üçün yaxşı vərdişdir. 6 bal.</p>"),
        ("qarisiq-mezmun", "Qarışıq məzmun (mixed content) nədir?", "mixed content qarisiq http sekil skript",
         "<p>Səhifə HTTPS ilə açılır, amma içindəki şəkil və ya skript HTTP ilə yüklənir. Onda kilid işarəsi pozulur, kənardan həmin hissəni dəyişmək olur. Həll: bütün resursları <i>https://</i> ilə çağırmaq. 5 bal.</p>"),
    ]),
    ("3. E-poçt və domen qoruması", [
        ("eposta-saxta", "Saxta e-poçt (spoofing) nədir?", "spoofing saxta mektub phishing fishinq eposta email",
         "<p>E-poçtun protokolu qurulanda göndərənin kim olduğu yoxlanmırdı. Yəni hər kəs <i>info@sizin-sayt.az</i> adından məktub yaza bilər. Fırıldaqçılar bundan istifadə edib sizin müştərilərinizə «ödənişi bu hesaba göndərin» yazır. "
         "SPF, DKIM və DMARC məhz bunun qarşısını almaq üçündür. Üçü də DNS-də TXT qeydi kimi yazılır.</p>"),
        ("spf", "SPF nədir?", "sender policy framework spf txt eposta",
         "<p>SPF domen üçün «bu domen adından məktubu yalnız bu serverlər göndərə bilər» siyahısıdır. Qəbul edən server məktubun hansı serverdən gəldiyinə baxır və siyahıda yoxdursa şübhə ilə yanaşır. "
         "Qeydin sonu vacibdir: <i>-all</i> (siyahıda olmayanı rədd et) və <i>~all</i> (şübhəli say) işləyir, <i>?all</i> və <i>+all</i> isə faktiki heç nəyi qorumur. SaytYoxla-da 10 bal.</p>"),
        ("dkim", "DKIM nədir?", "domainkeys identified mail dkim imza selector",
         "<p>DKIM hər məktuba rəqəmsal imza qoyur. Qəbul edən server imzanı DNS-dəki açıq açarla yoxlayır və məktubun yolda dəyişdirilmədiyini təsdiqləyir. "
         "DKIM «selector» adlı addan istifadə edir və hər e-poçt xidmətinin öz adı olur (google, selector1, k1, mail və s.). Bu səbəbdən SaytYoxla geniş yayılmış adlara baxır; tapılmadısa, bu «qeyd yoxdur» demək deyil, sadəcə başqa adla yazılmış ola bilər. Buna görə DKIM balda sayılmır, yalnız məlumat kimi göstərilir.</p>"),
        ("dmarc", "DMARC nədir?", "dmarc p=none quarantine reject eposta rua",
         "<p>DMARC SPF və DKIM-in üstündə qərardır: «yoxlamadan keçməyən məktubla nə etmək lazımdır?» Üç seçim var: <b>p=none</b> (heç nə etmə, yalnız hesabat göndər), <b>p=quarantine</b> (spam qovluğuna at) və <b>p=reject</b> (heç göstərmə). "
         "Düzgün yol belədir: əvvəlcə <i>p=none</i> yazıb hesabatlara baxırsınız, hər şey qaydasındadırsa, <i>quarantine</i>, sonra <i>reject</i> edirsiniz. Yoxsa öz qanuni məktublarınız da itə bilər. "
         "SaytYoxla-nın 106 saytlıq araşdırmasında DMARC-ı tətbiq edən (quarantine/reject) saytlar 58% idi. 8 bal; <i>p=none</i> yarım bal verir.</p>"),
        ("mx", "MX qeydi nədir?", "mx mail exchange eposta server dns",
         "<p>MX qeydi domenin e-poçtunu hansı serverin qəbul edəcəyini göstərir. Məsələn Google Workspace istifadə edirsinizsə, MX qeydləri Google serverlərinə baxır.</p>"),
    ]),
    ("4. Hücum növləri", [
        ("xss", "XSS (Cross-Site Scripting) nədir?", "xss cross site scripting skript inject reflected stored",
         "<p>XSS-də hücumçu sizin saytın səhifəsinə öz zərərli skriptini yerləşdirir. Həmin səhifəni açan hər kəsin brauzerində skript sizin saytın adından işləyir: kuki oğurlaya, formaları dəyişə, başqa saytlara yönləndirə bilər. "
         "Adətən sayt istifadəçinin yazdığı mətni (axtarış, şərh, ünvandakı parametr) təmizləmədən səhifədə göstərəndə baş verir. "
         "<b>Reflected</b> XSS-də skript ünvanın içində olur və yalnız həmin linkə basanı vurur. <b>Stored</b> XSS-də isə skript bazada saxlanır (məsələn şərhdə) və səhifəni açan hamını vurur. "
         "Qorunma: istifadəçi mətnini həmişə təmizləmək (escape) və CSP istifadə etmək.</p>"),
        ("sql", "SQL və verilənlər bazası nədir?", "sql database baza sorgu mysql postgres",
         "<p>Verilənlər bazası saytın məlumat anbarıdır: istifadəçilər, sifarişlər, məhsullar. SQL bazaya sual vermək dilidir. Məsələn: «ünvanı bu olan istifadəçini tap».</p>"),
        ("sql-injection", "SQL injection nədir?", "sql injection inyeksiya injeksiya sqli baza hucum parametr",
         "<p>Sayt istifadəçinin yazdığı mətni birbaşa SQL sorğusunun içinə qoyanda hücumçu mətnin içinə öz SQL əmrini yaza bilər və sayt onu icra edir. Nəticədə hücumçu bütün istifadəçi siyahısını oxuya, silə və ya admin kimi girə bilər. "
         "Bu, onilliklərdir bilinən, amma hələ də ən təhlükəli hücumlardandır. Qorunma: sorğunu «parametrli» (prepared statement) yazmaq; əksər hazır kitabxana bunu avtomatik edir.</p>"),
        ("csrf", "CSRF nədir?", "csrf cross site request forgery sorgu saxtakarligi",
         "<p>CSRF-də hücumçu sizi girişli olduğunuz saytda istəmədiyiniz əməliyyata məcbur edir. Məsələn, banka giriş edib başqa tabda zərərli səhifəyə baxırsınız və həmin səhifə gizli şəkildə «pul köçür» sorğusu göndərir. "
         "Qorunma: hər formada təsadüfi token və kukidə <i>SameSite</i> bayrağı.</p>"),
        ("fishinq", "Fişinq (phishing) nədir?", "phishing fishing saxta sayt parol aldatma",
         "<p>Fişinq real sayta və ya banka bənzəyən saxta səhifə və ya məktubla parolunuzu, kart məlumatınızı almaq cəhdidir. Əlamətlər: təcili tələb, qəribə ünvan, düzgün olmayan domen. "
         "SPF/DMARC saxta e-poçtu azaldır, HTTPS isə sizin saytınızın saxta olmadığını sübut edir.</p>"),
        ("brute-force", "Brute force (kobud güc) hücumu nədir?", "brute force parol sinama giris hucum",
         "<p>Hücumçu giriş formasında minlərlə parolu ardıcıl sınayır. Qorunma: uzun və təkrarlanmayan parol, giriş cəhdlərinə limit (rate limit), iki mərhələli təsdiq (2FA).</p>"),
        ("ddos", "DDoS nədir?", "ddos dos hucum yuk sayt dayanir",
         "<p>DDoS-da minlərlə cihazdan saytınıza eyni anda sorğu göndərilir və server dözməyib dayanır. Kiçik saytlar üçün adətən CDN (Cloudflare, Vercel) bunu özü azaldır. SaytYoxla özü də limit qoyur ki, həmin yoxlayıcı sui-istifadə olunmasın.</p>"),
        ("malware", "Zərərli proqram (malware) nədir?", "malware zererli proqram virus hack sındırılma",
         "<p>Sındırılmış saytda hücumçu çox vaxt gizli zərərli kod yerləşdirir: ziyarətçini başqa saytlara atır, reklam göstərir, kart məlumatını oğurlayır. Əlamətlər: sayt qəfil yavaşlayır, Google «bu sayt zərərli ola bilər» xəbərdarlığı göstərir, naməlum səhifələr peyda olur. "
         "Əsas səbəblər köhnə plaginlər, zəif parol və yenilənməyən proqramdır.</p>"),
        ("prompt-injection", "Prompt injection nədir?", "prompt injection ai sunii intellekt llm agent provguard",
         "<p>Prompt injection süni intellekt (LLM) əsaslı proqramlara qarşı hücumdur: hücumçu sənədin, e-poçtun və ya veb səhifənin içinə AI-ya ünvanlanmış gizli əmr yazır («əvvəlki təlimatları unut və ...»). AI bunu istifadəçinin əmri kimi qəbul edib istənilməyən iş görə bilər. "
         "Süni intellektli köməkçi və ya çatbot qurursunuzsa, bu risk sizin üçün də aktualdır. Bu mövzuda ayrıca açıq mənbəli alətimiz var: ProvGuard (<a href=\"https://provguard.vercel.app\" rel=\"noopener\">provguard.vercel.app</a>), "
         "və izahlı məqalə: <a href=\"https://ayfar.dev/articles/provguard.html\" rel=\"noopener\">ayfar.dev/articles/provguard.html</a>.</p>"),
    ]),
    ("5. Google və sürət", [
        ("seo", "SEO nədir?", "seo axtaris sistemi google sira optimallasdirma",
         "<p>SEO saytı Google-da daha yuxarıda göstərməyə kömək edən işlərin məcmusudur: düzgün başlıq, təsvir, sürət, telefona uyğunluq, faydalı məzmun. "
         "Dürüst olaq: SaytYoxla SEO-nun texniki əsaslarını yoxlayır, amma sıralamanı təmin etmir. Google-da yuxarı çıxmaq məzmundan, rəqabətdən və zamandan da asılıdır.</p>"),
        ("title-description", "Title və meta description nədir?", "title basliq meta description tesvir google netice",
         "<p><b>Title</b> brauzer tabında və Google nəticəsində göstərilən mavi başlıqdır (ideal 10–70 simvol). <b>Meta description</b> nəticənin altındakı qısa izahdır (ideal 50–170 simvol). "
         "Hər səhifənin öz başlığı və təsviri olmalıdır. Onlar yoxdursa, Google özü təsadüfi mətn seçir və klik azalır. Hər biri SaytYoxla-da yoxlanılır.</p>"),
        ("h1", "H1 başlıq nədir?", "h1 basliq heading sehife",
         "<p>H1 səhifənin əsas başlığıdır; hər səhifədə bir dənə olmalıdır. Google və ekran oxuyucuları səhifənin nə haqqında olduğunu ondan başa düşür.</p>"),
        ("viewport", "Viewport və telefona uyğunluq nədir?", "viewport mobil telefon responsive uygunluq meta",
         "<p>Viewport teqi telefona deyir: «səhifəni ekranın eninə uyğun göstər». Olmayanda telefon saytı kompüter ölçüsündə açıb kiçildir və oxumaq mümkün olmur. Google mobil uyğunluğu sıralamada nəzərə alır. SaytYoxla-da 8 bal.</p>"),
        ("robots-sitemap", "robots.txt və sitemap.xml nədir?", "robots txt sitemap xml axtaris robotu indeks",
         "<p><b>robots.txt</b> axtarış robotlarına hansı hissələrə girə biləcəklərini və girə bilməyəcəklərini deyir. <b>sitemap.xml</b> saytın bütün səhifələrinin siyahısıdır; Google-a «mənim səhifələrim bunlardır» demək üçündür. "
         "Əgər robots.txt-də səhvən hər şey bağlanıbsa, sayt Google-da heç çıxmaz.</p>"),
        ("noindex", "Noindex və indeksləmə nədir?", "noindex indeks indexing google gorunmur",
         "<p>İndeksləmə Google-un səhifəni öz bazasına əlavə etməsidir. Səhifədə <i>noindex</i> teqi varsa, Google onu bazaya qoymur və o, axtarışda çıxmır. "
         "Tez-tez sayt hazırlanarkən qoyulan noindex işə düşəndən sonra unudulur. «Saytım niyə Google-da yoxdur?» sualının ən çox rast gəlinən cavabı budur. 6 bal.</p>"),
        ("canonical", "Canonical nədir?", "canonical link dublikat sehife",
         "<p>Canonical teqi Google-a «bu səhifənin əsas ünvanı budur» deyir. Eyni səhifə bir neçə ünvanda açılırsa (www ilə və ya olmadan), Google bunları qarışdırmasın deyə lazımdır.</p>"),
        ("lang-og", "Səhifənin dili və sosial şəbəkə kartı (Open Graph) nədir?", "lang dil og open graph sosial kart paylasim whatsapp",
         "<p><b>lang</b> teqi səhifənin dilini bildirir (az, en, ru); brauzer tərcümə təklifi və ekran oxuyucuları ondan istifadə edir. "
         "<b>Open Graph (og)</b> teqləri linki WhatsApp, Instagram və ya LinkedIn-də paylaşanda çıxan şəkil və başlığı müəyyən edir. Onlar olmasa, link boş və etibarsız görünür. Hər biri 2 bal.</p>"),
        ("cavab-vaxti", "Serverin cavab vaxtı və səhifənin həcmi nədir?", "surət speed cavab vaxti ms html olcu size yavas",
         "<p>İnsanlar yavaş saytı tərk edir. SaytYoxla serverin cavab vaxtını ölçür: 1500 ms-dən az yaxşı, 4000 ms-ə qədər xəbərdarlıq, ondan çox pisdir (8 bal). "
         "HTML həcmi də ölçülür: 300 KB-dan azı yaxşı, 1000 KB-a qədər xəbərdarlıq (4 bal). Bunlar saytın tam yüklənməsi deyil, yalnız serverin cavab sürətidir.</p>"),
        ("sixilma-http2", "Sıxılma (gzip, brotli) və HTTP/2 nədir?", "gzip brotli sixilma compression http2 http/2 suret protokol",
         "<p><b>Sıxılma</b> serverin səhifəni göndərməzdən əvvəl kiçiltməsidir (gzip və ya brotli); brauzer onu özü açır. Mətn 3–5 dəfə kiçilir, zəif internetdə fərq dərhal hiss olunur. "
         "SaytYoxla serverin cavabında sıxılma olub-olmadığına baxır (3 bal); 1400 baytdan kiçik səhifədən bunu tələb etmir.</p>"
         "<p><b>HTTP/2</b> brauzerlə serverin danışdığı qaydanın yeni versiyasıdır: şəkil, stil və skriptlər bir bağlantı ilə, eyni vaxtda gəlir. Köhnə HTTP/1.1-də onlar növbə gözləyir. "
         "Əksər hostinqlərdə HTTP/2 paneldən pulsuz açılır (2 bal).</p>"),
        ("alt-schema", "Şəkil təsviri (alt) və Schema.org nədir?", "alt sekil tesvir img schema json-ld strukturlasdirilmis melumat localbusiness",
         "<p><b>alt</b> şəklin qısa mətn təsviridir: <i>&lt;img src=\"...\" alt=\"Qırmızı divan\"&gt;</i>. Google şəkli görmür, bu mətni oxuyur; görmə çətinliyi olan insanların proqramı da onu səsləndirir. "
         "Sırf bəzək olan şəkilə boş <i>alt=\"\"</i> yazılır. Təsviri olmayan şəkil varsa, SaytYoxla tövsiyə verir (2 bal).</p>"
         "<p><b>Schema.org</b> (JSON-LD) səhifəyə əlavə olunan, insanın görmədiyi kiçik məlumat blokudur: biznesin adı, ünvanı, telefonu, iş saatları. "
         "Google bunu oxuyub biznesi daha dəqiq tanıyır (1 bal).</p>"),
        ("core-web-vitals", "Core Web Vitals nədir?", "core web vitals lcp cls inp lighthouse pagespeed",
         "<p>Core Web Vitals Google-un səhifə təcrübəsini ölçdüyü üç göstəricidir: əsas məzmunun nə vaxt görünməsi (LCP), səhifənin yüklənərkən «atlanması» (CLS) və toxunuşa cavab verməsi (INP). "
         "Dürüst qeyd: SaytYoxla bunları ölçmür; bunun üçün brauzerin tam yüklənməsi lazımdır. Onları Google-un PageSpeed Insights və ya Lighthouse alətində yoxlaya bilərsiniz.</p>"),
    ]),
    ("6. SaytYoxla necə işləyir", [
        ("bal-hesablanma", "Bal necə hesablanır?", "bal hesablama qiymet a b c d f cap",
         "<p>SaytYoxla 30 yoxlama aparır; bunlardan 28-i ballıdır (TLS və DKIM yalnız məlumat üçündür). Hər yoxlamanın çəkisi var: ən ağırları HTTPS (20), sertifikat (15) və SPF (10), sonra 8 baldan başlayaraq daha kiçikləri. Cəmi 151 çəkidir və 100-ə çevrilir. "
         "Uğursuz yoxlama bütün çəkisini aparır, xəbərdarlıq yarısını.</p>"
         "<p>Qiymət: 90 və üstü A, 75 və üstü B, 60 və üstü C, 40 və üstü D, ondan aşağı F. Üstəlik həddlər var: HTTPS işləmirsə bal 39-dan, sertifikat etibarsızdırsa 59-dan yuxarı çıxmır. "
         "Beş əsas qoruyucudan (yönləndirmə, HSTS, clickjacking, nosniff, CSP) 4-ü və daha çoxu problemlidirsə, bal 74-dən, 2-si problemlidirsə 89-dan yuxarı çıxmır. Yəni zəif təhlükəsizlik başqa yaxşı nəticələrlə «örtülə» bilməz.</p>"),
        ("nezaman-yoxlayir", "SaytYoxla nəyi yoxlayır, nəyi yoxlamır?", "yoxlayir yoxlamir hedd mehdudiyyet audit",
         "<p><b>Yoxlayır:</b> HTTPS, sertifikat, başlıqlar, kuki bayraqları, SPF/DMARC/DKIM, sürət, telefona uyğunluq və Google üçün əsas teqləri, yəni kənardan hər kəsin görə biləcəyi hər şeyi. Hamısı sayta zərər vermədən: əsas səhifə, robots.txt və sitemap.xml bir dəfə açılır.</p>"
         "<p><b>Yoxlamır:</b> saytın daxili kodunu, serverin içini, parolları, bazanı, proqramın məntiqini. Bu tam təhlükəsizlik auditi deyil. Yüksək bal «sayt tam təhlükəsizdir» demək deyil, aşağı bal da «sayt sındırılıb» demək deyil.</p>"),
        ("deep-scan", "Dərin analiz və sahiblik təsdiqi nədir?", "deep scan derin analiz sahiblik tesdiq dns fayl port sql xss yoxlama",
         "<p>Dərin analiz saytın xarici səthinə baxır: subdomenlər, DNS, köhnə proqram versiyaları, açıq fayl və portlar. Bəzi hissələri yalnız sayt sizindir deyə sübut etdikdən sonra (DNS qeydi və ya fayl ilə) işləyir; başqasının saytında açıq fayl axtarmaq düzgün olmazdı. "
         "Təsdiqdən sonra ünvan parametrləri SQL injection və XSS üçün yalnız oxuyan, zərərsiz sorğularla sınanır (məsələn tək dırnaq və <i>AND 1=1</i> / <i>AND 1=2</i> müqayisəsi). Heç nə silinmir, dəyişdirilmir və ya yazılmır. Tapılan fayl və ya açarın məzmunu göstərilmir və saxlanmır.</p>"),
        ("netice-oxu", "Nəticəni necə oxumalı?", "netice hesabat oxumaq qirmizi sari yasil prioritet",
         "<p>Hesabatda hər yoxlama üç rəngdən birini alır: yaşıl (qaydasındadır), sarı (xəbərdarlıq) və qırmızı (problem). Əvvəlcə qırmızılara baxın: onlar balı ən çox azaldır. "
         "Hər problemin altında nə edilməli olduğu yazılıb; bunu saytı quran proqramçıya göstərmək kifayətdir. Nəticə yalnız o anın şəklidir: sayt dəyişəndə təkrar yoxlayın.</p>"),
        ("mexfilik-xulase", "SaytYoxla hansı məlumatı saxlayır?", "mexfilik gizlilik kuki izleme saxlanir ip",
         "<p>Ad, telefon və ya e-poçt soruşmur, kuki və izləmə skripti yoxdur. Yoxlanılan ünvan və nəticə təkrar yoxlamanı sürətləndirmək üçün 10 dəqiqəyə qədər serverin yaddaşında qalır, IP ünvanı isə sui-istifadəni məhdudlaşdıran sayğacda ən çox 1 gün. "
         "Ətraflı: <a href=\"/mexfilik/\">Məxfilik</a>.</p>"),
    ]),
    ("7. Saytın qorunması üçün praktik məsləhətlər", [
        ("yenileme", "Yeniləmələr və köhnə proqram", "yenileme update plugin wordpress kohne versiya zeiflik cve",
         "<p>Sındırılan saytların böyük hissəsində səbəb köhnə proqramdır (WordPress, plaginlər, kitabxanalar). Zəifliklər açıq elan olunur və robotlar milyonlarla saytı avtomatik axtarır. Yeniləməni təxirə salmayın, işlətmədiyiniz plaginləri silin. Bilinən zəifliklər <b>CVE</b> nömrəsi ilə qeyd olunur.</p>"),
        ("parol-2fa", "Parol və iki mərhələli təsdiq (2FA)", "parol 2fa iki merhele sifre manager",
         "<p>Hər xidmət üçün ayrıca uzun parol, parol meneceri və admin panellərdə 2FA. Domen şirkəti, hosting və e-poçt hesabını xüsusilə qoruyun: bunlar ələ keçirilsə, hücumçu sayta və poçta sahib olur.</p>"),
        ("backup", "Ehtiyat nüsxə (backup)", "backup ehtiyat nusxe berpa",
         "<p>Sayt sındırılsa, silinsə və ya server sıradan çıxsa, ehtiyat nüsxə sizi xilas edir. Avtomatik, ayrı yerdə saxlanan və ara-sıra bərpası sınanan nüsxə lazımdır.</p>"),
        ("cdn-waf", "CDN və WAF nədir?", "cdn waf cloudflare firewall qoruma",
         "<p><b>CDN</b> saytın surətini dünyanın müxtəlif yerlərində saxlayıb ziyarətçiyə yaxın serverdən verir; saytı sürətləndirir. <b>WAF</b> (Web Application Firewall) saytın qarşısında zərərli sorğuları süzən qalxandır. Cloudflare kimi xidmətlər hər ikisini pulsuz planda da verir.</p>"),
        ("security-txt", "security.txt nədir?", "security txt zeiflik bildiris elaqe",
         "<p><i>/.well-known/security.txt</i> faylı təhlükəsizlik tədqiqatçısına zəiflik tapanda kimə yazmalı olduğunu göstərir. Kiçik, amma ciddi saytın əlamətidir.</p>"),
    ]),
]

# one reading of the page: what a term title looks like in the search results and how the index is read
SEARCH_LABEL = "Sözə görə axtarın (məsələn: DMARC, HTTPS, SQL)"


def _term(id_: str, title: str, keys: str, body: str) -> str:
    return f'<section class="term" id="{id_}" data-k="{escape(keys)}">\n<h3>{title}</h3>\n{body}\n</section>'


def body() -> str:
    parts = [f'<h1>{TITLE}</h1>',
             '<p class="meta">Saytınız necə işləyir və necə qorunur? Sadə dillə.</p>',
             f'''<div class="gl-search" id="gl-search" hidden>
<label for="gl-q">{SEARCH_LABEL}</label>
<input id="gl-q" type="search" autocomplete="off" spellcheck="false" placeholder="Axtar…">
<ul id="gl-results" role="listbox" aria-label="Nəticələr" hidden></ul>
<p id="gl-status" class="meta" role="status" aria-live="polite"></p>
</div>''',
             f'<div id="gl-text">{INTRO}']
    for title, terms in SECTIONS:
        parts.append(f'<h2 class="sec">{title}</h2>')
        parts.extend(_term(*t) for t in terms)
    parts.append('</div>')
    parts.append(f'<p class="meta">Sual və ya təklif: {CONTACT}</p>')
    parts.append(f'<p><a class="btn" href="{HOMES["az"]}">Saytı yoxla</a></p>')
    parts.append('<script src="/static/glossary.js" defer></script>')
    return "\n".join(parts)


STYLE_EXTRA = """
.gl-search{position:sticky;top:0;z-index:5;background:var(--bg);padding:10px 0 8px;margin:6px 0 4px;border-bottom:1px solid var(--line)}
.gl-search label{display:block;font-weight:700;font-size:14px;margin-bottom:6px}
.gl-search input{width:100%;font:inherit;font-size:16px;padding:12px 14px;border:1px solid var(--line-2);border-radius:12px;background:#fff;color:var(--ink)}
.gl-search input:focus{outline:3px solid #93b4ff;outline-offset:1px}
#gl-results{list-style:none;margin:8px 0 0;padding:0;max-height:46vh;overflow:auto;border:1px solid var(--line-2);border-radius:12px;background:#fff}
#gl-results li{margin:0}
#gl-results button{display:block;width:100%;text-align:left;font:inherit;font-size:15px;padding:12px 14px;min-height:44px;border:0;border-bottom:1px solid var(--line);background:none;color:var(--ink);cursor:pointer}
#gl-results li:last-child button{border-bottom:0}
#gl-results button:hover,#gl-results button:focus-visible,#gl-results button[aria-selected=true]{background:#e8efff}
#gl-results small{display:block;color:var(--muted);font-size:13px}
h2.sec{margin-top:40px;padding-top:6px;border-top:2px solid var(--line)}
section.term,h2.term{scroll-margin-top:150px}
section.term h3{font-size:17px;margin:22px 0 6px;color:var(--ink)}
mark{background:#fde68a;color:#1a1200;border-radius:3px;padding:0 1px}
.flash{animation:flash 2.2s ease-out}
@keyframes flash{0%,35%{background:#dbe7ff;box-shadow:0 0 0 8px #dbe7ff}100%{background:transparent;box-shadow:0 0 0 8px transparent}}
@media (prefers-reduced-motion:reduce){.flash{animation:none;background:#dbe7ff}html{scroll-behavior:auto!important}}
@media screen and (prefers-color-scheme:dark){
.gl-search input,#gl-results{background:#131c2e}
#gl-results button:hover,#gl-results button:focus-visible,#gl-results button[aria-selected=true]{background:#1c2c4a}
mark{background:#7a5d00;color:#fff}
@keyframes flash{0%,35%{background:#1c3a63;box-shadow:0 0 0 8px #1c3a63}100%{background:transparent;box-shadow:0 0 0 8px transparent}}
.flash{--x:0}
}
"""


def page() -> str:
    html = _shell("az", TITLE, DESC, body(), {"az": PATH, "en": HOMES["en"], "ru": HOMES["ru"]})
    html = html.replace('<link rel="icon"', f'<link rel="canonical" href="{SITE_URL}{PATH}">\n<link rel="icon"', 1)
    return html.replace("</style>", STYLE_EXTRA + "</style>", 1)
