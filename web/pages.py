"""
Small static pages in three languages: about, privacy, terms and the 404 page.

What the privacy page says must stay true of the code: the report cache in web/app.py (10 minutes),
the rate-limit counters in web/ratelimit.py (up to a day) and the absence of cookies and analytics.
"""

from __future__ import annotations

import json
import re
from html import escape

from web.seo import SITE_URL

LANGS = ("az", "en", "ru")
HOMES = {"az": "/", "en": "/en/", "ru": "/ru/"}
PATHS = {
    "about": {"az": "/haqqimizda/", "en": "/en/about/", "ru": "/ru/o-nas/"},
    "privacy": {"az": "/mexfilik/", "en": "/en/privacy/", "ru": "/ru/konfidencialnost/"},
    "terms": {"az": "/sertler/", "en": "/en/terms/", "ru": "/ru/usloviya/"},
}
ROUTES = {path: (key, lang) for key, by_lang in PATHS.items() for lang, path in by_lang.items()}
# The Tools page is the React app again (react-ui/src/ToolsApp.tsx) with its own title and addresses
TOOLS_PATHS = {"az": "/aletler/", "en": "/en/tools/", "ru": "/ru/instrumenty/"}
TOOLS_META = {  # short name, <title>, description, heading
    "az": ("Alətlər", "SSL, DMARC, SPF, DKIM yoxlama alətləri | SaytYoxla",
           "SSL, DMARC, SPF və DKIM-i ayrıca yoxlayın. DMARC, SPF, CSP, başlıqlar, robots.txt və sitemap üçün hazır qeydlər yaradın. Pulsuz.",
           "Sayt alətləri"),
    "en": ("Tools", "SSL, DMARC, SPF and DKIM checkers | SaytYoxla",
           "Check SSL, DMARC, SPF and DKIM on their own. Create ready-made DMARC, SPF, CSP, header, robots.txt and sitemap records for free.",
           "Website tools"),
    "ru": ("Инструменты", "Проверка SSL, DMARC, SPF и DKIM | SaytYoxla",
           "Проверьте по отдельности SSL, DMARC, SPF и DKIM. Создайте готовые записи DMARC, SPF, CSP, заголовки, robots.txt и sitemap. Бесплатно.",
           "Инструменты для сайта"),
}
# Two to four sites side by side (web/compare.py, web/static/compare.js)
COMPARE_PATHS = {"az": "/muqayise/", "en": "/en/compare/", "ru": "/ru/sravnenie/"}
COMPARE_NAME = {"az": "Müqayisə", "en": "Compare", "ru": "Сравнение"}
GLOSSARY_PATHS = {"az": "/lugat/", "en": "/en/glossary/", "ru": "/ru/slovar/"}
GLOSSARY_NAME = {"az": "Lüğət", "en": "Glossary", "ru": "Словарь"}
LINKS = {
    "about": {"az": "Haqqımızda", "en": "About", "ru": "О сервисе"},
    "privacy": {"az": "Məxfilik", "en": "Privacy", "ru": "Конфиденциальность"},
    "terms": {"az": "Şərtlər", "en": "Terms", "ru": "Условия"},
}
UPDATED = {"az": "Son yenilənmə: 5 noyabr 2026", "en": "Last updated: 5 November 2026", "ru": "Обновлено: 5 ноября 2026"}

WHATSAPP = '<a href="https://wa.me/994772172358" target="_blank" rel="noopener">WhatsApp</a>'
LINKEDIN = '<a href="https://www.linkedin.com/in/ziyaazizov" target="_blank" rel="noopener">LinkedIn</a>'
INSTAGRAM = '<a href="https://www.instagram.com/ayfar.web/" target="_blank" rel="noopener">Instagram</a>'
CONTACT = f"{WHATSAPP} · {LINKEDIN} · {INSTAGRAM}"

# key -> lang -> (title, meta description, body)
CONTENT = {
    "about": {
        "az": ("SaytYoxla haqqında", "SaytYoxla kiçik bizneslər üçün saytın təhlükəsizliyini, e-poçt qorumasını və sürətini pulsuz yoxlayan alətdir.", f"""
<p>SaytYoxla kiçik biznes sahibləri və sayt quranlar üçün pulsuz alətdir. Saytın ünvanını yazırsınız, biz təhlükəsizlik, e-poçt qoruması, sürət və telefona uyğunluq ayarlarını yoxlayıb nəticəni sadə dildə izah edirik.</p>
<h2>Necə işləyir?</h2>
<p>Yalnız hər kəsə açıq olan məlumata baxırıq: əsas səhifəni, onun yüklədiyi faylları (skript, üslub, şəkil), robots.txt və sitemap.xml fayllarını bir dəfə açırıq, sertifikatı və açıq DNS qeydlərini oxuyuruq. Saytı sındırmağa çalışmırıq və heç nəyi dəyişmirik. Açıq fayl və portlara yalnız saytın sahibi bunu təsdiq etdikdən sonra baxırıq. Bu, tam təhlükəsizlik auditi deyil: kənardan görünməyən problemləri aşkar edə bilmir.</p>
<h2>Müəllif</h2>
<p>SaytYoxla-nı Ziya Azizov hazırlayıb.</p>
<h2>Əlaqə</h2>
<p>{CONTACT}</p>"""),
        "en": ("About SaytYoxla", "SaytYoxla is a free tool that checks a website's security, e-mail protection and speed for small businesses.", f"""
<p>SaytYoxla is a free tool for small business owners and the people who build their websites. You enter a site's address, and we check its security, e-mail protection, speed and mobile settings, then explain the result in plain words.</p>
<h2>How it works</h2>
<p>We only look at information that is open to everyone: we open the home page, the files it loads (scripts, styles, images), robots.txt and sitemap.xml once and read the certificate and public DNS records. We do not try to break into the site and we change nothing. Exposed files and ports are looked at only after the site's owner has confirmed it. This is not a full security audit: it cannot find problems that are not visible from outside.</p>
<h2>Author</h2>
<p>SaytYoxla was made by Ziya Azizov.</p>
<h2>Contact</h2>
<p>{CONTACT}</p>"""),
        "ru": ("О сервисе SaytYoxla", "SaytYoxla — бесплатный инструмент для малого бизнеса: проверка безопасности сайта, защиты почты и скорости.", f"""
<p>SaytYoxla — бесплатный инструмент для владельцев малого бизнеса и тех, кто делает им сайты. Вы вводите адрес сайта, а мы проверяем безопасность, защиту почты, скорость и адаптацию под телефон и объясняем результат простыми словами.</p>
<h2>Как это работает</h2>
<p>Мы смотрим только на открытую информацию: один раз открываем главную страницу, файлы, которые она загружает (скрипты, стили, изображения), robots.txt и sitemap.xml, читаем сертификат и открытые DNS-записи. Мы не пытаемся взломать сайт и ничего не меняем. Открытые файлы и порты мы смотрим только после подтверждения владельцем сайта. Это не полный аудит безопасности: проблемы, которые не видны снаружи, он найти не может.</p>
<h2>Автор</h2>
<p>SaytYoxla создал Ziya Azizov.</p>
<h2>Контакты</h2>
<p>{CONTACT}</p>"""),
    },
    "privacy": {
        "az": ("Məxfilik", "SaytYoxla hansı məlumatı nə qədər saxlayır: ünvan və nəticə 10 dəqiqə, IP sayğacı ən çox 1 gün. Kuki və izləmə yoxdur.", f"""
<p>SaytYoxla qeydiyyat tələb etmir, adınızı və telefonunuzu soruşmur. E-poçt yalnız daimi izləməni özünüz seçsəniz lazımdır.</p>
<h2>Nə saxlanılır?</h2>
<ul>
<li><b>Yoxlanılan ünvan və nəticə:</b> təkrar yoxlamanı sürətləndirmək üçün serverin yaddaşında 10 dəqiqəyə qədər qalır. Nəticə sizin adınızla bağlanmır.</li>
<li><b>IP ünvanınız:</b> sui-istifadənin qarşısını almaq üçün yoxlama sayını hesablayan sayğacda ən çox 1 gün qalır.</li>
<li><b>Hostinq jurnalları:</b> sayt Vercel-də işləyir. Vercel xidmətin işləməsi üçün texniki sorğu jurnalları apara bilər.</li>
</ul>
<h2>Nə istifadə olunmur?</h2>
<p>Saytda reklam, izləmə skriptləri və kuki faylları yoxdur. Şriftlər də öz serverimizdən yüklənir.</p>
<h2>Yoxlanılan sayt nə görür?</h2>
<p>Yoxlama zamanı saytın əsas səhifəsi, onun yüklədiyi fayllar (skript, üslub, şəkil), robots.txt və sitemap.xml faylları serverimizdən bir dəfə açılır. Sayt sizin IP ünvanınızı yox, serverimizin ünvanını görür.</p>
<h2>Dərin analiz</h2>
<p>Dərin analiz domen adını sertifikat qeydlərinə (Cert Spotter, crt.sh), qeydiyyat bazasına (rdap.org, IP ünvanı ilə birlikdə) və DNS qara siyahılarına, saytda görünən kitabxananın adı və versiyasını isə zəiflik bazasına (OSV) göndərir. Server proqramının versiyası NVD-yə (nvd.nist.gov), plaginlərin adı wordpress.org-a gedir, açarlar qoşulubsa WPScan, Spamhaus və Google Safe Browsing də sorğulanır. Sayt tərəfdən əsas səhifə, onun öz skriptləri (ən çox 6), robots.txt və security.txt oxunur və TLS bağlantısı sınanır. Əvvəlki yoxlama ilə müqayisə yalnız sizin brauzerinizdə (localStorage) saxlanılır, serverə getmir.</p>
<p>Dərin yoxlama (açıq fayllar, qovluqlar, portlar, DNS zonası və saytın 30 səhifəyə qədər oxunması, həmçinin ünvan parametrlərinin SQL injection və reflected XSS üçün yalnız oxuyan, dağıdıcı olmayan sorğularla sınağı) yalnız saytın sizin olduğunu DNS qeydi və ya fayl ilə sübut etdikdən sonra işləyir. Fayl və ya açar tapılsa, yalnız yolu və növü göstərilir, məzmunu nə göstərilir, nə də saxlanılır.</p>\n<h2>İzləmə</h2>\n<p>Daimi izləməni özünüz başlatsanız, e-poçt ünvanınız, saytın adı və son yoxlamanın nəticəsi Upstash Redis-də saxlanılır, məktublar Brevo ilə göndərilir. Ünvan yalnız linkə basıb təsdiqlədikdən sonra saxlanılır və hər məktubdakı linklə silinir.</p>
<h2>WhatsApp</h2>
<p>«WhatsApp-a yazın» düyməsini bassanız, hazır mesaj WhatsApp-da açılır və onu siz özünüz göndərirsiniz. Bundan sonra WhatsApp-ın öz qaydaları tətbiq olunur.</p>
<h2>Əlaqə</h2>
<p>Suallarınız üçün: {CONTACT}</p>"""),
        "en": ("Privacy", "What SaytYoxla keeps and for how long: address and result for 10 minutes, IP counter for up to 1 day. No cookies or tracking.", f"""
<p>SaytYoxla needs no sign-up and does not ask for your name or phone. An e-mail address is needed only if you choose ongoing watching yourself.</p>
<h2>What is kept</h2>
<ul>
<li><b>The checked address and its result:</b> stay in the server's memory for up to 10 minutes to speed up a repeat check. The result is not tied to your name.</li>
<li><b>Your IP address:</b> stays for up to 1 day in the counter that limits the number of checks, to prevent abuse.</li>
<li><b>Hosting logs:</b> the site runs on Vercel, which may keep technical request logs to operate its service.</li>
</ul>
<h2>What is not used</h2>
<p>The site has no ads, no tracking scripts and no cookies. Fonts are loaded from our own server too.</p>
<h2>What the checked site sees</h2>
<p>During a check, the site's home page, the files it loads (scripts, styles, images), robots.txt and sitemap.xml are opened once from our server. The site sees our server's address, not your IP address.</p>
<h2>Deep analysis</h2>
<p>The deep analysis sends the domain name to certificate logs (Cert Spotter, crt.sh), a registration database (rdap.org, along with the IP address) and DNS blocklists, and the name and version of a library visible on the site to a vulnerability database (OSV). A server program's version goes to NVD (nvd.nist.gov) and plugin names to wordpress.org, and when keys are set WPScan, Spamhaus and Google Safe Browsing are asked too. On the site itself the home page, its own scripts (6 at most), robots.txt and security.txt are read, and TLS connections are tried. The comparison with an earlier check is kept only in your browser (localStorage) and does not reach the server.</p>
<p>The deep check (exposed files, folders, ports, the DNS zone and reading up to 30 pages of the site, and testing address parameters for SQL injection and reflected XSS with read-only, non-destructive requests) runs only after you prove the site is yours with a DNS record or a file. If a file or key is found, only its path and kind are shown; its content is neither shown nor stored.</p>\n<h2>Watching</h2>\n<p>If you start ongoing watching yourself, your e-mail address, the site's name and the last check's result are kept in Upstash Redis, and messages are sent through Brevo. The address is kept only after you confirm by its link, and the link in each message deletes it.</p>
<h2>WhatsApp</h2>
<p>If you press "Message on WhatsApp", a prepared message opens in WhatsApp and you send it yourself. WhatsApp's own rules apply from there.</p>
<h2>Contact</h2>
<p>For questions: {CONTACT}</p>"""),
        "ru": ("Конфиденциальность", "Что и как долго хранит SaytYoxla: адрес и результат 10 минут, счётчик IP до 1 дня. Без cookie и отслеживания.", f"""
<p>SaytYoxla не требует регистрации и не спрашивает имя и телефон. E-mail нужен, только если вы сами выберете постоянное наблюдение.</p>
<h2>Что хранится</h2>
<ul>
<li><b>Проверенный адрес и результат:</b> до 10 минут в памяти сервера, чтобы ускорить повторную проверку. Результат не связан с вашим именем.</li>
<li><b>Ваш IP-адрес:</b> до 1 дня в счётчике, который ограничивает число проверок, чтобы предотвратить злоупотребления.</li>
<li><b>Журналы хостинга:</b> сайт работает на Vercel, который может вести технические журналы запросов для работы своего сервиса.</li>
</ul>
<h2>Что не используется</h2>
<p>На сайте нет рекламы, скриптов отслеживания и cookie. Шрифты тоже загружаются с нашего сервера.</p>
<h2>Что видит проверяемый сайт</h2>
<p>При проверке главная страница сайта, файлы, которые она загружает (скрипты, стили, изображения), robots.txt и sitemap.xml один раз открываются с нашего сервера. Сайт видит адрес нашего сервера, а не ваш IP-адрес.</p>
<h2>Глубокий анализ</h2>
<p>Глубокий анализ отправляет имя домена в журналы сертификатов (Cert Spotter, crt.sh), базу регистрации (rdap.org, вместе с IP-адресом) и чёрные списки DNS, а название и версию библиотеки, видимой на сайте, в базу уязвимостей (OSV). Версия серверной программы уходит в NVD (nvd.nist.gov), названия плагинов на wordpress.org, а при наличии ключей запрашиваются также WPScan, Spamhaus и Google Safe Browsing. На самом сайте читаются главная страница, её собственные скрипты (не более 6), robots.txt и security.txt и проверяются соединения TLS. Сравнение с прошлой проверкой хранится только в вашем браузере (localStorage) и на сервер не передаётся.</p>
<p>Глубокая проверка (открытые файлы, папки, порты, зона DNS и чтение до 30 страниц сайта, а также проверка параметров адреса на SQL-инъекции и отражённую XSS только читающими, неразрушающими запросами) работает только после того, как вы докажете записью DNS или файлом, что сайт ваш. Если найден файл или ключ, показываются только путь и вид, а содержимое не показывается и не хранится.</p>\n<h2>Наблюдение</h2>\n<p>Если вы сами запустите постоянное наблюдение, ваш e-mail, имя сайта и результат последней проверки хранятся в Upstash Redis, а письма отправляются через Brevo. Адрес сохраняется только после подтверждения по ссылке и удаляется ссылкой из любого письма.</p>
<h2>WhatsApp</h2>
<p>Если вы нажмёте «Написать в WhatsApp», готовое сообщение откроется в WhatsApp, и отправляете его вы сами. Дальше действуют правила WhatsApp.</p>
<h2>Контакты</h2>
<p>По вопросам: {CONTACT}</p>"""),
    },
    "terms": {
        "az": ("İstifadə şərtləri", "SaytYoxla pulsuzdur və yalnız açıq məlumatı yoxlayır. Nəticə məlumat xarakterlidir və tam təhlükəsizlik auditi deyil.", f"""
<h2>Xidmət</h2>
<p>SaytYoxla pulsuzdur və olduğu kimi təqdim olunur. Xidmətin fasiləsiz işləyəcəyinə zəmanət verilmir.</p>
<h2>Nəticənin mənası</h2>
<p>Bal və tövsiyələr yalnız kənardan görünən ayarlara əsaslanır və məlumat xarakterlidir. Yüksək bal saytın tam təhlükəsiz olduğunu göstərmir, aşağı bal isə saytın sındırıldığını bildirmir. Vacib qərarlar üçün mütəxəssislə məsləhətləşin.</p>
<h2>İstifadə qaydası</h2>
<ul>
<li>Xidmətdən başqa saytlara ziyan vurmaq və ya onu həddindən artıq yükləmək üçün istifadə etməyin.</li>
<li>Limitlər var: bir IP ünvanından dəqiqədə 6, gündə 60 təzə yoxlama. Dərin analizin hər hissəsi ayrıca sayılır: dəqiqədə 24, gündə 150.</li>
<li>Dərin yoxlamanı (açıq fayllar və portlar) yalnız sizə aid və ya yoxlamaq üçün icazə aldığınız saytda işlədin.</li>
<li>Nəticəni başqasını aldatmaq və ya yanıltmaq üçün istifadə etməyin.</li>
</ul>
<h2>Əlaqə</h2>
<p>{CONTACT}</p>"""),
        "en": ("Terms of use", "SaytYoxla is free and checks public information only. Results are for information and are not a full security audit.", f"""
<h2>The service</h2>
<p>SaytYoxla is free and provided as it is. We do not guarantee that it will run without interruption.</p>
<h2>What a result means</h2>
<p>The score and recommendations rely only on settings visible from outside and are for information. A high score does not prove a site is fully secure, and a low score does not mean it has been hacked. For important decisions, consult a specialist.</p>
<h2>Acceptable use</h2>
<ul>
<li>Do not use the service to harm other sites or to overload it.</li>
<li>There are limits: 6 fresh checks a minute and 60 a day from one IP address. Each part of the deep analysis counts on its own: 24 a minute, 150 a day.</li>
<li>Run the deep check (exposed files and ports) only on a site that is yours or that you have permission to check.</li>
<li>Do not use a result to deceive or mislead anyone.</li>
</ul>
<h2>Contact</h2>
<p>{CONTACT}</p>"""),
        "ru": ("Условия использования", "SaytYoxla бесплатен и проверяет только открытые данные. Результат носит информационный характер и не является полным аудитом.", f"""
<h2>Сервис</h2>
<p>SaytYoxla бесплатен и предоставляется как есть. Мы не гарантируем его бесперебойную работу.</p>
<h2>Что означает результат</h2>
<p>Балл и рекомендации основаны только на настройках, видимых снаружи, и носят информационный характер. Высокий балл не доказывает полную безопасность сайта, а низкий не означает, что сайт взломан. Для важных решений обратитесь к специалисту.</p>
<h2>Правила использования</h2>
<ul>
<li>Не используйте сервис, чтобы навредить другим сайтам или перегрузить его.</li>
<li>Есть ограничения: 6 новых проверок в минуту и 60 в день с одного IP-адреса. Каждая часть глубокого анализа считается отдельно: 24 в минуту, 150 в день.</li>
<li>Запускайте глубокую проверку (открытые файлы и порты) только на своём сайте или на сайте, который вам разрешили проверять.</li>
<li>Не используйте результат, чтобы обмануть или ввести кого-либо в заблуждение.</li>
</ul>
<h2>Контакты</h2>
<p>{CONTACT}</p>"""),
    },
}

NOT_FOUND = {
    "az": ("Səhifə tapılmadı", "Axtardığınız səhifə yoxdur və ya köçürülüb.", "Saytı yoxlamağa qayıt"),
    "en": ("Page not found", "The page you are looking for does not exist or has moved.", "Back to the website check"),
    "ru": ("Страница не найдена", "Такой страницы нет, или она перемещена.", "Вернуться к проверке сайта"),
}

ICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' "
        "rx='14' fill='%230f2a4a'/%3E%3Cpath d='M18 33l9 9 19-20' fill='none' stroke='%2334d399' stroke-width='7' "
        "stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E")

STYLE = """
:root{--bg:#f5f7fb;--line:#e3e8f0;--line-2:#cfd7e3;--ink:#0f1b2d;--ink-2:#3d4b60;--muted:#5b6779;--brand:#0f2a4a;--brand-2:#1d4ed8;
--font:Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:400 16px/1.65 var(--font);-webkit-font-smoothing:antialiased}
a{color:var(--brand-2)}
.wrap{max-width:720px;margin:0 auto;padding:0 16px}
.top{background:#fff;border-bottom:1px solid var(--line)}
.top .wrap{display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:62px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;color:var(--brand);text-decoration:none;font:800 20px/1 var(--font)}
.brand b{color:var(--brand-2)}
.mark{width:34px;height:34px;border-radius:10px;background:var(--brand);display:grid;place-items:center}
.langs{display:flex;border:1px solid var(--line-2);border-radius:10px;overflow:hidden}
.langs a{padding:8px 9px;font:700 13px/1 var(--font);color:var(--ink-2);text-decoration:none}
.langs a+a{border-left:1px solid var(--line-2)}
.langs a[aria-current]{background:var(--brand);color:#fff}
h1{font-size:clamp(28px,5vw,38px);line-height:1.15;letter-spacing:-.02em;margin:36px 0 12px}
h2{font-size:20px;letter-spacing:-.01em;margin:30px 0 6px}
p,ul{margin:0 0 12px;color:var(--ink-2)}
li{margin:0 0 8px}
.meta{color:var(--muted);font-size:14px}
.btn{display:inline-block;background:#f59e0b;color:#231500;font-weight:700;text-decoration:none;padding:12px 18px;border-radius:12px;margin-top:8px}
footer{color:var(--muted);font-size:14px;padding:32px 0 40px}
footer a{display:inline-block;padding:13px 4px}
@media (pointer:coarse){main p a,main li a{display:inline-block;padding:11px 2px}}
.btn-plain{border:0;cursor:pointer;font:700 16px/1.2 var(--font)}
.skip{position:absolute;left:12px;top:-80px;background:#1d4ed8;color:#fff;padding:12px 16px;border-radius:10px;font-weight:700;text-decoration:none}
.skip:focus{top:8px}
@media (max-width:640px){.langs a{display:inline-flex;align-items:center;justify-content:center;min-width:40px;min-height:44px;padding:0 4px}}
@media screen and (prefers-color-scheme:dark){
:root{color-scheme:dark;--bg:#0b1220;--line:#26324a;--line-2:#3a4a66;--ink:#e8edf6;--ink-2:#b7c2d6;--muted:#98a6bd;--brand:#1c3a63;--brand-2:#8ab4ff}
.top{background:#131c2e}
.brand{color:var(--ink)}
}
"""
OG_LOCALE = {"az": "az_AZ", "en": "en_US", "ru": "ru_RU"}
SKIP = {"az": "Məzmuna keç", "en": "Skip to content", "ru": "Перейти к содержимому"}
ICON_LINKS = ('<link rel="icon" href="/favicon.ico" sizes="32x32">\n<link rel="apple-touch-icon" href="/apple-touch-icon.png">\n'
              '<link rel="manifest" href="/site.webmanifest">\n<meta name="color-scheme" content="light dark">')


def footer_links(lang: str) -> str:
    tools = f'<a href="{TOOLS_PATHS[lang]}">{TOOLS_META[lang][0]}</a>'
    compare = f'<a href="{COMPARE_PATHS[lang]}">{COMPARE_NAME[lang]}</a>'
    glossary = f'<a href="{GLOSSARY_PATHS[lang]}">{GLOSSARY_NAME[lang]}</a>'
    return " · ".join([tools, compare, glossary] + [f'<a href="{PATHS[k][lang]}">{LINKS[k][lang]}</a>' for k in PATHS])


def _shell(lang: str, title: str, desc: str, body: str, paths: dict[str, str], robots: str = "index, follow",
           canonical: str | None = None) -> str:
    alt = "".join(f'<link rel="alternate" hreflang="{l}" href="{SITE_URL}{p}">\n' for l, p in paths.items())
    if canonical:
        alt = f'<link rel="canonical" href="{SITE_URL}{canonical}">\n{alt}<link rel="alternate" hreflang="x-default" href="{SITE_URL}{paths["az"]}">\n'
        # The card a shared link shows in WhatsApp, Telegram and Facebook
        alt += (f'<meta property="og:type" content="website">\n<meta property="og:site_name" content="SaytYoxla">\n'
                f'<meta property="og:locale" content="{OG_LOCALE[lang]}">\n<meta property="og:url" content="{SITE_URL}{canonical}">\n'
                f'<meta property="og:title" content="{title}">\n<meta property="og:description" content="{desc}">\n'
                f'<meta property="og:image" content="{SITE_URL}/static/og-image.png">\n<meta property="og:image:width" content="1200">\n'
                f'<meta property="og:image:height" content="630">\n<meta name="twitter:card" content="summary_large_image">\n')
    else:
        alt = ""
    langs = "".join(f'<a href="{paths[l]}" hreflang="{l}" lang="{l}"{" aria-current=page" if l == lang else ""}>{l.upper()}</a>'
                    for l in LANGS)
    nav = {"az": "Dil", "en": "Language", "ru": "Язык"}[lang]
    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} | SaytYoxla</title>
<meta name="description" content="{desc}">
<meta name="robots" content="{robots}">
{alt}<link rel="icon" type="image/svg+xml" href="{ICON}">
{ICON_LINKS}
<link rel="preload" href="/static/fonts/inter-4-latin.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="/static/fonts.css">
<style>{STYLE}</style>
</head>
<body>
<a class="skip" href="#main">{SKIP[lang]}</a>
<header class="top"><div class="wrap">
  <a class="brand" href="{HOMES[lang]}"><span class="mark"><svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path d="M9.5 16.2 5.3 12l-1.4 1.4 5.6 5.6 11-11-1.4-1.4z" fill="#34d399"/></svg></span><span>Sayt<b>Yoxla</b></span></a>
  <nav class="langs" aria-label="{nav}">{langs}</nav>
</div></header>
<main id="main" class="wrap">
{body}
</main>
<footer><div class="wrap">SaytYoxla · {footer_links(lang)}</div></footer>
</body>
</html>
"""


def tools_page(home_html: str, lang: str) -> str:
    """The built home page with the Tools page's title, description and addresses, for search engines and shared links."""
    _, title, desc, heading = TOOLS_META[lang]
    home, path = SITE_URL + HOMES[lang], SITE_URL + TOOLS_PATHS[lang]
    html = re.sub(r"<title>.*?</title>", f"<title>{title}</title>", home_html, count=1, flags=re.DOTALL)
    html = re.sub(r'(<meta name="description" content=")[^"]*', lambda m: m.group(1) + desc, html, count=1)
    html = re.sub(r'(<meta property="og:title" content=")[^"]*', lambda m: m.group(1) + title, html, count=1)
    html = re.sub(r'(<meta property="og:description" content=")[^"]*', lambda m: m.group(1) + desc, html, count=1)
    html = html.replace(f'<link rel="canonical" href="{home}">', f'<link rel="canonical" href="{path}">')
    html = html.replace(f'<meta property="og:url" content="{home}">', f'<meta property="og:url" content="{path}">')
    for code in LANGS:
        html = html.replace(f'hreflang="{code}" href="{SITE_URL}{HOMES[code]}"', f'hreflang="{code}" href="{SITE_URL}{TOOLS_PATHS[code]}"')
    html = html.replace(f'hreflang="x-default" href="{SITE_URL}/"', f'hreflang="x-default" href="{SITE_URL}{TOOLS_PATHS["az"]}"')
    html = re.sub(r"<h1>.*?</h1>", f"<h1>{heading}</h1>", html, count=1, flags=re.DOTALL)
    # The questions and the "what we check" cards belong to the home page: repeated here they are duplicate
    # content, and a second FAQPage with the same questions is ignored or penalised by search engines
    html = re.sub(r"<!-- Static content stays.*?(?=<footer)", "", html, count=1, flags=re.DOTALL)
    return re.sub(r'(<script type="application/ld\+json">)(.*?)(</script>)', _without_faq, html, count=1, flags=re.DOTALL)


def _without_faq(m: re.Match) -> str:
    try:
        data = json.loads(m.group(2))
    except ValueError:
        return m.group(0)
    data["@graph"] = [node for node in data.get("@graph", []) if node.get("@type") != "FAQPage"]
    return m.group(1) + "\n" + json.dumps(data, ensure_ascii=False, indent=1) + "\n" + m.group(3)


def notice(lang: str, text: str, button: str = "", post_to: str = "") -> str:
    """A one-sentence page, with a button that POSTs when the visitor has to agree to something (web/app.py)."""
    body = f"<h1>SaytYoxla</h1>\n<p>{escape(text)}</p>"
    if button:
        body += f'\n<form method="post" action="{escape(post_to)}"><button class="btn btn-plain" type="submit">{escape(button)}</button></form>'
    return _shell(lang, "SaytYoxla", escape(text), body, HOMES, robots="noindex")


def page(key: str, lang: str) -> str:
    title, desc, body = CONTENT[key][lang]
    html = f'<h1>{title}</h1>\n<p class="meta">{UPDATED[lang]}</p>\n{body}'
    return _shell(lang, title, desc, html, PATHS[key], canonical=PATHS[key][lang])


def not_found(path: str) -> str:
    lang = next((l for l in ("en", "ru") if path.startswith(f"/{l}/")), "az")
    title, text, back = NOT_FOUND[lang]
    body = f'<h1>{title}</h1>\n<p>{text}</p>\n<a class="btn" href="{HOMES[lang]}">{back}</a>'
    return _shell(lang, title, text, body, HOMES, robots="noindex")
