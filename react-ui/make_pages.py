"""
Write en/index.html and ru/index.html from index.html (the Azerbaijani page).

    python3 make_pages.py      # run before `npm run build` whenever index.html changes

Every Azerbaijani sentence in index.html must appear below; the script stops and names
any leftover Azerbaijani text, so the three pages cannot drift apart.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).parent
SITE = "https://saytyoxla.vercel.app"
AZ_LETTERS = re.compile(r"[əğışçöüƏĞİŞÇÖÜ]")
ALLOWED = {"Ziya Əzizov", "Azərbaycanca"}      # names that stay in Azerbaijani on every page

# (Azerbaijani, English, Russian); longer strings first is not required: each is matched whole.
T = [
    ('<html lang="az">', '<html lang="en">', '<html lang="ru">'),
    ('<link rel="canonical" href="https://saytyoxla.vercel.app/">',
     '<link rel="canonical" href="https://saytyoxla.vercel.app/en/">',
     '<link rel="canonical" href="https://saytyoxla.vercel.app/ru/">'),
    ('<meta property="og:url" content="https://saytyoxla.vercel.app/">',
     '<meta property="og:url" content="https://saytyoxla.vercel.app/en/">',
     '<meta property="og:url" content="https://saytyoxla.vercel.app/ru/">'),
    ('content="az_AZ"', 'content="en_US"', 'content="ru_RU"'),
    ('"inLanguage": "az"', '"inLanguage": "en"', '"inLanguage": "ru"'),
    ('"url": "https://saytyoxla.vercel.app/",\n   "description"', '"url": "https://saytyoxla.vercel.app/en/",\n   "description"',
     '"url": "https://saytyoxla.vercel.app/ru/",\n   "description"'),
    ('"@id": "https://saytyoxla.vercel.app/#faq"', '"@id": "https://saytyoxla.vercel.app/en/#faq"',
     '"@id": "https://saytyoxla.vercel.app/ru/#faq"'),
    ('<a href="/" hreflang="az" lang="az" title="Azərbaycanca" aria-current="page">AZ</a><a href="/en/" hreflang="en" lang="en" title="English">EN</a><a href="/ru/" hreflang="ru" lang="ru" title="Русский">RU</a>',
     '<a href="/" hreflang="az" lang="az" title="Azərbaycanca">AZ</a><a href="/en/" hreflang="en" lang="en" title="English" aria-current="page">EN</a><a href="/ru/" hreflang="ru" lang="ru" title="Русский">RU</a>',
     '<a href="/" hreflang="az" lang="az" title="Azərbaycanca">AZ</a><a href="/en/" hreflang="en" lang="en" title="English">EN</a><a href="/ru/" hreflang="ru" lang="ru" title="Русский" aria-current="page">RU</a>'),
    ('<a class="brand" href="/" aria-label="SaytYoxla — əsas səhifə">',
     '<a class="brand" href="/en/" aria-label="SaytYoxla — home page">',
     '<a class="brand" href="/ru/" aria-label="SaytYoxla — главная страница">'),
    ('aria-label="Dil"', 'aria-label="Language"', 'aria-label="Язык"'),

    # head
    ("Saytı pulsuz yoxla: təhlükəsizlik, SSL, sürət | SaytYoxla",
     "Free website check: security, SSL, speed | SaytYoxla",
     "Бесплатная проверка сайта: безопасность, SSL, скорость | SaytYoxla"),
    (("Saytınızın təhlükəsizliyini, SSL sertifikatını, e-poçt qorumasını, sürətini və telefona uyğunluğunu "
     "30 saniyəyə pulsuz yoxlayın. Qeydiyyat tələb olunmur."),
     ("Check your website's security, SSL certificate, e-mail protection, speed and mobile-friendliness "
     "for free in 30 seconds. No sign-up needed."),
     ("Бесплатно проверьте безопасность сайта, SSL-сертификат, защиту почты, скорость и адаптацию "
     "под телефон за 30 секунд. Без регистрации.")),
    ("SaytYoxla — saytınızı 30 saniyəyə pulsuz yoxlayın",
     "SaytYoxla — check your website for free in 30 seconds",
     "SaytYoxla — бесплатная проверка сайта за 30 секунд"),
    ("Təhlükəsizlik, SSL, e-poçt qoruması, sürət və telefona uyğunluq — 0–100 bal və sadə dildə izah.",
     "Security, SSL, e-mail protection, speed and mobile-friendliness — a 0–100 score explained in plain words.",
     "Безопасность, SSL, защита почты, скорость и адаптация под телефон — балл 0–100 и объяснение простыми словами."),
    ('"Any (brauzerdə işləyir)"', '"Any (runs in the browser)"', '"Any (работает в браузере)"'),
    ("HTTPS və SSL sertifikatının yoxlanması", "HTTPS and SSL certificate check", "Проверка HTTPS и SSL-сертификата"),
    ("Təhlükəsizlik başlıqları: HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy",
     "Security headers: HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy",
     "Заголовки безопасности: HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy"),
    ("SPF və DMARC e-poçt qorumasının yoxlanması", "SPF and DMARC e-mail protection check", "Проверка защиты почты SPF и DMARC"),
    ("Serverin cavab sürəti və səhifə həcmi", "Server response time and page size", "Время ответа сервера и размер страницы"),
    ("Telefona uyğunluq (viewport), səhifə başlığı və meta description",
     "Mobile-friendliness (viewport), page title and meta description",
     "Адаптация под телефон (viewport), заголовок страницы и meta description"),
    ("0–100 bal, A–F qiyməti və hər problem üçün düzəliş yolu",
     "0–100 score, A–F grade and a fix for every problem",
     "Балл 0–100, оценка A–F и способ исправить каждую проблему"),
    ('"PDF hesabat"', '"PDF report"', '"Отчёт в PDF"'),

    # fallback header / hero (same text React renders)
    ("Saytı necə işlətməli?", "How to use it", "Как пользоваться?"),
    ("<h1>Saytınız nə qədər <span>təhlükəsiz</span> və sağlamdır?</h1>",
     "<h1>How <span>secure</span> and healthy is your website?</h1>",
     "<h1>Насколько ваш сайт <span>безопасен</span> и исправен?</h1>"),
    ("Saytınızın ünvanını yazın — 30 saniyəyə pulsuz yoxlayaq və nəticəni sadə dildə izah edək.",
     "Enter your website address — we check it for free in 30 seconds and explain the result in plain words.",
     "Введите адрес сайта — мы бесплатно проверим его за 30 секунд и объясним результат простыми словами."),
    (">Saytın ünvanı</label>", ">Website address</label>", ">Адрес сайта</label>"),
    ('placeholder="məsələn: meninsaytim.az"', 'placeholder="for example: mywebsite.com"', 'placeholder="например: moisait.az"'),
    ('type="submit">Yoxla</button>', 'type="submit">Check</button>', 'type="submit">Проверить</button>'),
    ("http:// və ya www yazmağa ehtiyac yoxdur. Pulsuzdur, qeydiyyat tələb olunmur.",
     "No need to type http:// or www. Free, no sign-up.",
     "Не нужно писать http:// или www. Бесплатно, без регистрации."),
    ("Ətraflı bələdçi →", "Full guide →", "Подробная инструкция →"),
    ("<strong>Ünvanı yazın</strong>Yuxarıdakı xanaya saytınızın adını yazın.",
     "<strong>Enter the address</strong>Type your website name in the box above.",
     "<strong>Введите адрес</strong>Напишите название сайта в поле выше."),
    ('<a class="skip" href="#main">Məzmuna keç</a>', '<a class="skip" href="#main">Skip to content</a>',
     '<a class="skip" href="#main">Перейти к содержимому</a>'),
    ("<strong>«Yoxla» basın</strong>Bir neçə saniyə gözləyin, səhifəni bağlamayın.",
     "<strong>Press “Check”</strong>Wait a few seconds and keep the page open.",
     "<strong>Нажмите «Проверить»</strong>Подождите несколько секунд, не закрывайте страницу."),
    ("<strong>Balınıza baxın</strong>100-ə yaxın bal — yaxşı. Aşağı bal — diqqət.",
     "<strong>Look at your score</strong>Close to 100 is good. A low score needs attention.",
     "<strong>Посмотрите на балл</strong>Близко к 100 — хорошо. Низкий балл — нужно внимание."),
    ("<strong>Qırmızıları düzəldin</strong>Hər problemin altında necə düzəldiləcəyi yazılıb.",
     "<strong>Fix the red ones</strong>Every problem comes with how to fix it.",
     "<strong>Исправьте красные</strong>Под каждой проблемой написано, как её исправить."),

    # what we check
    ('aria-label="Nəyi yoxlayırıq və suallar"', 'aria-label="What we check and questions"', 'aria-label="Что мы проверяем и вопросы"'),
    ("Nəyi yoxlayırıq?", "What do we check?", "Что мы проверяем?"),
    ("<h3>Təhlükəsizlik</h3>", "<h3>Security</h3>", "<h3>Безопасность</h3>"),
    ("Saytın şifrəli bağlantısı, sertifikatın vaxtı və hücumlara qarşı qoruyucu ayarlar.",
     "The encrypted connection, the certificate's expiry and settings that protect against attacks.",
     "Шифрованное соединение, срок сертификата и настройки защиты от атак."),
    ("<h3>E-poçt</h3>", "<h3>E-mail</h3>", "<h3>Эл. почта</h3>"),
    ("Başqalarının sizin adınızdan saxta məktub göndərə bilib-bilməyəcəyi.",
     "Whether others can send fake e-mails in your name.",
     "Могут ли другие отправлять поддельные письма от вашего имени."),
    ("<h3>Sürət</h3>", "<h3>Speed</h3>", "<h3>Скорость</h3>"),
    ("Serverin ABŞ-dan ölçülən cavab vaxtı, səhifənin skript və şəkillərlə birlikdə tam çəkisi, ağır şəkillər və keşləmə.",
     "The server's response time, measured from the USA, the full weight of the page with its scripts and images, heavy images and caching.",
     "Время ответа сервера, измеренное из США, полный вес страницы со скриптами и изображениями, тяжёлые изображения и кэширование."),
    ("<h3>Telefon və Google</h3>", "<h3>Mobile and Google</h3>", "<h3>Телефон и Google</h3>"),
    ("Saytın telefonda düzgün görünməsi və Google axtarışında necə göstərildiyi.",
     "Whether the site looks right on a phone and how it shows up in Google search.",
     "Правильно ли сайт выглядит на телефоне и как он показывается в поиске Google."),

    ('<a href="/hesabat/">Azərbaycan saytlarının təhlükəsizlik hesabatı: banklar, universitetlər, dövlət qurumları →</a>',
     '<a href="/en/report/">Report: how secure are Azerbaijani websites? Banks, universities, government →</a>',
     '<a href="/ru/otchet/">Отчёт о безопасности сайтов Азербайджана: банки, университеты, госорганы →</a>'),
    # FAQ (in the page and in the JSON-LD)
    ("Tez-tez verilən suallar", "Frequently asked questions", "Частые вопросы"),
    ("Bu, pulsuzdur?", "Is it free?", "Это бесплатно?"),
    ("Bəli. Yoxlama tamamilə pulsuzdur və qeydiyyat tələb etmir.",
     "Yes. The check is completely free and needs no sign-up.",
     "Да. Проверка полностью бесплатна и не требует регистрации."),
    ("Saytımın təhlükəsiz olub-olmadığını necə bilim?", "How do I know if my website is secure?",
     "Как узнать, безопасен ли мой сайт?"),
    (("Yuxarıdakı xanaya saytınızın ünvanını yazıb «Yoxla» basın. SaytYoxla HTTPS bağlantısını, SSL sertifikatını, "
     "HSTS, CSP və digər qoruyucu başlıqları, server versiyasının açıq görünüb-görünmədiyini və qarışıq (http) "
     "məzmunu yoxlayır, hər problemin həllini sadə dildə yazır."),
     ("Enter your website address in the box above and press “Check”. SaytYoxla checks the HTTPS connection, the SSL "
     "certificate, HSTS, CSP and other protective headers, whether the server version is exposed, and mixed (http) "
     "content, and explains the fix for every problem in plain words."),
     ("Введите адрес сайта в поле выше и нажмите «Проверить». SaytYoxla проверяет соединение HTTPS, SSL-сертификат, "
     "HSTS, CSP и другие защитные заголовки, не раскрыта ли версия сервера, и смешанное (http) содержимое, а для "
     "каждой проблемы простыми словами пишет решение.")),
    ("SSL sertifikatının bitmə tarixini necə yoxlamaq olar?", "How can I check when my SSL certificate expires?",
     "Как узнать, когда истекает SSL-сертификат?"),
    (("Yoxlamadan sonra «Təhlükəsizlik» bölməsində sertifikatın neçə gün etibarlı qaldığı və bitmə tarixi göstərilir. "
     "Sertifikatın vaxtı bitəndə brauzerlər sayta girişi «təhlükəli» kimi göstərir, ona görə onu vaxtında yeniləyin — "
     "mümkünsə avtomatik yenilənməni (məsələn, Let's Encrypt) açın."),
     ("After the check, the “Security” section shows how many days the certificate is still valid and its expiry date. "
     "When a certificate expires, browsers mark the site as “not secure”, so renew it in time — ideally turn on "
     "automatic renewal (for example, Let's Encrypt)."),
     ("После проверки в разделе «Безопасность» показано, сколько дней ещё действует сертификат и дата окончания. "
     "Когда срок истекает, браузеры помечают сайт как «небезопасный», поэтому обновляйте его вовремя — лучше "
     "включите автоматическое продление (например, Let's Encrypt).")),
    ("SPF və DMARC nədir, niyə lazımdır?", "What are SPF and DMARC, and why do they matter?",
     "Что такое SPF и DMARC и зачем они нужны?"),
    (("SPF və DMARC domeninizin DNS ayarlarına yazılan qeydlərdir. Onlar sizin adınızdan hansı serverlərin məktub "
     "göndərə biləcəyini göstərir. Bu qeydlər olmayanda fırıldaqçılar sizin domeninizdən göndərilmiş kimi görünən "
     "saxta məktublar yaza bilər. SaytYoxla hər iki qeydi yoxlayır; yoxdursa, DNS və ya hostinq təminatçınızdan "
     "əlavə etməyi xahiş edin."),
     ("SPF and DMARC are records in your domain's DNS settings. They say which servers may send e-mail in your name. "
     "Without them, scammers can write fake e-mails that look like they came from your domain. SaytYoxla checks "
     "both; if they are missing, ask your DNS or hosting provider to add them."),
     ("SPF и DMARC — это записи в DNS-настройках вашего домена. Они указывают, какие серверы могут отправлять почту "
     "от вашего имени. Без них мошенники могут рассылать поддельные письма, которые выглядят как отправленные с "
     "вашего домена. SaytYoxla проверяет обе записи; если их нет, попросите DNS- или хостинг-провайдера добавить их.")),
    ("Saytım niyə Google-da çıxmır?", "Why doesn't my website show up on Google?", "Почему мой сайт не находится в Google?"),
    (("Ən çox rast gəlinən səbəblər: səhifənin başlığı (title) və təsviri (meta description) yoxdur və ya zəifdir, "
     "sayt telefona uyğun deyil, ya da sayt Google-a heç təqdim olunmayıb. SaytYoxla başlığı, təsviri və telefona "
     "uyğunluğu yoxlayır. Yeni saytı isə Google Search Console-a əlavə edib sitemap göndərmək lazımdır."),
     ("The most common reasons: the page title and meta description are missing or weak, the site is not "
     "mobile-friendly, or the site was never submitted to Google. SaytYoxla checks the title, the description and "
     "mobile-friendliness. A new site should also be added to Google Search Console with a sitemap."),
     ("Самые частые причины: нет или слабые заголовок страницы (title) и описание (meta description), сайт не "
     "адаптирован под телефон, или сайт вообще не добавлен в Google. SaytYoxla проверяет заголовок, описание и "
     "адаптацию. Новый сайт также нужно добавить в Google Search Console и отправить sitemap.")),
    ("Saytım telefonda niyə düzgün görünmür?", "Why does my website look wrong on a phone?",
     "Почему сайт неправильно выглядит на телефоне?"),
    (("Çox vaxt səbəb səhifədə «viewport» teqinin olmamasıdır — onda telefon saytı kompüter ölçüsündə açıb kiçildir. "
     "SaytYoxla bunu «Telefon və Google» bölməsində yoxlayır və əlavə ediləcək teqi göstərir."),
     ("Usually the page has no “viewport” tag, so the phone opens the site at desktop size and shrinks it. "
     "SaytYoxla checks this in the “Mobile and Google” section and shows the tag to add."),
     ("Чаще всего на странице нет тега «viewport» — тогда телефон открывает сайт в размере компьютера и уменьшает его. "
     "SaytYoxla проверяет это в разделе «Мобильные и Google» и показывает, какой тег добавить.")),
    ("Yoxlama saytıma zərər verə bilər?", "Can the check harm my website?", "Может ли проверка навредить сайту?"),
    (("Xeyr. Biz yalnız hər kəsə açıq olana baxırıq: əsas səhifəni, onun yüklədiyi faylları (skript, üslub, şəkil), robots.txt və sitemap.xml fayllarını bir dəfə açırıq, "
     "sertifikatı və açıq DNS qeydlərini oxuyuruq. Heç nəyi dəyişmirik və heç nəyi sındırmağa çalışmırıq. Açıq fayl və portlara yalnız sayt sahibi təsdiq etdikdən sonra, dərin yoxlamada baxılır."),
     ("No. We only look at what is open to everyone: we open the home page, the files it loads (scripts, styles, images), robots.txt and sitemap.xml once and read the "
     "certificate and public DNS records. We change nothing and try to break nothing. Exposed files and ports are looked at only in the deep check, after the site's owner has confirmed it."),
     ("Нет. Мы смотрим только на то, что открыто всем: один раз открываем главную страницу, файлы, которые она загружает (скрипты, стили, изображения), robots.txt и sitemap.xml, "
     "читаем сертификат и открытые DNS-записи. Ничего не меняем и ничего не пытаемся взломать. Открытые файлы и порты смотрим только в глубокой проверке, после подтверждения владельцем сайта.")),
    ("Məlumatlarım saxlanılır?", "Is my data stored?", "Сохраняются ли мои данные?"),
    (("Adınızı və telefonunuzu soruşmuruq, kuki və izləmə skriptləri də yoxdur. E-poçt yalnız saytınızın daimi "
     "izlənməsini özünüz seçsəniz lazımdır və izləməni dayandıranda silinir. Yoxlanılan ünvan və nəticə təkrar "
     "yoxlamanı sürətləndirmək üçün 10 dəqiqəyə qədər, IP ünvanınız isə sui-istifadəni məhdudlaşdıran sayğacda ən çox "
     "1 gün qalır."),
     ("We do not ask for your name or phone, and there are no cookies or tracking scripts. An e-mail address is needed "
     "only if you choose ongoing watching of your site yourself, and it is deleted when you stop the watching. The "
     "checked address and its result stay for up to 10 minutes to speed up a repeat check, and your IP address stays "
     "for up to 1 day in the counter that limits abuse."),
     ("Мы не спрашиваем имя и телефон, cookie и скриптов отслеживания нет. E-mail нужен, только если вы сами выберете "
     "постоянное наблюдение за сайтом, и удаляется, когда вы его останавливаете. Проверенный адрес и результат "
     "хранятся до 10 минут, чтобы ускорить повторную проверку, а ваш IP-адрес — до 1 дня в счётчике, ограничивающем "
     "злоупотребления.")),
    ("Bal nə deməkdir?", "What does the score mean?", "Что означает балл?"),
    (("100 ən yaxşı nəticədir. 90+ — əla (A), 75+ — yaxşı (B), 60+ — orta (C), 40+ — zəif (D), 40-dan aşağı — "
     "ciddi diqqət lazımdır (F). Qırmızı problemlər balı daha çox azaldır. Əsas qoruma çatışmayanda bal məhdudlaşır: "
     "etibarlı HTTPS yoxdursa 39-dan, sertifikatın bitməsinə 7 gündən az qalıbsa 59-dan, 4–5 əsas ayar yoxdursa "
     "74-dən, 2–3 ayar yoxdursa 89-dan yuxarı olmur."),
     ("100 is the best result. 90+ is excellent (A), 75+ good (B), 60+ fair (C), 40+ weak (D), below 40 needs "
     "serious attention (F). Red problems lower the score the most. Missing basic protection limits the score: "
     "no more than 39 without trusted HTTPS, 59 if the certificate expires in under 7 days, 74 with 4–5 basic "
     "settings missing and 89 with 2–3 missing."),
     ("100 — лучший результат. 90+ — отлично (A), 75+ — хорошо (B), 60+ — средне (C), 40+ — слабо (D), ниже 40 — "
     "нужно серьёзное внимание (F). Красные проблемы снижают балл сильнее всего. Если не хватает основной защиты, "
     "балл ограничен: не выше 39 без надёжного HTTPS, 59, если сертификат истекает менее чем через 7 дней, 74 при "
     "отсутствии 4–5 основных настроек и 89 при отсутствии 2–3.")),
    ("Problemləri kim düzəltməlidir?", "Who should fix the problems?", "Кто должен исправлять проблемы?"),
    (("Saytınızı quran proqramçıya və ya hostinq şirkətinə hesabatı göstərin — hər problemin altında nə ediləcəyi "
     "yazılıb. İstəsəniz, WhatsApp-a yazın, kömək edək."),
     ("Show the report to the developer who built your site or to your hosting company — every problem says what "
     "to do. If you like, message us on WhatsApp and we will help."),
     ("Покажите отчёт разработчику сайта или хостинг-компании — под каждой проблемой написано, что делать. "
     "Если хотите, напишите в WhatsApp, мы поможем.")),

    # footer
    ('<a href="/aletler/">Alətlər</a>', '<a href="/en/tools/">Tools</a>', '<a href="/ru/instrumenty/">Инструменты</a>'),
    ('<a href="/muqayise/">Müqayisə</a>', '<a href="/en/compare/">Compare</a>', '<a href="/ru/sravnenie/">Сравнение</a>'),
    ('<a href="/haqqimizda/">Haqqımızda</a>','<a href="/en/about/">About</a>', '<a href="/ru/o-nas/">О сервисе</a>'),
    ('<a href="/mexfilik/">Məxfilik</a>', '<a href="/en/privacy/">Privacy</a>', '<a href="/ru/konfidencialnost/">Конфиденциальность</a>'),
    ('<a href="/sertler/">Şərtlər</a>', '<a href="/en/terms/">Terms</a>', '<a href="/ru/usloviya/">Условия</a>'),
    ("Sahibin təsdiqi olmadan yalnız açıq məlumatlar yoxlanılır", "Without the owner's proof, only public information is checked", "Без подтверждения владельца проверяются только открытые данные"),
    ("Sayt sifarişi və digər sayt nümunələrini görmək üçün:", "To order a website or see more examples:",
     "Заказать сайт или посмотреть другие работы:"),
]


def build(lang: str) -> str:
    i = {"en": 1, "ru": 2}[lang]
    src = (HERE / "index.html").read_text(encoding="utf-8")
    for row in T:
        az = row[0]
        # the FAQ text in JSON-LD has the same sentence as the page, with &#x27; instead of '
        for a in {az, az.replace("'", "&#x27;")}:
            if a in src:
                src = src.replace(a, row[i] if a == az else row[i].replace("'", "&#x27;"))
    left = [m for m in re.findall(r"[^<>\"\n]*[əğışçöüƏĞİŞÇÖÜ][^<>\"\n]*", src)
            if not any(name in m for name in ALLOWED)]
    if left:
        sys.exit(f"{lang}: untranslated text:\n  " + "\n  ".join(left))
    return src


if __name__ == "__main__":
    for lang in ("en", "ru"):
        out = HERE / lang / "index.html"
        out.parent.mkdir(exist_ok=True)
        out.write_text(build(lang), encoding="utf-8")
        print("wrote", out.relative_to(HERE))
