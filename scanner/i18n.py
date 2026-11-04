"""
English and Russian versions of every text the scanner shows.

The checks write Azerbaijani (the reference language, and what the cache stores).
translate() maps a finished report or an error message into "en" or "ru" at the very end,
so the checks stay simple and a missing translation is caught by tests/test_i18n.py.

Static sentences are looked up exactly; sentences with numbers or names in them match a regex.
Russian avoids number agreement ("дн.", "файлов: 3") so one template fits every count.
"""

from __future__ import annotations

import re

LANGS = ("az", "en", "ru")

# Azerbaijani -> (English, Russian)
EXACT: dict[str, tuple[str, str]] = {
    # categories
    "Təhlükəsizlik": ("Security", "Безопасность"),
    "E-poçt": ("E-mail", "Эл. почта"),
    "Sürət": ("Speed", "Скорость"),
    "Mobil və Google": ("Mobile and Google", "Мобильные и Google"),

    # titles
    "Təhlükəsiz bağlantı (HTTPS)": ("Secure connection (HTTPS)", "Защищённое соединение (HTTPS)"),
    "HTTP-dən HTTPS-ə yönləndirmə": ("HTTP to HTTPS redirect", "Перенаправление с HTTP на HTTPS"),
    "SSL sertifikatı": ("SSL certificate", "SSL-сертификат"),
    "Məcburi HTTPS (HSTS)": ("Forced HTTPS (HSTS)", "Принудительный HTTPS (HSTS)"),
    "Fayl tipinin qorunması": ("File type protection", "Защита типа файлов"),
    "Keçid məlumatının qorunması": ("Referrer protection", "Защита данных о переходе"),
    "Saxta çərçivəyə qarşı qoruma": ("Clickjacking protection", "Защита от кликджекинга"),
    "Kənar skriptlərə nəzarət (CSP)": ("Control over third-party scripts (CSP)",
                                       "Контроль сторонних скриптов (CSP)"),
    "Proqram versiyasının gizlədilməsi": ("Software versions hidden", "Скрытие версий ПО"),
    "Qarışıq məzmun": ("Mixed content", "Смешанное содержимое"),
    "E-poçt göndərən icazəsi (SPF)": ("Allowed e-mail senders (SPF)", "Разрешённые отправители почты (SPF)"),
    "Saxta məktuba qarşı qoruma (DMARC)": ("Protection against fake e-mails (DMARC)",
                                           "Защита от поддельных писем (DMARC)"),
    "Serverin cavab sürəti": ("Server response time", "Время ответа сервера"),
    "Səhifənin həcmi": ("Page size", "Размер страницы"),
    "Telefona uyğunluq": ("Mobile-friendly", "Адаптация под телефон"),
    "Səhifə başlığı": ("Page title", "Заголовок страницы"),
    "Google üçün təsvir": ("Description for Google", "Описание для Google"),

    # https
    "Sayt şifrələnmiş HTTPS bağlantısı ilə açılır.": (
        "The site opens over an encrypted HTTPS connection.",
        "Сайт открывается по зашифрованному соединению HTTPS."),
    "Sayt şifrəsiz (http) açılır. Brauzerlər onu \"Təhlükəli deyil\" kimi göstərir.": (
        "The site opens without encryption (http). Browsers mark it as \"Not secure\".",
        "Сайт открывается без шифрования (http). Браузеры помечают его как «Не защищено»."),
    "Hostinq panelindən pulsuz SSL sertifikatı (Let's Encrypt) qoşun.": (
        "Turn on a free SSL certificate (Let's Encrypt) in your hosting panel.",
        "Подключите бесплатный SSL-сертификат (Let's Encrypt) в панели хостинга."),

    "Sayt HTTPS ilə açılır, amma sertifikat etibarsız olduğu üçün bu bağlantıya etibar etmək olmur.": (
        "The site opens over HTTPS, but its certificate is not valid, so the connection cannot be trusted.",
        "Сайт открывается по HTTPS, но сертификат недействителен, поэтому такому соединению нельзя доверять."),

    # redirect
    "http:// ünvanı yoxlanıla bilmədi.": (
        "The http:// address could not be checked.", "Не удалось проверить адрес http://."),
    "http:// ilə yazanlar avtomatik təhlükəsiz versiyaya keçir.": (
        "Visitors who type http:// are moved to the secure version automatically.",
        "Посетители, набравшие http://, автоматически попадают на защищённую версию."),
    "Ünvanı http:// ilə yazan ziyarətçi şifrəsiz versiyada qalır.": (
        "A visitor who types the address with http:// stays on the unencrypted version.",
        "Посетитель, набравший адрес с http://, остаётся на незашифрованной версии."),
    "Serverdə bütün http sorğularını https-ə yönləndirin (301).": (
        "Redirect every http request to https on the server (301).",
        "Настройте на сервере перенаправление всех http-запросов на https (301)."),

    # certificate
    "Sertifikatın vaxtı bitib. Brauzerlər ziyarətçiyə təhlükəsizlik xəbərdarlığı göstərir.": (
        "The certificate has expired. Browsers show visitors a security warning.",
        "Срок действия сертификата истёк. Браузеры показывают посетителям предупреждение."),
    "Sertifikat özü-imzalıdır, brauzerlər ona etibar etmir və ziyarətçiyə xəbərdarlıq göstərir.": (
        "The certificate is self-signed: browsers do not trust it and show visitors a warning.",
        "Сертификат самоподписанный: браузеры ему не доверяют и показывают посетителям предупреждение."),
    "Sertifikat bu domen adına verilməyib. Brauzerlər ziyarətçiyə təhlükəsizlik xəbərdarlığı göstərir.": (
        "The certificate was not issued for this domain name. Browsers show visitors a security warning.",
        "Сертификат выдан не на это доменное имя. Браузеры показывают посетителям предупреждение."),
    "Sertifikat ləğv edilib. Brauzerlər ziyarətçiyə təhlükəsizlik xəbərdarlığı göstərir.": (
        "The certificate has been revoked. Browsers show visitors a security warning.",
        "Сертификат отозван. Браузеры показывают посетителям предупреждение."),
    "Sertifikatı etibarlı mərkəz təsdiqləmir və ya zəncir tam deyil. Brauzerlər ziyarətçiyə xəbərdarlıq göstərir.": (
        "The certificate is not confirmed by a trusted authority, or its chain is incomplete. Browsers show visitors a warning.",
        "Сертификат не подтверждён доверенным центром или цепочка неполная. Браузеры показывают посетителям предупреждение."),
    "Sertifikat etibarsızdır. Brauzerlər ziyarətçiyə təhlükəsizlik xəbərdarlığı göstərir.": (
        "The certificate is not valid. Browsers show visitors a security warning.",
        "Сертификат недействителен. Браузеры показывают посетителям предупреждение."),
    "Sertifikat yoxlanılmadı (sayt https deyil).": (
        "The certificate was not checked (the site is not on https).",
        "Сертификат не проверялся (сайт не на https)."),
    "Sertifikatı yeniləyin və domen adına uyğun olduğunu yoxlayın.": (
        "Renew the certificate and make sure it matches the domain name.",
        "Обновите сертификат и проверьте, что он выдан на это доменное имя."),
    "Sertifikatın avtomatik yenilənməsini qurun.": (
        "Set up automatic certificate renewal.", "Настройте автоматическое продление сертификата."),

    # headers
    "Brauzerlərə sayta yalnız HTTPS ilə girmək əmr olunub.": (
        "Browsers are told to open the site over HTTPS only.",
        "Браузерам предписано открывать сайт только по HTTPS."),
    "Brauzerlərə yalnız HTTPS istifadə etmək əmri verilməyib.": (
        "Browsers are not told to use HTTPS only.",
        "Браузерам не предписано использовать только HTTPS."),
    "Server cavabına Strict-Transport-Security başlığını əlavə edin.": (
        "Add the Strict-Transport-Security header to the server response.",
        "Добавьте в ответ сервера заголовок Strict-Transport-Security."),
    "Brauzerin faylları səhv tipdə açması qadağandır.": (
        "Browsers may not open files as the wrong type.",
        "Браузеру запрещено открывать файлы с неверным типом."),
    "X-Content-Type-Options başlığı yoxdur.": (
        "The X-Content-Type-Options header is missing.", "Нет заголовка X-Content-Type-Options."),
    "Server cavabına \"X-Content-Type-Options: nosniff\" əlavə edin.": (
        "Add \"X-Content-Type-Options: nosniff\" to the server response.",
        "Добавьте в ответ сервера «X-Content-Type-Options: nosniff»."),
    "Keçid zamanı digər saytlara nə qədər məlumat ötürüldüyü məhdudlaşdırılıb.": (
        "The site limits how much information other sites receive when a visitor follows a link.",
        "Сайт ограничивает, сколько данных получают другие сайты при переходе по ссылке."),
    "Referrer-Policy başlığı yoxdur.": ("The Referrer-Policy header is missing.", "Нет заголовка Referrer-Policy."),
    "Server cavabına \"Referrer-Policy: strict-origin-when-cross-origin\" əlavə edin.": (
        "Add \"Referrer-Policy: strict-origin-when-cross-origin\" to the server response.",
        "Добавьте в ответ сервера «Referrer-Policy: strict-origin-when-cross-origin»."),

    # framing
    "Sayt başqa saytın içində gizli açıla bilməz.": (
        "The site cannot be hidden inside another site.",
        "Сайт нельзя скрытно открыть внутри другого сайта."),
    "Sayt başqa saytın içinə yerləşdirilib istifadəçini aldatmaq üçün istifadə oluna bilər.": (
        "The site can be embedded inside another site and used to trick visitors.",
        "Сайт можно встроить в другой сайт и использовать для обмана посетителей."),
    "Server cavabına \"X-Frame-Options: SAMEORIGIN\" əlavə edin.": (
        "Add \"X-Frame-Options: SAMEORIGIN\" to the server response.",
        "Добавьте в ответ сервера «X-Frame-Options: SAMEORIGIN»."),

    # csp
    "Saytda hansı skriptlərin işləyə biləcəyi məhdudlaşdırılıb.": (
        "The site limits which scripts are allowed to run.",
        "Сайт ограничивает, какие скрипты могут выполняться."),
    "Saytda kənar skriptlərə nəzarət qaydası (CSP) yoxdur.": (
        "The site has no rule controlling third-party scripts (CSP).",
        "У сайта нет правила контроля сторонних скриптов (CSP)."),
    "Content-Security-Policy başlığını əvvəlcə report-only rejimində qurun.": (
        "Set up the Content-Security-Policy header, starting in report-only mode.",
        "Настройте заголовок Content-Security-Policy, начав с режима report-only."),

    # disclosure
    "Server və sayt proqramlarının versiyaları açıq göstərilmir.": (
        "Server and site software versions are not shown publicly.",
        "Версии серверного ПО и движка сайта не раскрываются."),
    "Versiya məlumatını gizlədin və proqramları son versiyaya yeniləyin.": (
        "Hide the version information and update the software to the latest version.",
        "Скройте информацию о версиях и обновите ПО до последней версии."),

    # mixed
    "Sayt https olmadığı üçün yoxlanılmadı.": (
        "Not checked because the site is not on https.", "Не проверялось, так как сайт не на https."),
    "Bütün şəkil və skriptlər təhlükəsiz bağlantı ilə yüklənir.": (
        "All images and scripts load over a secure connection.",
        "Все изображения и скрипты загружаются по защищённому соединению."),
    "Səhifədəki http:// linklərini https:// ilə əvəz edin.": (
        "Replace the http:// links on the page with https://.",
        "Замените ссылки http:// на странице на https://."),

    # mail
    "Sayt pulsuz platforma ünvanında yerləşir, bu ünvandan e-poçt göndərilmir. "
    "Öz domeniniz (məsələn, .az) olanda bu yoxlama vacib olacaq.": (
        ("The site lives on a free platform address, which sends no e-mail. "
        "This check will matter once you have your own domain (for example, .az)."),
        ("Сайт размещён на адресе бесплатной платформы, с него не отправляется почта. "
        "Эта проверка станет важной, когда у вас будет свой домен (например, .az).")),
    "DNS yoxlanıla bilmədi.": ("DNS could not be checked.", "Не удалось проверить DNS."),
    "Domen adından kimin məktub göndərə biləcəyi müəyyən edilib.": (
        "The domain states who may send e-mail in its name.",
        "Для домена указано, кто может отправлять письма от его имени."),
    "Hər kəs sizin domen adınızdan saxta məktub göndərə bilər, məktublarınız isə spam-a düşə bilər.": (
        "Anyone can send fake e-mail in your domain's name, and your own e-mails may land in spam.",
        "Любой может отправлять поддельные письма от имени вашего домена, а ваши письма могут попадать в спам."),
    "DNS-ə SPF qeydi əlavə edin (məsələn, e-poçt provayderinizin verdiyi v=spf1 ... qeydi).": (
        "Add an SPF record to DNS (for example, the v=spf1 ... record your e-mail provider gives you).",
        "Добавьте в DNS запись SPF (например, запись v=spf1 ..., которую даёт ваш почтовый провайдер)."),
    "Domen adınızdan göndərilən saxta məktublar üçün heç bir qayda yoxdur.": (
        "There is no rule for fake e-mails sent in your domain's name.",
        "Нет никакого правила для поддельных писем от имени вашего домена."),
    "DNS-ə _dmarc qeydi əlavə edin, əvvəlcə p=none ilə başlayın.": (
        "Add a _dmarc record to DNS, starting with p=none.",
        "Добавьте в DNS запись _dmarc, начав с p=none."),
    "DMARC var, amma yalnız müşahidə rejimindədir (p=none); saxta məktublar bloklanmır.": (
        "DMARC is set, but only in monitoring mode (p=none); fake e-mails are not blocked.",
        "DMARC есть, но только в режиме наблюдения (p=none); поддельные письма не блокируются."),
    "Hesabatları yoxladıqdan sonra siyasəti p=quarantine və ya p=reject edin.": (
        "After reviewing the reports, change the policy to p=quarantine or p=reject.",
        "Изучив отчёты, смените политику на p=quarantine или p=reject."),
    "Saxta məktublar qəbul edən tərəfindən bloklanır.": (
        "Fake e-mails are blocked by the receiving side.",
        "Поддельные письма блокируются на стороне получателя."),

    # speed
    "Hostinqi, keşləməni və ağır plaginləri yoxlayın.": (
        "Check the hosting, caching and heavy plugins.",
        "Проверьте хостинг, кэширование и тяжёлые плагины."),
    "Səhifəyə daxil edilmiş böyük kodları və şəkilləri ayrı fayllara çıxarın.": (
        "Move large inline code and images out of the page into separate files.",
        "Вынесите большой встроенный код и изображения в отдельные файлы."),

    # mobile & search
    "Sayt telefon ekranına uyğunlaşmaq üçün qurulub.": (
        "The site is set up to fit phone screens.", "Сайт настроен под экраны телефонов."),
    "Sayt telefonda kiçik və oxunmaz görünə bilər; Google bunu nəzərə alır.": (
        "The site may look tiny and unreadable on a phone; Google takes this into account.",
        "На телефоне сайт может выглядеть мелким и нечитаемым; Google это учитывает."),
    "Səhifəyə <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> əlavə edin.": (
        "Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> to the page.",
        "Добавьте на страницу <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">."),
    "Səhifənin başlığı yoxdur.": ("The page has no title.", "У страницы нет заголовка."),
    "Biznesi və xidməti izah edən 10–70 simvollu başlıq yazın.": (
        "Write a 10–70 character title that explains the business and the service.",
        "Напишите заголовок длиной 10–70 символов, описывающий бизнес и услугу."),
    "Google axtarışında görünən təsvir yoxdur.": (
        "There is no description for Google search results.",
        "Нет описания, которое показывается в поиске Google."),
    "50–170 simvolluq, xidməti və əlaqəni göstərən meta description yazın.": (
        "Write a 50–170 character meta description with the service and how to get in touch.",
        "Напишите meta description длиной 50–170 символов с услугой и контактами."),
    "Səhifənin məzmunu oxunmadı (server boş cavab qaytardı). "
    "Bu yoxlama bala təsir etmir; saytı brauzerdə açıb yenidən yoxlayın.": (
        ("The page content could not be read (the server returned an empty response). "
        "This check does not affect the score; open the site in a browser and check again."),
        ("Содержимое страницы не прочитано (сервер вернул пустой ответ). "
        "Эта проверка не влияет на балл; откройте сайт в браузере и проверьте снова.")),

    # summary
    "Əla nəticə: ciddi problem tapılmadı.": (
        "Great result: no serious problems found.", "Отличный результат: серьёзных проблем не найдено."),

    # deeper checks: titles
    "Cookie təhlükəsizliyi": ("Cookie security", "Безопасность cookie"),
    "Şifrələmə versiyası (TLS)": ("Encryption version (TLS)", "Версия шифрования (TLS)"),
    "E-poçt imzası (DKIM)": ("E-mail signature (DKIM)", "Подпись писем (DKIM)"),
    "Əsas başlıq (H1)": ("Main heading (H1)", "Основной заголовок (H1)"),
    "Səhifənin dili": ("Page language", "Язык страницы"),
    "Əsas ünvan (canonical)": ("Main address (canonical)", "Основной адрес (canonical)"),
    "Sosial şəbəkə kartı": ("Social media card", "Карточка для соцсетей"),
    "Google-da görünmə icazəsi": ("Permission to appear in Google", "Разрешение на показ в Google"),
    "Sayt xəritəsi (sitemap)": ("Sitemap", "Карта сайта (sitemap)"),

    # deeper checks: details and fixes
    "Sertifikat vaxtında oxuna bilmədi.": ("The certificate could not be read in time.", "Не удалось вовремя прочитать сертификат."),
    "HSTS müddətini ən azı 180 günə qaldırın (max-age=31536000 tövsiyə olunur).": (
        "Raise the HSTS time to at least 180 days (max-age=31536000 is recommended).",
        "Увеличьте срок HSTS минимум до 180 дней (рекомендуется max-age=31536000)."),
    "X-Content-Type-Options başlığının dəyəri səhvdir, brauzer onu nəzərə almır.": (
        "The X-Content-Type-Options header has a wrong value, so browsers ignore it.",
        "У заголовка X-Content-Type-Options неверное значение, браузеры его игнорируют."),
    "Referrer-Policy digər saytlara səhifənin tam ünvanını ötürməyə icazə verir.": (
        "Referrer-Policy lets other sites receive the page's full address.",
        "Referrer-Policy разрешает передавать другим сайтам полный адрес страницы."),
    "CSP yalnız müşahidə rejimindədir (report-only), heç nəyi bloklamır.": (
        "CSP is only in monitoring mode (report-only) and blocks nothing.",
        "CSP только в режиме наблюдения (report-only) и ничего не блокирует."),
    "Hesabatları yoxladıqdan sonra başlığı Content-Security-Policy adı ilə işə salın.": (
        "After reviewing the reports, turn the header on under the name Content-Security-Policy.",
        "Изучив отчёты, включите заголовок под именем Content-Security-Policy."),
    "script-src qaydasından unsafe-inline, unsafe-eval və * dəyərlərini çıxarın, nonce və ya hash işlədin.": (
        "Remove unsafe-inline, unsafe-eval and * from script-src, and use a nonce or hash.",
        "Уберите из script-src unsafe-inline, unsafe-eval и *, используйте nonce или hash."),
    "Əsas səhifə cookie yazmır.": ("The home page sets no cookies.", "Главная страница не устанавливает cookie."),
    "Cookie-lərə Secure və SameSite=Lax, giriş cookie-lərinə HttpOnly da əlavə edin.": (
        "Add Secure and SameSite=Lax to cookies, and HttpOnly to login cookies as well.",
        "Добавьте cookie атрибуты Secure и SameSite=Lax, а cookie входа ещё и HttpOnly."),
    "TLS versiyası oxunmadı.": ("The TLS version was not read.", "Версия TLS не прочитана."),
    "Geniş yayılmış adlarda DKIM açarı tapılmadı. Bu, DKIM-in olmadığını sübut etmir.": (
        "No DKIM key was found under the common names. This does not prove that DKIM is missing.",
        "Ключ DKIM не найден под распространёнными именами. Это не доказывает, что DKIM нет."),
    "Səhifədə bir əsas başlıq var.": ("The page has one main heading.", "На странице один основной заголовок."),
    "Səhifədə əsas başlıq (H1) yoxdur.": ("The page has no main heading (H1).", "На странице нет основного заголовка (H1)."),
    "Səhifənin mövzusunu izah edən bir H1 başlığı saxlayın.": (
        "Keep one H1 heading that explains what the page is about.",
        "Оставьте один заголовок H1, объясняющий тему страницы."),
    "Səhifənin dili göstərilməyib.": ("The page's language is not set.", "Язык страницы не указан."),
    "<html> teqinə dili əlavə edin, məsələn: <html lang=\"az\">.": (
        "Add the language to the <html> tag, for example: <html lang=\"az\">.",
        "Добавьте язык в тег <html>, например: <html lang=\"az\">."),
    "Google-a səhifənin əsas ünvanı göstərilib.": (
        "Google is told the page's main address.", "Google указан основной адрес страницы."),
    "Google-a səhifənin əsas ünvanı göstərilməyib.": (
        "Google is not told the page's main address.", "Google не указан основной адрес страницы."),
    "Səhifəyə <link rel=\"canonical\" href=\"...\"> əlavə edin.": (
        "Add <link rel=\"canonical\" href=\"...\"> to the page.", "Добавьте на страницу <link rel=\"canonical\" href=\"...\">."),
    "Link paylaşılanda başlıq və şəkil görünür.": (
        "A shared link shows a title and an image.", "При отправке ссылки видны заголовок и картинка."),
    "Link WhatsApp və Facebook-da paylaşılanda başlıq və ya şəkil görünməyə bilər.": (
        "A link shared on WhatsApp or Facebook may show no title or image.",
        "Ссылка в WhatsApp и Facebook может отображаться без заголовка или картинки."),
    "Səhifəyə og:title və og:image meta teqlərini əlavə edin.": (
        "Add the og:title and og:image meta tags to the page.", "Добавьте на страницу мета-теги og:title и og:image."),
    "Səhifə Google-dan gizlədilib (noindex), axtarışda çıxmayacaq.": (
        "The page is hidden from Google (noindex) and will not appear in search.",
        "Страница скрыта от Google (noindex) и не появится в поиске."),
    "Sayt açıqdırsa, robots meta teqindən və ya X-Robots-Tag başlığından noindex-i çıxarın.": (
        "If the site is public, remove noindex from the robots meta tag or the X-Robots-Tag header.",
        "Если сайт открытый, уберите noindex из мета-тега robots или заголовка X-Robots-Tag."),
    "robots.txt vaxtında oxuna bilmədi.": ("robots.txt could not be read in time.", "Не удалось вовремя прочитать robots.txt."),
    "robots.txt bütün sayta girişi bağlayır, sayt axtarışda çıxmayacaq.": (
        "robots.txt blocks the whole site, so it will not appear in search.",
        "robots.txt закрывает весь сайт, он не появится в поиске."),
    "Sayt açıqdırsa, robots.txt-dən \"Disallow: /\" sətrini çıxarın.": (
        "If the site is public, remove the \"Disallow: /\" line from robots.txt.",
        "Если сайт открытый, уберите из robots.txt строку «Disallow: /»."),
    "Axtarış sistemlərinə sayta baxmaq icazəsi verilib.": (
        "Search engines are allowed to look at the site.", "Поисковым системам разрешено просматривать сайт."),
    "Sayt xəritəsi vaxtında oxuna bilmədi.": ("The sitemap could not be read in time.", "Не удалось вовремя прочитать карту сайта."),
    "Sayt xəritəsi tapıldı.": ("A sitemap was found.", "Карта сайта найдена."),
    "Sayt xəritəsi (sitemap.xml) tapılmadı.": ("No sitemap (sitemap.xml) was found.", "Карта сайта (sitemap.xml) не найдена."),
    "sitemap.xml yaradın və ünvanını robots.txt-ə yazın.": (
        "Create sitemap.xml and write its address in robots.txt.", "Создайте sitemap.xml и укажите его адрес в robots.txt."),
    "Səhifə JavaScript ilə qurulur, bu məlumat brauzerdə əlavə oluna bilər və burada yoxlanılmadı. "
    "Bu yoxlama bala təsir etmir.": (
        ("The page is built by JavaScript, so this may be added in the browser and was not checked here. "
        "This check does not affect the score."),
        ("Страница строится на JavaScript, поэтому эти данные могут добавляться в браузере и здесь не проверялись. "
        "Эта проверка не влияет на балл.")),

    # score limits
    "Sayt etibarlı HTTPS ilə açılmadığı üçün bal 39-dan yuxarı ola bilməz.": (
        "The score cannot go above 39 because the site does not open over trusted HTTPS.",
        "Балл не может быть выше 39: сайт не открывается по надёжному HTTPS."),
    "Sertifikatın vaxtı bitmək üzrə olduğu üçün bal 59-dan yuxarı ola bilməz.": (
        "The score cannot go above 59 because the certificate is about to expire.",
        "Балл не может быть выше 59: срок действия сертификата заканчивается."),

    # errors
    "Sayt açılmadı: təhlükəsiz bağlantı (SSL) qurula bilmədi. Hostinq panelində SSL ayarlarını yoxlayın.": (
        "The site did not open: a secure connection (SSL) could not be made. Check the SSL settings in your hosting panel.",
        "Сайт не открылся: не удалось установить защищённое соединение (SSL). Проверьте настройки SSL в панели хостинга."),
    "Sayt açılmadı: server vaxtında cavab vermədi. Bir az sonra yenidən cəhd edin.": (
        "The site did not open: the server did not answer in time. Try again a little later.",
        "Сайт не открылся: сервер не ответил вовремя. Попробуйте немного позже."),
    "Sayt açılmadı: serverə qoşulmaq mümkün olmadı. Ünvanı yoxlayın və bir az sonra yenidən cəhd edin.": (
        "The site did not open: could not connect to the server. Check the address and try again a little later.",
        "Сайт не открылся: не удалось подключиться к серверу. Проверьте адрес и попробуйте немного позже."),
    "Bu ünvanda təhlükəsiz bağlantı (HTTPS) açılmadı. Sayt HTTPS işlətmir və ya sertifikat oxuna bilmədi.": (
        "No secure connection (HTTPS) opened at this address. The site does not use HTTPS, or the certificate could not be read.",
        "По этому адресу не открылось защищённое соединение (HTTPS). Сайт не использует HTTPS, или сертификат не удалось прочитать."),
    "Əvvəlcə saytın sizə aid olduğunu təsdiqləyin.": (
        "First confirm that the site is yours.", "Сначала подтвердите, что сайт принадлежит вам."),
    "Bu hissə indi yoxlanıla bilmədi. Bir az sonra yenidən cəhd edin.": (
        "This part could not be checked right now. Try again a little later.",
        "Эту часть сейчас не удалось проверить. Попробуйте немного позже."),
    "Ünvan çox uzundur. Yalnız domeni yazın, məsələn: example.az": (
        "The address is too long. Enter just the domain, for example: example.az",
        "Адрес слишком длинный. Введите только домен, например: example.az"),
    "Saytın ünvanını yazın, məsələn: example.az": (
        "Enter the site's address, for example: example.az", "Введите адрес сайта, например: example.az"),
    "Yalnız http və https ünvanları yoxlanılır.": (
        "Only http and https addresses can be checked.", "Проверяются только адреса http и https."),
    "Ünvanda istifadəçi adı və ya şifrə olmamalıdır.": (
        "The address must not contain a username or password.",
        "Адрес не должен содержать имя пользователя или пароль."),
    "Ünvan düzgün görünmür. Nümunə: example.az": (
        "The address does not look right. Example: example.az",
        "Адрес выглядит неправильно. Пример: example.az"),
    "Yalnız standart portlar (80, 443) yoxlanılır.": (
        "Only standard ports (80, 443) can be checked.", "Проверяются только стандартные порты (80, 443)."),
    "Bu ünvan tapılmadı. Yazılışı yoxlayın.": (
        "This address was not found. Check the spelling.", "Этот адрес не найден. Проверьте написание."),
    "Bu ünvan daxili şəbəkəyə aiddir və yoxlanıla bilməz.": (
        "This address belongs to a private network and cannot be checked.",
        "Этот адрес относится к внутренней сети и не может быть проверен."),
    "Sayt çox sayda yönləndirmə edir.": ("The site redirects too many times.", "Сайт делает слишком много перенаправлений."),
    "Çox sayda yoxlama etdiniz. Bir dəqiqə gözləyib yenidən cəhd edin.": (
        "You have run too many checks. Wait a minute and try again.",
        "Слишком много проверок. Подождите минуту и попробуйте снова."),
    "Bu səhifə tapılmadı (kod 404). Ünvanın yazılışını yoxlayın və ya yalnız domeni yazın, məsələn: example.az": (
        "This page was not found (code 404). Check the spelling, or enter just the domain, for example: example.az",
        "Страница не найдена (код 404). Проверьте написание или введите только домен, например: example.az"),
}

# (pattern, English template, Russian template); groups are reused by number.
PATTERNS: list[tuple[re.Pattern, str, str]] = [(re.compile(p, re.DOTALL), en, ru) for p, en, ru in [
    (r"Sertifikatın vaxtı (-?\d+) gün sonra bitir\.",
     r"The certificate expires in \1 days.",
     r"Срок действия сертификата истекает через \1 дн."),
    (r"Sertifikat etibarlıdır, (\d+) gün qalıb \((.+)\)\.",
     r"The certificate is valid, \1 days left (\2).",
     r"Сертификат действителен, осталось \1 дн. (\2)."),
    ((r"Sayt istifadə etdiyi proqramların dəqiq versiyasını göstərir: (.+)\. "
     r"Hücumçular köhnə versiyaların zəifliklərini axtarır\."),
     r"The site shows the exact versions of the software it runs: \1. Attackers look for weaknesses in old versions.",
     r"Сайт показывает точные версии используемого ПО: \1. Злоумышленники ищут уязвимости старых версий."),
    (r"(\d+) fayl şifrəsiz http:// ilə yüklənir; brauzer onları bloklaya bilər\.",
     r"\1 file(s) load over unencrypted http://; browsers may block them.",
     r"Файлов, загружаемых по незашифрованному http://: \1; браузер может их блокировать."),
    (r"Server (\d+) millisaniyəyə cavab verdi\.",
     r"The server responded in \1 milliseconds.",
     r"Сервер ответил за \1 мс."),
    (r"Server ([\d.]+) saniyəyə cavab verdi\.",
     r"The server responded in \1 seconds.",
     r"Сервер ответил за \1 с."),
    (r"Əsas səhifənin HTML həcmi (\d+) KB-dır\.",
     r"The home page HTML is \1 KB.",
     r"Размер HTML главной страницы: \1 КБ."),
    (r"Başlıq: \"(.*)\" \((\d+) simvol\)\.",
     r"Title: \"\1\" (\2 characters).",
     r"Заголовок: «\1» (символов: \2)."),
    (r"Təsvir (\d+) simvoldur\.",
     r"The description is \1 characters long.",
     r"Длина описания: \1 символов."),
    # e-mail records inherited from the parent domain
    (r"Bu subdomenin öz SPF qeydi yoxdur, amma əsas domenin \((.+)\) DMARC qaydası saxta məktubları bloklayır\.",
     r"This subdomain has no SPF record of its own, but the DMARC rule of the main domain (\1) blocks fake e-mails.",
     r"У этого поддомена нет своей записи SPF, но правило DMARC основного домена (\1) блокирует поддельные письма."),
    (r"Bu subdomenin öz qeydi yoxdur, amma əsas domenin \((.+)\) DMARC qaydası saxta məktubları bloklayır\.",
     r"This subdomain has no record of its own, but the DMARC rule of the main domain (\1) blocks fake e-mails.",
     r"У этого поддомена нет своей записи, но правило DMARC основного домена (\1) блокирует поддельные письма."),
    (r"Əsas domenin \((.+)\) DMARC qaydası yalnız müşahidə rejimindədir \(p=none\); saxta məktublar bloklanmır\.",
     r"The DMARC rule of the main domain (\1) only monitors (p=none); fake e-mails are not blocked.",
     r"Правило DMARC основного домена (\1) только наблюдает (p=none); поддельные письма не блокируются."),
    # score limits
    (r"(\d+) əsas qoruma ayarı çatışmadığı və ya zəif olduğu üçün bal (\d+)-(?:dən|dan) yuxarı ola bilməz\.",
     r"The score cannot go above \2 because \1 basic protection settings are missing or weak.",
     r"Балл не может быть выше \2: основные настройки защиты отсутствуют или слабые (\1)."),
    # deeper checks
    (r"HSTS çox qısa müddətə qurulub \((\d+) gün\), brauzerlər bu əmri tez unudur\.",
     r"HSTS is set for too short a time (\1 days), so browsers soon forget it.",
     r"HSTS задан на слишком короткий срок (дней: \1), браузеры быстро его забывают."),
    (r"CSP var, amma skriptləri az məhdudlaşdırır: unsafe-inline\.",
     r"CSP is set, but it does little to limit scripts: unsafe-inline.",
     r"CSP есть, но мало ограничивает скрипты: unsafe-inline."),
    (r"CSP var, amma skriptləri az məhdudlaşdırır: unsafe-eval\.",
     r"CSP is set, but it does little to limit scripts: unsafe-eval.",
     r"CSP есть, но мало ограничивает скрипты: unsafe-eval."),
    (r"CSP var, amma skriptləri az məhdudlaşdırır: skriptlər üçün qayda yoxdur\.",
     r"CSP is set, but it does little to limit scripts: it has no rule for scripts.",
     r"CSP есть, но мало ограничивает скрипты: нет правила для скриптов."),
    (r"CSP var, amma skriptləri az məhdudlaşdırır: hər yerdən skriptə icazə\.",
     r"CSP is set, but it does little to limit scripts: scripts are allowed from anywhere.",
     r"CSP есть, но мало ограничивает скрипты: скрипты разрешены отовсюду."),
    (r"Cookie-lər qorunub \((\d+) ədəd\)\.",
     r"The cookies are protected (\1).",
     r"Cookie защищены (\1)."),
    (r"(\d+) cookie-də qoruma çatışmır: (.+)\.",
     r"Protection is missing on \1 cookie(s): \2.",
     r"Не хватает защиты у cookie (\1): \2."),
    (r"Bağlantı (TLS [\d.]+) ilə qurulur\.",
     r"The connection uses \1.",
     r"Соединение использует \1."),
    (r"Məktubları imzalayan DKIM açarı tapıldı \((.+)\)\.",
     r"A DKIM key that signs e-mails was found (\1).",
     r"Найден ключ DKIM, подписывающий письма (\1)."),
    (r"Səhifədə (\d+) əsas başlıq \(H1\) var\.",
     r"The page has \1 main headings (H1).",
     r"На странице несколько основных заголовков H1: \1."),
    (r"Səhifənin dili göstərilib \((.+)\)\.",
     r"The page's language is set (\1).",
     r"Язык страницы указан (\1)."),
    # summary
    (r"(\d+) ciddi problem və (\d+) təkmilləşdirmə tövsiyəsi tapıldı\.",
     r"Found \1 serious problem(s) and \2 improvement(s) to make.",
     r"Найдено серьёзных проблем: \1, рекомендаций по улучшению: \2."),
    (r"(\d+) ciddi problem tapıldı\.",
     r"Found \1 serious problem(s).",
     r"Найдено серьёзных проблем: \1."),
    (r"(\d+) təkmilləşdirmə tövsiyəsi tapıldı\.",
     r"Found \1 improvement(s) to make.",
     r"Рекомендаций по улучшению: \1."),
    # errors
    (r"Sayt avtomatik yoxlamaları bloklayır \(kod (\d+)\)\. .*",
     (r"The site blocks automated checks (code \1). This is usually bot protection (for example, Cloudflare): "
     r"the site opens in a browser but does not answer tools. Big platforms (lalafo, tap.az, Instagram) do this; "
     r"check the business's own site instead."),
     (r"Сайт блокирует автоматические проверки (код \1). Обычно это защита от ботов (например, Cloudflare): "
     r"в браузере сайт открывается, но инструментам не отвечает. Так делают крупные платформы "
     r"(lalafo, tap.az, Instagram); проверьте собственный сайт бизнеса.")),
    (r"Saytın serverində xəta var \(kod (\d+)\)\. Bir az sonra yenidən cəhd edin\.",
     r"The site's server has an error (code \1). Try again a little later.",
     r"На сервере сайта ошибка (код \1). Попробуйте немного позже."),
    (r"Sayt xəta qaytardı \(kod (\d+)\)\. Ünvanı yoxlayın\.",
     r"The site returned an error (code \1). Check the address.",
     r"Сайт вернул ошибку (код \1). Проверьте адрес."),
]]


def lang_of(value: str | None) -> str:
    v = (value or "az").lower()[:2]
    return v if v in LANGS else "az"


def text(s: str, lang: str) -> str:
    """Translate one sentence. Unknown text is returned unchanged (Azerbaijani)."""
    if lang == "az" or not s:
        return s
    i = LANGS.index(lang) - 1
    if s in EXACT:
        return EXACT[s][i]
    for pat, en, ru in PATTERNS:
        m = pat.fullmatch(s)
        if m:
            # a group may itself be a known sentence (an error inside an error)
            out = (en, ru)[i]
            for n, g in enumerate(m.groups(), 1):
                out = out.replace(f"\\{n}", text(g, lang) if g and g in EXACT else (g or ""))
            if lang == "en":       # "1 file(s)" -> "1 file", "3 file(s)" -> "3 files"
                out = re.sub(r"\b(\d+) ((?:\w+ )?\w+)\(s\)", lambda m: f"{m[1]} {m[2]}" + ("" if m[1] == "1" else "s"), out)
            return out
    return s


def known(s: str) -> bool:
    """True when text() has a translation for s (used by the tests)."""
    return not s or s in EXACT or any(p.fullmatch(s) for p, _, _ in PATTERNS)


def report(d: dict, lang: str) -> dict:
    """A translated copy of Report.to_dict(); the original (cached) dict is not changed."""
    if lang == "az":
        return d
    out = dict(d, summary=text(d["summary"], lang), score_note=text(d.get("score_note", ""), lang), lang=lang)
    out["findings"] = [dict(f, **{k: text(f[k], lang) for k in ("category", "title", "detail", "fix")})
                       for f in d["findings"]]
    return out
