"""
Small static pages in three languages: about, privacy, terms and the 404 page.

What the privacy page says must stay true of the code: the report cache in web/app.py (10 minutes),
the rate-limit counters in web/ratelimit.py (up to a day) and the absence of cookies and analytics.
"""

from __future__ import annotations

from web.seo import SITE_URL

LANGS = ("az", "en", "ru")
HOMES = {"az": "/", "en": "/en/", "ru": "/ru/"}
PATHS = {
    "about": {"az": "/haqqimizda/", "en": "/en/about/", "ru": "/ru/o-nas/"},
    "privacy": {"az": "/mexfilik/", "en": "/en/privacy/", "ru": "/ru/konfidencialnost/"},
    "terms": {"az": "/sertler/", "en": "/en/terms/", "ru": "/ru/usloviya/"},
}
ROUTES = {path: (key, lang) for key, by_lang in PATHS.items() for lang, path in by_lang.items()}
LINKS = {
    "about": {"az": "Haqqımızda", "en": "About", "ru": "О сервисе"},
    "privacy": {"az": "Məxfilik", "en": "Privacy", "ru": "Конфиденциальность"},
    "terms": {"az": "Şərtlər", "en": "Terms", "ru": "Условия"},
}
UPDATED = {"az": "Son yenilənmə: 4 noyabr 2026", "en": "Last updated: 4 November 2026", "ru": "Обновлено: 4 ноября 2026"}

WHATSAPP = '<a href="https://wa.me/994772172358" target="_blank" rel="noopener">WhatsApp</a>'
LINKEDIN = '<a href="https://www.linkedin.com/in/ziya-azizov-91bba638a" target="_blank" rel="noopener">LinkedIn</a>'
INSTAGRAM = '<a href="https://www.instagram.com/ayfar.web/" target="_blank" rel="noopener">Instagram</a>'
CONTACT = f"{WHATSAPP} · {LINKEDIN} · {INSTAGRAM}"

# key -> lang -> (title, meta description, body)
CONTENT = {
    "about": {
        "az": ("SaytYoxla haqqında", "SaytYoxla kiçik bizneslər üçün saytın təhlükəsizliyini, e-poçt qorumasını və sürətini pulsuz yoxlayan alətdir.", f"""
<p>SaytYoxla kiçik biznes sahibləri və sayt quranlar üçün pulsuz alətdir. Saytın ünvanını yazırsınız, biz təhlükəsizlik, e-poçt qoruması, sürət və telefona uyğunluq ayarlarını yoxlayıb nəticəni sadə dildə izah edirik.</p>
<h2>Necə işləyir?</h2>
<p>Yalnız hər kəsə açıq olan məlumata baxırıq: əsas səhifəni bir dəfə açırıq, sertifikatı və açıq DNS qeydlərini oxuyuruq. Saytı sındırmağa çalışmırıq və heç nəyi dəyişmirik. Bu, tam təhlükəsizlik auditi deyil: kənardan görünməyən problemləri aşkar edə bilmir.</p>
<h2>Müəllif</h2>
<p>SaytYoxla-nı Ziya Azizov hazırlayıb.</p>
<h2>Əlaqə</h2>
<p>{CONTACT}</p>"""),
        "en": ("About SaytYoxla", "SaytYoxla is a free tool that checks a website's security, e-mail protection and speed for small businesses.", f"""
<p>SaytYoxla is a free tool for small business owners and the people who build their websites. You enter a site's address, and we check its security, e-mail protection, speed and mobile settings, then explain the result in plain words.</p>
<h2>How it works</h2>
<p>We only look at information that is open to everyone: we open the home page once and read the certificate and public DNS records. We do not try to break into the site and we change nothing. This is not a full security audit: it cannot find problems that are not visible from outside.</p>
<h2>Author</h2>
<p>SaytYoxla was made by Ziya Azizov.</p>
<h2>Contact</h2>
<p>{CONTACT}</p>"""),
        "ru": ("О сервисе SaytYoxla", "SaytYoxla — бесплатный инструмент для малого бизнеса: проверка безопасности сайта, защиты почты и скорости.", f"""
<p>SaytYoxla — бесплатный инструмент для владельцев малого бизнеса и тех, кто делает им сайты. Вы вводите адрес сайта, а мы проверяем безопасность, защиту почты, скорость и адаптацию под телефон и объясняем результат простыми словами.</p>
<h2>Как это работает</h2>
<p>Мы смотрим только на открытую информацию: один раз открываем главную страницу, читаем сертификат и открытые DNS-записи. Мы не пытаемся взломать сайт и ничего не меняем. Это не полный аудит безопасности: проблемы, которые не видны снаружи, он найти не может.</p>
<h2>Автор</h2>
<p>SaytYoxla создал Ziya Azizov.</p>
<h2>Контакты</h2>
<p>{CONTACT}</p>"""),
    },
    "privacy": {
        "az": ("Məxfilik", "SaytYoxla hansı məlumatı nə qədər saxlayır: ünvan və nəticə 10 dəqiqə, IP sayğacı ən çox 1 gün. Kuki və izləmə yoxdur.", f"""
<p>SaytYoxla qeydiyyat tələb etmir, adınızı, telefonunuzu və ya e-poçtunuzu soruşmur.</p>
<h2>Nə saxlanılır?</h2>
<ul>
<li><b>Yoxlanılan ünvan və nəticə:</b> təkrar yoxlamanı sürətləndirmək üçün serverin yaddaşında 10 dəqiqəyə qədər qalır. Nəticə sizin adınızla bağlanmır.</li>
<li><b>IP ünvanınız:</b> sui-istifadənin qarşısını almaq üçün yoxlama sayını hesablayan sayğacda ən çox 1 gün qalır.</li>
<li><b>Hostinq jurnalları:</b> sayt Vercel-də işləyir. Vercel xidmətin işləməsi üçün texniki sorğu jurnalları apara bilər.</li>
</ul>
<h2>Nə istifadə olunmur?</h2>
<p>Saytda reklam, izləmə skriptləri və kuki faylları yoxdur. Şriftlər də öz serverimizdən yüklənir.</p>
<h2>Yoxlanılan sayt nə görür?</h2>
<p>Yoxlama zamanı saytın əsas səhifəsi serverimizdən bir dəfə açılır. Sayt sizin IP ünvanınızı yox, serverimizin ünvanını görür.</p>
<h2>WhatsApp</h2>
<p>«WhatsApp-a yazın» düyməsini bassanız, hazır mesaj WhatsApp-da açılır və onu siz özünüz göndərirsiniz. Bundan sonra WhatsApp-ın öz qaydaları tətbiq olunur.</p>
<h2>Əlaqə</h2>
<p>Suallarınız üçün: {CONTACT}</p>"""),
        "en": ("Privacy", "What SaytYoxla keeps and for how long: address and result for 10 minutes, IP counter for up to 1 day. No cookies or tracking.", f"""
<p>SaytYoxla needs no sign-up and does not ask for your name, phone or e-mail.</p>
<h2>What is kept</h2>
<ul>
<li><b>The checked address and its result:</b> stay in the server's memory for up to 10 minutes to speed up a repeat check. The result is not tied to your name.</li>
<li><b>Your IP address:</b> stays for up to 1 day in the counter that limits the number of checks, to prevent abuse.</li>
<li><b>Hosting logs:</b> the site runs on Vercel, which may keep technical request logs to operate its service.</li>
</ul>
<h2>What is not used</h2>
<p>The site has no ads, no tracking scripts and no cookies. Fonts are loaded from our own server too.</p>
<h2>What the checked site sees</h2>
<p>During a check, the site's home page is opened once from our server. The site sees our server's address, not your IP address.</p>
<h2>WhatsApp</h2>
<p>If you press "Message on WhatsApp", a prepared message opens in WhatsApp and you send it yourself. WhatsApp's own rules apply from there.</p>
<h2>Contact</h2>
<p>For questions: {CONTACT}</p>"""),
        "ru": ("Конфиденциальность", "Что и как долго хранит SaytYoxla: адрес и результат 10 минут, счётчик IP до 1 дня. Без cookie и отслеживания.", f"""
<p>SaytYoxla не требует регистрации и не спрашивает имя, телефон или e-mail.</p>
<h2>Что хранится</h2>
<ul>
<li><b>Проверенный адрес и результат:</b> до 10 минут в памяти сервера, чтобы ускорить повторную проверку. Результат не связан с вашим именем.</li>
<li><b>Ваш IP-адрес:</b> до 1 дня в счётчике, который ограничивает число проверок, чтобы предотвратить злоупотребления.</li>
<li><b>Журналы хостинга:</b> сайт работает на Vercel, который может вести технические журналы запросов для работы своего сервиса.</li>
</ul>
<h2>Что не используется</h2>
<p>На сайте нет рекламы, скриптов отслеживания и cookie. Шрифты тоже загружаются с нашего сервера.</p>
<h2>Что видит проверяемый сайт</h2>
<p>При проверке главная страница сайта один раз открывается с нашего сервера. Сайт видит адрес нашего сервера, а не ваш IP-адрес.</p>
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
<li>Limitlər var: bir IP ünvanından dəqiqədə 6, gündə 60 təzə yoxlama.</li>
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
<li>There are limits: 6 fresh checks a minute and 60 a day from one IP address.</li>
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
<li>Есть ограничения: 6 новых проверок в минуту и 60 в день с одного IP-адреса.</li>
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
"""


def footer_links(lang: str) -> str:
    return " · ".join(f'<a href="{PATHS[k][lang]}">{LINKS[k][lang]}</a>' for k in PATHS)


def _shell(lang: str, title: str, desc: str, body: str, paths: dict[str, str], robots: str = "index, follow",
           canonical: str | None = None) -> str:
    alt = "".join(f'<link rel="alternate" hreflang="{l}" href="{SITE_URL}{p}">\n' for l, p in paths.items())
    if canonical:
        alt = f'<link rel="canonical" href="{SITE_URL}{canonical}">\n{alt}<link rel="alternate" hreflang="x-default" href="{SITE_URL}{paths["az"]}">\n'
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
{alt}<link rel="icon" href="{ICON}">
<link rel="preload" href="/static/fonts/inter-4-latin.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="/static/fonts.css">
<style>{STYLE}</style>
</head>
<body>
<header class="top"><div class="wrap">
  <a class="brand" href="{HOMES[lang]}"><span class="mark"><svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true"><path d="M9.5 16.2 5.3 12l-1.4 1.4 5.6 5.6 11-11-1.4-1.4z" fill="#34d399"/></svg></span><span>Sayt<b>Yoxla</b></span></a>
  <nav class="langs" aria-label="{nav}">{langs}</nav>
</div></header>
<main class="wrap">
{body}
</main>
<footer><div class="wrap">SaytYoxla · {footer_links(lang)}</div></footer>
</body>
</html>
"""


def page(key: str, lang: str) -> str:
    title, desc, body = CONTENT[key][lang]
    html = f'<h1>{title}</h1>\n<p class="meta">{UPDATED[lang]}</p>\n{body}'
    return _shell(lang, title, desc, html, PATHS[key], canonical=PATHS[key][lang])


def not_found(path: str) -> str:
    lang = next((l for l in ("en", "ru") if path.startswith(f"/{l}/")), "az")
    title, text, back = NOT_FOUND[lang]
    body = f'<h1>{title}</h1>\n<p>{text}</p>\n<a class="btn" href="{HOMES[lang]}">{back}</a>'
    return _shell(lang, title, text, body, HOMES, robots="noindex")
