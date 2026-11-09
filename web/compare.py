"""
Two to four sites side by side: /muqayise/, /en/compare/, /ru/sravnenie/.

The page is ordinary HTML with the form in it; web/static/compare.js asks /api/scan once per site (so the usual
rate limits and the 10-minute cache apply) and draws the scores and the check-by-check table. Every word the script
shows is written here, in WORDS, and handed over as a JSON data block: the script itself knows no language.
Nothing is stored: the addresses live only in the page's link (?u=a.az&u=b.az), which can be shared.
"""

# ruff: noqa: ISC004  (long sentences are written as adjacent string pieces on purpose)

from __future__ import annotations

import json
from html import escape

from web.pages import COMPARE_PATHS as PATHS
from web.pages import HOMES, _shell

MAX_SITES = 4

# lang -> (title, meta description, heading, lead)
META = {
    "az": ("Saytları müqayisə et: iki saytın balı yan-yana",
           "İki–dörd saytın təhlükəsizliyini, e-poçt qorumasını, sürətini və Google ayarlarını yan-yana müqayisə edin. "
           "Pulsuz, qeydiyyatsız.",
           "Saytları müqayisə edin",
           "Öz saytınızı və rəqibinizin saytını yazın. Hansının daha təhlükəsiz və sağlam olduğunu yan-yana göstərək."),
    "en": ("Compare websites: two scores side by side",
           "Compare the security, e-mail protection, speed and Google settings of two to four websites side by side. "
           "Free, no sign-up.",
           "Compare websites",
           "Enter your site and a competitor's. We show side by side which one is more secure and healthy."),
    "ru": ("Сравнение сайтов: баллы двух сайтов рядом",
           "Сравните безопасность, защиту почты, скорость и настройки для Google у двух–четырёх сайтов. "
           "Бесплатно, без регистрации.",
           "Сравните сайты",
           "Введите свой сайт и сайт конкурента. Покажем рядом, какой из них безопаснее и исправнее."),
}

# Text in the page itself
PAGE = {
    "az": {"labels": ["1-ci sayt", "2-ci sayt", "3-cü sayt", "4-cü sayt"],
           "placeholders": ["məsələn: meninsaytim.az", "məsələn: reqibinsayti.az", "məsələn: basqasayt.az", "məsələn: dorduncu.az"],
           "add": "Daha bir sayt əlavə et", "submit": "Müqayisə et",
           "hint": "http:// və ya www yazmağa ehtiyac yoxdur. Hər sayt bir yoxlama sayılır: dəqiqədə 6 yoxlama etmək olar.",
           "noscript": "Müqayisə üçün brauzerdə JavaScript açıq olmalıdır. Bir saytı ana səhifədə də yoxlaya bilərsiniz.",
           "how": "Necə işləyir?",
           "how_items": ["Hər sayt ana səhifədəki yoxlamadan keçir: təhlükəsizlik, e-poçt, sürət, telefon və Google.",
                         "Yalnız hər kəsə açıq olana baxılır. Başqasının saytını müqayisə etmək ona zərər vermir.",
                         "Ünvanlar yalnız səhifənin linkində qalır. Linki kopyalayıb nəticəni başqasına göndərə bilərsiniz."],
           "single": "Bir saytı yoxla"},
    "en": {"labels": ["Site 1", "Site 2", "Site 3", "Site 4"],
           "placeholders": ["for example: mywebsite.com", "for example: competitor.com", "for example: another.com", "for example: fourth.com"],
           "add": "Add another site", "submit": "Compare",
           "hint": "No need to type http:// or www. Each site counts as one check: you can run 6 checks a minute.",
           "noscript": "Comparing needs JavaScript turned on in the browser. You can still check one site on the home page.",
           "how": "How it works",
           "how_items": ["Each site goes through the same check as on the home page: security, e-mail, speed, mobile and Google.",
                         "Only information open to everyone is read. Comparing someone else's site does it no harm.",
                         "The addresses stay only in the page's link. Copy the link to send the result to someone."],
           "single": "Check one site"},
    "ru": {"labels": ["Сайт 1", "Сайт 2", "Сайт 3", "Сайт 4"],
           "placeholders": ["например: moisait.az", "например: konkurent.az", "например: drugoi.az", "например: chetvertyi.az"],
           "add": "Добавить ещё сайт", "submit": "Сравнить",
           "hint": "Не нужно писать http:// или www. Каждый сайт считается одной проверкой: в минуту можно сделать 6 проверок.",
           "noscript": "Для сравнения в браузере должен быть включён JavaScript. Один сайт можно проверить на главной странице.",
           "how": "Как это работает",
           "how_items": ["Каждый сайт проходит ту же проверку, что и на главной: безопасность, почта, скорость, телефон и Google.",
                         "Читаются только открытые всем данные. Сравнение чужого сайта ему не вредит.",
                         "Адреса остаются только в ссылке страницы. Скопируйте ссылку, чтобы отправить результат."],
           "single": "Проверить один сайт"},
}

# Text the script shows. {host}, {score}, {diff}, {n} and {total} are filled in by the script.
WORDS = {
    "az": {"need_two": "Ən azı iki saytın ünvanını yazın.",
           "duplicate": "Eyni sayt iki dəfə yazılıb. Fərqli saytlar yazın.",
           "checking": "Yoxlanılır…", "checking_all": "Saytlar yoxlanılır. Bu, 30 saniyəyə qədər çəkə bilər.",
           "done": "Müqayisə hazırdır.", "network": "Serverə qoşulmaq mümkün olmadı. İnternet bağlantınızı yoxlayın.",
           "generic": "Xəta baş verdi. Bir az sonra yenidən cəhd edin.",
           "failed": "Bu sayt yoxlanıla bilmədi",
           "none_ok": "Saytların heç biri yoxlanıla bilmədi. Ünvanları yoxlayıb yenidən cəhd edin.",
           "one_ok": "Yalnız bir sayt yoxlanıla bildi, müqayisə üçün ən azı ikisi lazımdır.",
           "leader": "Ən yüksək bal: {host}, {score}/100. Fərq: {diff} bal.",
           "tie": "Bal bərabərdir: {score}/100.",
           "grade": "Qiymət", "fail": "ciddi problem", "warn": "tövsiyə", "ok": "qaydasında",
           "full": "Tam hesabat", "remove": "Bu xananı sil",
           "categories": "Sahələr üzrə", "category": "Sahə", "passed": "Keçilən yoxlama: {n} / {total}",
           "checks": "Yoxlamalar üzrə", "check": "Yoxlama",
           "only_diff": "Yalnız fərqli nəticələr göstərilir.", "show_all": "Bütün yoxlamaları göstər ({n})",
           "show_diff": "Yalnız fərqliləri göstər", "no_diff": "Bütün yoxlamaların nəticəsi eynidir.",
           "st_ok": "Qaydasındadır", "st_warn": "Tövsiyə", "st_fail": "Ciddi problem", "st_info": "Məlumat", "st_none": "Yoxdur",
           "copy": "Linki kopyala", "copied": "Kopyalandı", "clear": "Təmizlə",
           "legend": "Rənglərin mənası"},
    "en": {"need_two": "Enter the addresses of at least two sites.",
           "duplicate": "The same site is entered twice. Enter different sites.",
           "checking": "Checking…", "checking_all": "Checking the sites. This can take up to 30 seconds.",
           "done": "The comparison is ready.", "network": "Could not reach the server. Check your internet connection.",
           "generic": "Something went wrong. Try again a little later.",
           "failed": "This site could not be checked",
           "none_ok": "None of the sites could be checked. Check the addresses and try again.",
           "one_ok": "Only one site could be checked; a comparison needs at least two.",
           "leader": "Highest score: {host}, {score}/100. Difference: {diff} points.",
           "tie": "The scores are equal: {score}/100.",
           "grade": "Grade", "fail": "serious", "warn": "to improve", "ok": "passed",
           "full": "Full report", "remove": "Remove this box",
           "categories": "By area", "category": "Area", "passed": "Checks passed: {n} of {total}",
           "checks": "Check by check", "check": "Check",
           "only_diff": "Only results that differ are shown.", "show_all": "Show all checks ({n})",
           "show_diff": "Show only differences", "no_diff": "Every check has the same result.",
           "st_ok": "All good", "st_warn": "Recommendation", "st_fail": "Serious problem", "st_info": "Info", "st_none": "Not there",
           "copy": "Copy link", "copied": "Copied", "clear": "Clear",
           "legend": "What the colours mean"},
    "ru": {"need_two": "Введите адреса хотя бы двух сайтов.",
           "duplicate": "Один и тот же сайт указан дважды. Введите разные сайты.",
           "checking": "Проверяем…", "checking_all": "Проверяем сайты. Это может занять до 30 секунд.",
           "done": "Сравнение готово.", "network": "Не удалось подключиться к серверу. Проверьте интернет-соединение.",
           "generic": "Произошла ошибка. Попробуйте немного позже.",
           "failed": "Этот сайт не удалось проверить",
           "none_ok": "Ни один сайт не удалось проверить. Проверьте адреса и попробуйте снова.",
           "one_ok": "Удалось проверить только один сайт, а для сравнения нужно хотя бы два.",
           "leader": "Самый высокий балл: {host}, {score}/100. Разница в баллах: {diff}.",
           "tie": "Баллы равны: {score}/100.",
           "grade": "Оценка", "fail": "серьёзных", "warn": "рекомендаций", "ok": "в порядке",
           "full": "Полный отчёт", "remove": "Убрать это поле",
           "categories": "По разделам", "category": "Раздел", "passed": "Пройдено проверок: {n} из {total}",
           "checks": "По проверкам", "check": "Проверка",
           "only_diff": "Показаны только различающиеся результаты.", "show_all": "Показать все проверки ({n})",
           "show_diff": "Показать только различия", "no_diff": "Результаты всех проверок совпадают.",
           "st_ok": "В порядке", "st_warn": "Рекомендация", "st_fail": "Серьёзная проблема", "st_info": "Информация", "st_none": "Нет",
           "copy": "Скопировать ссылку", "copied": "Скопировано", "clear": "Очистить",
           "legend": "Что означают цвета"},
}

STYLE_EXTRA = """
:root{--surface:#fff;--fail:#dc2626;--fail-bg:#fef2f2;--warn:#b45309;--warn-bg:#fffbeb;--ok:#047857;--ok-bg:#ecfdf5;--info:#64748b;--info-bg:#f1f5f9}
.wrap{max-width:880px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
[hidden]{display:none!important}
:focus-visible{outline:3px solid #93c5fd;outline-offset:2px;border-radius:8px}
.lead{font-size:18px;max-width:60ch}
.cmp-form{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:18px;margin:22px 0 0}
.cmp-fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
.cmp-field label{display:flex;align-items:center;gap:8px;font-weight:700;font-size:14px;margin-bottom:6px}
.cmp-row{display:flex;gap:6px}
.cmp-field input{flex:1;min-width:0;min-height:48px;font:500 17px var(--font);padding:10px 12px;border:2px solid var(--line-2);border-radius:12px;background:var(--surface);color:var(--ink)}
.cmp-field input:focus{outline:0;border-color:var(--brand-2)}
.cmp-x{flex:none;width:48px;min-height:48px;border:1px solid var(--line-2);border-radius:12px;background:var(--surface);color:var(--ink-2);font:700 20px/1 var(--font);cursor:pointer}
.cmp-x:hover{border-color:var(--brand-2);color:var(--brand-2)}
.cmp-actions{display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between;margin-top:16px}
.cmp-form .hint{margin:12px 0 0;font-size:14px;color:var(--muted)}
.b{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:48px;border:0;border-radius:12px;padding:12px 20px;font:700 16px/1 var(--font);cursor:pointer;text-decoration:none}
.b-main{background:#1d4ed8;color:#fff}
.b-main:hover{background:#1e40af}
.b-main:disabled{background:#93a5c9;cursor:wait}
.b-ghost{background:var(--surface);color:var(--ink);border:1px solid var(--line-2)}
.b-ghost:hover{border-color:var(--brand-2);color:var(--brand-2)}
.cmp-error{margin:14px 0 0;padding:12px 14px;border-radius:12px;background:var(--fail-bg);color:#991b1b;border:1px solid #fecaca;font-weight:600}
.cmp-status{margin:16px 0 0;color:var(--ink-2);font-weight:600;min-height:1.6em}
.cmp-verdict{font-size:clamp(20px,3.4vw,26px);line-height:1.25;margin:26px 0 14px;color:var(--ink)}
.cmp-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.cmp-card{background:var(--surface);border:1px solid var(--line);border-top:5px solid var(--c,var(--line-2));border-radius:14px;padding:16px;min-width:0}
.cmp-card.lead-card{box-shadow:0 14px 30px -22px rgba(15,42,74,.7)}
.cmp-card h3{display:flex;align-items:center;gap:8px;margin:0 0 12px;font-size:16px;line-height:1.3;word-break:break-all}
.num{flex:none;width:26px;height:26px;border-radius:50%;background:var(--brand);color:#fff;display:inline-grid;place-items:center;font:800 13px/1 var(--font)}
.cmp-score{display:flex;align-items:baseline;gap:6px}
.cmp-score b{font-size:44px;line-height:1;letter-spacing:-.02em;color:var(--c,var(--ink))}
.cmp-score small{color:var(--muted);font-weight:600}
.cmp-bar{height:8px;border-radius:4px;background:var(--line);margin:10px 0;overflow:hidden}
.cmp-bar i{display:block;height:100%;width:0;background:var(--c,var(--info));border-radius:4px;transition:width .7s ease-out}
.cmp-grade{display:inline-block;font-weight:800;font-size:13px;padding:4px 10px;border-radius:999px;color:#fff;background:var(--c,var(--info))}
.cmp-counts{list-style:none;margin:12px 0;padding:0;font-size:14px;color:var(--ink-2)}
.cmp-counts li{display:flex;align-items:center;gap:8px;margin:0 0 4px}
.cmp-card p{margin:0;font-size:14px}
.cmp-card .spin{width:34px;height:34px;border-radius:50%;border:4px solid var(--line);border-top-color:#1d4ed8;animation:cmp-spin 1s linear infinite;margin:6px 0 10px}
@keyframes cmp-spin{to{transform:rotate(360deg)}}
.dot{flex:none;width:12px;height:12px;border-radius:50%;display:inline-block;background:var(--info)}
.dot.fail{background:var(--fail)}.dot.warn{background:var(--warn)}.dot.ok{background:var(--ok)}
.cmp-h{font-size:20px;margin:32px 0 4px}
.cmp-sub{color:var(--muted);font-size:14px;margin:0 0 10px}
.cmp-legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:14px;color:var(--ink-2);margin:0 0 10px}
.cmp-legend>span{display:inline-flex;align-items:center;gap:6px}
.tw{overflow-x:auto;background:var(--surface);border:1px solid var(--line);border-radius:14px}
.cmp-table{border-collapse:collapse;width:100%;font-size:15px}
.cmp-table th,.cmp-table td{padding:10px 8px;border-bottom:1px solid var(--line);text-align:center;vertical-align:middle}
.cmp-table tr:last-child th,.cmp-table tr:last-child td{border-bottom:0}
.cmp-table th:first-child{text-align:left;padding-left:14px;font-weight:600;color:var(--ink)}
.cmp-table thead th{color:var(--muted);font-weight:600;font-size:14px}
.cmp-table td{width:64px;font-variant-numeric:tabular-nums}
.cmp-table td.best{font-weight:800;color:var(--ok)}
.cmp-table tr.cat th{background:var(--bg);font-weight:800;font-size:13px;color:var(--ink-2)}
.st{flex:none;display:inline-grid;place-items:center;width:26px;height:26px;border-radius:50%;color:#fff;font:800 14px/1 var(--font);background:var(--info)}
.st.ok{background:var(--ok)}.st.warn{background:var(--warn)}.st.fail{background:var(--fail)}.st.none{background:none;color:var(--muted)}
.cmp-tools{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0 0}
.cmp-how{margin-top:40px}
.cmp-how ul{padding-left:20px}
@media (max-width:640px){.cmp-fields{grid-template-columns:1fr}.cmp-actions .b{flex:1 1 100%}.cmp-table td{width:44px;padding:10px 4px}.cmp-table th:first-child{padding-left:10px}}
@media (prefers-reduced-motion:reduce){.cmp-bar i{transition:none}.cmp-card .spin{animation:none}}
@media screen and (prefers-color-scheme:dark){
:root{--surface:#131c2e;--fail:#f87171;--fail-bg:#3a1618;--warn:#fbbf24;--warn-bg:#332507;--ok:#34d399;--ok-bg:#0d3026;--info:#94a3b8;--info-bg:#1e293b}
.cmp-error{color:#fecaca;border-color:#7f1d1d}
.b-main{background:#2563eb}.b-main:disabled{background:#3a4a66}
.st{color:#0b1220}.st.none{color:var(--muted)}
.cmp-score b{color:var(--ink)}
.num{background:#8ab4ff;color:#0b1220}
:focus-visible{outline-color:#8ab4ff}
}
@media print{.top,.cmp-form,.cmp-tools,.cmp-how,footer,.skip{display:none!important}body{background:#fff}}
"""


def data_block(lang: str) -> str:
    """The script's words as JSON. "<" is written as \\u003c so no text can close the block early."""
    data = {"lang": lang, "home": HOMES[lang], "max": MAX_SITES, "labels": PAGE[lang]["labels"],
            "placeholders": PAGE[lang]["placeholders"], "words": WORDS[lang]}
    return json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")


def _field(lang: str, i: int) -> str:
    p = PAGE[lang]
    return (f'<div class="cmp-field"><label for="cmp-u{i + 1}"><span class="num" aria-hidden="true">{i + 1}</span>{p["labels"][i]}</label>'
            f'<div class="cmp-row"><input id="cmp-u{i + 1}" name="u" type="text" inputmode="url" autocomplete="off" autocapitalize="off" '
            f'spellcheck="false" maxlength="300" placeholder="{escape(p["placeholders"][i])}"></div></div>')


def body(lang: str) -> str:
    _, _, heading, lead = META[lang]
    p = PAGE[lang]
    items = "".join(f"<li>{x}</li>" for x in p["how_items"])
    return f"""<h1>{heading}</h1>
<p class="lead">{lead}</p>
<form class="cmp-form" id="cmp-form" novalidate>
  <div class="cmp-fields" id="cmp-fields">{_field(lang, 0)}{_field(lang, 1)}</div>
  <div class="cmp-actions">
    <button class="b b-ghost" type="button" id="cmp-add" hidden>+ {p["add"]}</button>
    <button class="b b-main" type="submit" id="cmp-go">{p["submit"]}</button>
  </div>
  <p class="hint">{p["hint"]}</p>
</form>
<noscript><p class="cmp-error">{p["noscript"]}</p></noscript>
<p class="cmp-error" id="cmp-error" role="alert" hidden></p>
<p class="cmp-status" id="cmp-status" role="status" aria-live="polite"></p>
<section id="cmp-result" hidden></section>
<section class="cmp-how">
  <h2>{p["how"]}</h2>
  <ul>{items}</ul>
  <p><a href="{HOMES[lang]}">{p["single"]}</a></p>
</section>
<script type="application/json" id="cmp-data">{data_block(lang)}</script>
<script src="/static/compare.js" defer></script>"""


def page(lang: str) -> str:
    title, desc, _, _ = META[lang]
    html = _shell(lang, title, desc, body(lang), PATHS, canonical=PATHS[lang])
    return html.replace("</style>", STYLE_EXTRA + "</style>", 1)
