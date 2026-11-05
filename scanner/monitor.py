"""
Watching a site for its owner: each day compare it with last time and send an e-mail when something changed.

Needs accounts, so it stays off until they exist: Redis (the same one as the rate limits), a Brevo key for mail
(BREVO_API_KEY, MONITOR_FROM), MONITOR_SECRET to sign links and CRON_SECRET for the timer. Only someone who proved the
site is theirs can subscribe, and the address must confirm itself by a link, so nobody can be signed up by another.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time

import requests

from scanner import deep

EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s.]{2,}$")
KEY = "saytyoxla:mon"
LINK_LIFE = 3 * 86400
CHECK_EVERY = 86400
PER_RUN = 2             # a run has 45 seconds, and each site takes a few of its parts
MODULES = ("surface", "mail", "tls", "reputation")
CERT_WARN = 14
WORDS = {
    "az": {"confirm_subject": "SaytYoxla: {host} izləməsini təsdiqləyin", "confirm_body": "{host} saytını izləmək üçün bu ünvan yazılıb. Təsdiqləmək üçün linkə basın:\n\n{link}\n\nSiz yazılmamısınızsa, bu məktuba məhəl qoymayın.",
           "alert_subject": "SaytYoxla: {host} saytında dəyişiklik", "new_hosts": "Yeni subdomenlər: {items}", "new_problems": "Yeni problem sayı: {count}", "solved": "Həll olunan problem sayı: {count}",
           "cert": "Sertifikatın bitməsinə {days} gün qalıb.", "see": "Ətraflı: {link}", "stop": "İzləməni dayandırmaq: {link}",
           "confirmed": "İzləmə başladı. Dəyişiklik olanda məktub alacaqsınız.", "stopped": "İzləmə dayandırıldı. Ünvanınız silindi.", "bad_link": "Bu linkin vaxtı bitib və ya link düzgün deyil."},
    "en": {"confirm_subject": "SaytYoxla: confirm watching {host}", "confirm_body": "This address was entered to watch {host}. Open the link to confirm:\n\n{link}\n\nIf this was not you, ignore this message.",
           "alert_subject": "SaytYoxla: something changed on {host}", "new_hosts": "New subdomains: {items}", "new_problems": "New problems: {count}", "solved": "Problems solved: {count}",
           "cert": "The certificate expires in {days} days.", "see": "Details: {link}", "stop": "Stop watching: {link}",
           "confirmed": "Watching has started. You will get a message when something changes.", "stopped": "Watching has stopped. Your address was deleted.", "bad_link": "This link has expired or is not valid."},
    "ru": {"confirm_subject": "SaytYoxla: подтвердите наблюдение за {host}", "confirm_body": "Этот адрес указан для наблюдения за {host}. Для подтверждения откройте ссылку:\n\n{link}\n\nЕсли это были не вы, не обращайте внимания на письмо.",
           "alert_subject": "SaytYoxla: изменения на {host}", "new_hosts": "Новые поддомены: {items}", "new_problems": "Новых проблем: {count}", "solved": "Решено проблем: {count}",
           "cert": "До окончания сертификата осталось дней: {days}.", "see": "Подробнее: {link}", "stop": "Остановить наблюдение: {link}",
           "confirmed": "Наблюдение началось. При изменениях вы получите письмо.", "stopped": "Наблюдение остановлено. Ваш адрес удалён.", "bad_link": "Срок действия ссылки истёк, или она неверна."},
}


def words(lang: str) -> dict:
    return WORDS.get(lang, WORDS["az"])


def _redis_env():
    url = os.getenv("UPSTASH_REDIS_REST_URL") or os.getenv("KV_REST_API_URL")
    token = os.getenv("UPSTASH_REDIS_REST_TOKEN") or os.getenv("KV_REST_API_TOKEN")
    return (url, token) if url and token else None


def enabled() -> bool:
    return bool(_redis_env() and os.getenv("BREVO_API_KEY") and os.getenv("MONITOR_FROM") and os.getenv("MONITOR_SECRET") and os.getenv("CRON_SECRET"))


def _redis(*commands) -> list:
    from web.ratelimit import clean_token, clean_url
    url, token = _redis_env()
    r = requests.post(clean_url(url) + "/pipeline", headers={"Authorization": f"Bearer {clean_token(token)}"}, json=list(commands), timeout=5)
    r.raise_for_status()
    return [part.get("result") for part in r.json()]


def sign(action: str, host: str, email: str, lang: str, life: int = LINK_LIFE) -> str:
    body = json.dumps([action, host, email, lang, int(time.time()) + life], separators=(",", ":")).encode()
    mac = hmac.new(os.environ["MONITOR_SECRET"].encode(), body, hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(mac + body).decode().rstrip("=")


def read_token(token: str, action: str) -> tuple | None:
    secret = os.getenv("MONITOR_SECRET")
    if not secret or len(token) > 800:
        return None
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        mac, body = raw[:16], raw[16:]
        if not hmac.compare_digest(mac, hmac.new(secret.encode(), body, hashlib.sha256).digest()[:16]):
            return None
        kind, host, email, lang, until = json.loads(body)
    except (ValueError, TypeError):
        return None
    return (host, email, lang) if kind == action and until >= time.time() else None


def send_mail(to: str, subject: str, text: str) -> bool:
    try:
        r = requests.post("https://api.brevo.com/v3/smtp/email", timeout=8, headers={"api-key": os.environ["BREVO_API_KEY"]},
                          json={"sender": {"email": os.environ["MONITOR_FROM"], "name": "SaytYoxla"}, "to": [{"email": to}], "subject": subject, "textContent": text})
    except requests.RequestException:
        return False
    return r.status_code < 300


def _id(host: str, email: str) -> str:
    return hashlib.sha256(f"{host}|{email.lower()}".encode()).hexdigest()[:24]


def subscribe(raw: str, email: str, lang: str, site: str) -> str:
    """Sends the confirmation. Returns "" or the reason it was refused, in the wording of scanner/i18n.py."""
    host = deep._host(raw)
    if not EMAIL.match(email):
        return "E-poçt ünvanı düzgün deyil."
    if not deep.is_owner(host):
        return "Əvvəlcə saytın sizə aid olduğunu təsdiqləyin."
    link = f"{site}/monitor/confirm?t={sign('confirm', host, email, lang)}"
    w = words(lang)
    if not send_mail(email, w["confirm_subject"].format(host=host), w["confirm_body"].format(host=host, link=link)):
        return "Məktub göndərilə bilmədi. Bir az sonra yenidən cəhd edin."
    return ""


def confirm(token: str) -> str | None:
    found = read_token(token, "confirm")
    if not found:
        return None
    host, email, lang = found
    sub = _id(host, email)
    _redis(["SET", f"{KEY}:sub:{sub}", json.dumps({"host": host, "email": email, "lang": lang, "last": 0, "seen": None})], ["SADD", f"{KEY}:all", sub])
    return lang


def stop(token: str) -> str | None:
    found = read_token(token, "stop")
    if not found:
        return None
    host, email, lang = found
    sub = _id(host, email)
    _redis(["DEL", f"{KEY}:sub:{sub}"], ["SREM", f"{KEY}:all", sub])
    return lang


def snapshot(host: str) -> dict | None:
    """What is worth comparing. None if any part failed: a part that did not answer must not read as "solved"."""
    hosts, problems, days = [], [], None
    for module in MODULES:
        try:
            result = deep.MODULES[module](host)
        except (requests.RequestException, deep.UnsafeTarget, OSError, ValueError, KeyError):
            return None
        ids = {i["id"] for i in result["items"]}
        if ids & {"surface_unavailable", "dns_unavailable", "rep_unknown", "https_unavailable"}:
            return None
        problems += [f"{i['id']}|{json.dumps(i['params'], sort_keys=True)}" for i in result["items"] if i["status"] in ("fail", "warn")]
        if module == "surface":
            hosts = sorted(h["host"] for h in result["data"]["hosts"])
        if module == "tls":
            days = result["data"].get("cert", {}).get("days_left")
    return {"hosts": hosts, "problems": sorted(set(problems)), "days": days}


def changes(old: dict | None, now: dict) -> dict:
    """Nothing is new on the first look, or everything would be."""
    days = now.get("days")
    # Once when it crosses the line, not every day after
    near = days is not None and days <= CERT_WARN and not (old and old.get("days") is not None and old["days"] <= CERT_WARN)
    if not old:
        return {"hosts": [], "new": 0, "solved": 0, "cert": days if near else None}
    return {"hosts": [h for h in now["hosts"] if h not in old["hosts"]], "new": len([p for p in now["problems"] if p not in old["problems"]]),
            "solved": len([p for p in old["problems"] if p not in now["problems"]]), "cert": days if near else None}


def alert_text(host: str, email: str, lang: str, diff: dict, site: str) -> str:
    w = words(lang)
    lines = []
    if diff["hosts"]:
        lines.append(w["new_hosts"].format(items=", ".join(diff["hosts"][:20])))
    if diff["new"]:
        lines.append(w["new_problems"].format(count=diff["new"]))
    if diff["solved"]:
        lines.append(w["solved"].format(count=diff["solved"]))
    if diff["cert"] is not None:
        lines.append(w["cert"].format(days=diff["cert"]))
    lines += ["", w["see"].format(link=f"{site}/aletler/?tool=deep&url={host}"), w["stop"].format(link=f"{site}/monitor/stop?t={sign('stop', host, email, lang, 10 * 365 * 86400)}")]
    return "\n".join(lines)


def run(site: str, now: float | None = None) -> dict:
    """One timer tick: the sites longest unchecked, a few at a time."""
    now = time.time() if now is None else now
    ids = _redis(["SMEMBERS", f"{KEY}:all"])[0] or []
    if not ids:
        return {"checked": 0, "sent": 0}
    raw = _redis(*[["GET", f"{KEY}:sub:{sub}"] for sub in ids])
    subs = [(sub, json.loads(value)) for sub, value in zip(ids, raw, strict=True) if value]
    due = sorted((s for s in subs if now - s[1]["last"] >= CHECK_EVERY), key=lambda s: s[1]["last"])[:PER_RUN]
    checked = sent = 0
    for sub, record in due:
        seen = snapshot(record["host"])
        record["last"] = now
        if seen is not None:
            checked += 1
            diff = changes(record["seen"], seen)
            if diff["hosts"] or diff["new"] or diff["solved"] or diff["cert"] is not None:
                w = words(record["lang"])
                sent += send_mail(record["email"], w["alert_subject"].format(host=record["host"]), alert_text(record["host"], record["email"], record["lang"], diff, site))
            record["seen"] = seen
        _redis(["SET", f"{KEY}:sub:{sub}", json.dumps(record)])
    return {"checked": checked, "sent": sent}
