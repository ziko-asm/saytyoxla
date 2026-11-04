"""SaytYoxla: passive website health and security check for small businesses."""

from scanner.checks import run_checks
from scanner.fetch import collect
from scanner.report import build
from scanner.safety import UnsafeTarget, check_host_is_public, normalize

__all__ = ["UnsafeTarget", "scan"]


def status_message(code: int) -> str:
    """Explain an error status in plain Azerbaijani; 'check the address' is wrong advice for most of them."""
    if code in (401, 403, 429) or code == 503:
        return (f"Sayt avtomatik yoxlamaları bloklayır (kod {code}). Bu, adətən bot qorumasıdır "
                "(məsələn, Cloudflare): sayt brauzerdə açılır, amma alətlərə cavab vermir. "
                "Böyük platformalar (lalafo, tap.az, Instagram) belə edir; biznesin öz saytını yoxlayın.")
    if code == 404:
        return "Bu səhifə tapılmadı (kod 404). Ünvanın yazılışını yoxlayın və ya yalnız domeni yazın, məsələn: example.az"
    if code >= 500:
        return f"Saytın serverində xəta var (kod {code}). Bir az sonra yenidən cəhd edin."
    return f"Sayt xəta qaytardı (kod {code}). Ünvanı yoxlayın."


def error_message(error: str) -> str:
    """Explain why a site did not open, without showing the name of a Python exception."""
    if error == "SSLError":
        return ("Sayt açılmadı: təhlükəsiz bağlantı (SSL) qurula bilmədi. "
                "Hostinq panelində SSL ayarlarını yoxlayın.")
    if "Timeout" in error:
        return "Sayt açılmadı: server vaxtında cavab vermədi. Bir az sonra yenidən cəhd edin."
    return "Sayt açılmadı: serverə qoşulmaq mümkün olmadı. Ünvanı yoxlayın və bir az sonra yenidən cəhd edin."


def scan(raw_url: str):
    """Validate the address, collect public data once, run every check."""
    url = normalize(raw_url)
    check_host_is_public(url.split("/")[2])
    ctx = collect(url)
    if ctx.error:
        raise UnsafeTarget(error_message(ctx.error))
    if ctx.status_code and ctx.status_code >= 400:
        raise UnsafeTarget(status_message(ctx.status_code))
    return build(ctx, run_checks(ctx))
