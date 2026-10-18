"""SaytYoxla: passive website health and security check for small businesses."""

from scanner.checks import run_checks
from scanner.fetch import collect
from scanner.report import build
from scanner.safety import UnsafeTarget, check_host_is_public, normalize

__all__ = ["UnsafeTarget", "scan"]


def scan(raw_url: str):
    """Validate the address, collect public data once, run every check."""
    url = normalize(raw_url)
    check_host_is_public(url.split("/")[2])
    ctx = collect(url)
    if ctx.error:
        raise UnsafeTarget("Sayt açılmadı (" + ctx.error + "). Ünvanı yoxlayın və bir az sonra yenidən cəhd edin.")
    if ctx.status_code and ctx.status_code >= 400:
        raise UnsafeTarget(f"Sayt xəta qaytardı (kod {ctx.status_code}). Ünvanı yoxlayın.")
    return build(ctx, run_checks(ctx))
