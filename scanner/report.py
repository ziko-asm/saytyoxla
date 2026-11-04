"""Turn findings into a score, a grade and a one-line summary."""

from __future__ import annotations

from datetime import datetime, timezone

from scanner.models import FAIL, WARN, Context, Finding, Report

GRADES = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]
# The protections every site can turn on for free. Missing several of them rules out a top grade,
# however many unrelated checks (title, page size, ...) pass.
CORE_PROTECTIONS = ("http_redirect", "hsts", "framing", "nosniff", "csp")


def score(findings: list[Finding]) -> int:
    total = sum(f.weight for f in findings if f.weight)
    lost = sum(f.penalty for f in findings)
    return max(0, round(100 * (1 - lost / total))) if total else 0


def score_cap(findings: list[Finding]) -> tuple[int, str]:
    """The highest score these findings allow, and the reason shown to the user."""
    status = {f.id: f.status for f in findings}
    if status.get("https") == FAIL:
        return 39, "Sayt etibarlı HTTPS ilə açılmadığı üçün bal 39-dan yuxarı ola bilməz."
    if status.get("cert") == FAIL:
        return 59, "Sertifikatın vaxtı bitmək üzrə olduğu üçün bal 59-dan yuxarı ola bilməz."
    missing = sum(status.get(p) == WARN for p in CORE_PROTECTIONS)
    if missing >= 4:
        return 74, f"{missing} əsas qoruma ayarı çatışmadığı üçün bal 74-dən yuxarı ola bilməz."
    if missing >= 2:
        return 89, f"{missing} əsas qoruma ayarı çatışmadığı üçün bal 89-dan yuxarı ola bilməz."
    return 100, ""


def grade(s: int) -> str:
    return next(g for limit, g in GRADES if s >= limit)


def summary(findings: list[Finding]) -> str:
    fails = sum(f.status == FAIL for f in findings)
    warns = sum(f.status == WARN for f in findings)
    if not fails and not warns:
        return "Əla nəticə: ciddi problem tapılmadı."
    parts = []
    if fails:
        parts.append(f"{fails} ciddi problem")
    if warns:
        parts.append(f"{warns} təkmilləşdirmə tövsiyəsi")
    return " və ".join(parts) + " tapıldı."


def build(ctx: Context, findings: list[Finding]) -> Report:
    order = {FAIL: 0, WARN: 1}
    findings = sorted(findings, key=lambda f: (order.get(f.status, 2), -f.weight))
    points = score(findings)
    cap, note = score_cap(findings)
    s = min(points, cap)
    return Report(url=ctx.input_url, final_url=ctx.final_url or ctx.input_url, score=s, grade=grade(s),
                  summary=summary(findings), findings=findings,
                  scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  score_note=note if points > cap else "")
