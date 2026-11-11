"""
Scan a private list of websites and write the aggregate numbers the survey page shows (web/survey_stats.json).

    python scripts/survey.py sites.txt                    # scan through the live service, write web/survey_stats.json
    python scripts/survey.py sites.txt --out /tmp/s.json  # write somewhere else (a trial run)
    python scripts/survey.py sites.txt --local            # scan from this machine instead (needs working DNS for TXT)
    python scripts/survey.py sites.txt --keep run.json    # remember each result privately; run again to resume

sites.txt is one site per line, "<sector> <address>", with the sector keys of web/survey.py (bank, uni, gov, news,
shop, tel, health). Empty lines and lines starting with # are skipped. The list and the per-site results are
private: this script prints and stores only counts, and *.sites.txt / survey_sites* are in .gitignore.

Scanning goes through the public API by default, so the numbers are what a visitor of the site would get, and at
its pace (a few scans a minute), so the service's own limits are respected.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from web.survey import CHECKS, SECTORS

API = "https://saytyoxla.vercel.app/api/scan"
# How a refusal is counted, by a word of the Azerbaijani message the scanner gives (scanner/__init__.py, scanner/safety.py)
REASONS = (("tapılmadı", "not_in_dns"), ("bloklayır", "blocked"), ("SSL", "tls"))


def read_sites(text: str) -> list[tuple[str, str]]:
    sites = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.split("#")[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2 or parts[0] not in SECTORS:
            raise SystemExit(f"line {n}: expected '<sector> <address>' with a sector of {', '.join(SECTORS)}")
        sites.append((parts[0], parts[1]))
    return sites


def reason_of(message: str) -> str:
    return next((kind for word, kind in REASONS if word in message), "unreachable")


def scan_api(address: str, api: str, session: requests.Session, wait: float = 65, tries: int = 4) -> dict | str:
    """The report, or why there is none ("not_in_dns", "blocked", "tls", "unreachable")."""
    for _ in range(tries):
        try:
            r = session.post(api, json={"url": address, "lang": "az", "fresh": True}, timeout=60)
        except requests.RequestException:
            return "unreachable"
        if r.status_code == 429:            # the service's own limit: wait for the next minute
            time.sleep(wait)
            continue
        if r.status_code == 200:
            return r.json()
        try:
            return reason_of(str(r.json().get("detail", "")))
        except ValueError:
            return "unreachable"
    raise SystemExit("The service kept answering 429: try later or with a lower --per-minute.")


def scan_local(address: str) -> dict | str:
    import scanner
    try:
        return scanner.scan(address).to_dict()
    except scanner.UnsafeTarget as e:
        return reason_of(str(e))


def pct(part: int, whole: int) -> int:
    return round(100 * part / whole) if whole else 0


def summarise(reports: list[dict]) -> dict:
    """The numbers for one group of sites. A check that could not be made for a site (status "info") is left out
    of that check's percentage, so "not measured" never reads as "failed"."""
    status = [{f["id"]: f["status"] for f in r["findings"]} for r in reports]
    scores = [r["score"] for r in reports]
    grades: dict[str, int] = {}
    for r in reports:
        grades[r["grade"]] = grades.get(r["grade"], 0) + 1
    passed = {}
    for check in CHECKS:
        judged = [s[check] for s in status if s.get(check) in ("ok", "warn", "fail")]
        if any(check in s for s in status):         # a check the scanner did not have yet gets no row at all
            passed[check] = pct(judged.count("ok"), len(judged))
    n = len(reports)
    share = lambda check, *bad: pct(sum(s.get(check) in bad for s in status), n)
    return {"n": n, "avg": round(statistics.mean(scores)), "median": round(statistics.median(scores)), "grades": grades,
            "pass": passed, "dmarc_missing": share("dmarc", "fail"), "dmarc_none": share("dmarc", "warn"),
            "spf_missing": share("spf", "fail"), "version_leak": share("disclosure", "warn", "fail"),
            "cert_soon": share("cert", "warn", "fail"),
            "avg_fails": round(statistics.mean(sum(v == "fail" for v in s.values()) for s in status), 1)}


def build(results: list[tuple[str, dict | str]], date: str) -> dict:
    """results: (sector, report or reason). Returns what web/survey_stats.json holds."""
    skipped: dict[str, int] = {}
    for _, got in results:
        if isinstance(got, str):
            skipped[got] = skipped.get(got, 0) + 1
            if got == "tls":                # a site that failed on TLS did not open either
                skipped["unreachable"] = skipped.get("unreachable", 0) + 1
    good = [(sector, got) for sector, got in results if isinstance(got, dict)]
    if not good:
        raise SystemExit("No site could be analysed.")
    sizes: dict[str, int] = {}
    for sector, _ in results:
        sizes[sector] = sizes.get(sector, 0) + 1
    return {"scanned": len(results) - skipped.get("not_in_dns", 0), "analysed": len(good), "skipped": skipped, "dates": [date],
            "all": summarise([r for _, r in good]),
            "sectors": {s: summarise([r for sec, r in good if sec == s]) for s in SECTORS if any(sec == s for sec, _ in good)},
            "sector_sizes": sizes}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("sites", type=Path)
    ap.add_argument("--out", type=Path, default=ROOT / "web" / "survey_stats.json")
    ap.add_argument("--api", default=API)
    ap.add_argument("--local", action="store_true", help="scan from this machine instead of through the service")
    ap.add_argument("--keep", type=Path, help="private file for per-site results, so an interrupted run can resume; keep it out of the repository")
    ap.add_argument("--per-minute", type=float, default=5, help="scans a minute through the service (its limit is 6)")
    args = ap.parse_args()

    sites = read_sites(args.sites.read_text(encoding="utf-8"))
    session = requests.Session()
    kept = json.loads(args.keep.read_text(encoding="utf-8")) if args.keep and args.keep.exists() else {}
    results = []
    for i, (sector, address) in enumerate(sites, 1):
        started = time.monotonic()
        if address in kept:                 # a run that was cut short goes on where it stopped
            results.append((sector, kept[address]))
            continue
        got = scan_local(address) if args.local else scan_api(address, args.api, session)
        results.append((sector, got))
        if args.keep:
            kept[address] = got
            args.keep.write_text(json.dumps(kept, ensure_ascii=False), encoding="utf-8")
        # progress without names: the list is private, and terminal output gets pasted around
        print(f"{i}/{len(sites)} {sector}: {got if isinstance(got, str) else got['score']}", flush=True)
        if not args.local and i < len(sites):
            time.sleep(max(0.0, 60 / args.per_minute - (time.monotonic() - started)))
    stats = build(results, datetime.now(timezone.utc).date().isoformat())
    args.out.write_text(json.dumps(stats, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"{stats['analysed']} of {len(sites)} analysed, average {stats['all']['avg']}; written to {args.out}")


if __name__ == "__main__":
    main()
