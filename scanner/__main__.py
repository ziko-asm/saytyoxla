"""
    python -m scanner example.az
    python -m scanner example.az --json
"""

import argparse
import json
import sys

from scanner import UnsafeTarget, scan

ICON = {"fail": "[X]", "warn": "[!]", "ok": "[+]", "info": "[i]"}


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to a code page without "ə"
    p = argparse.ArgumentParser(description="SaytYoxla: sayt sağlamlığı yoxlaması")
    p.add_argument("url")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    try:
        report = scan(a.url)
    except UnsafeTarget as e:
        print(e)
        sys.exit(1)
    if a.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=1))
        return
    print(f"\n{report.final_url}\nBal: {report.score}/100  Qiymət: {report.grade}\n{report.summary}\n")
    for f in report.findings:
        print(f"{ICON[f.status]} {f.category} | {f.title}: {f.detail}")
        if f.fix:
            print(f"     Necə düzəltmək: {f.fix}")


if __name__ == "__main__":
    main()
