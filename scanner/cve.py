"""
Known weaknesses for software a site shows: server versions from NVD, WordPress plugins from wordpress.org and, with a
key, WPScan. A database match says a version is affected in general; Linux distributions often fix an old version
without changing its number, so the report calls it possible, never certain.
"""

from __future__ import annotations

import os
import re
import threading

import requests

from scanner.fetch import USER_AGENT

HEADERS = {"User-Agent": USER_AGENT}
TIMEOUT = 10
# name a server sends -> its product in NVD
CPE = {
    "nginx": "f5:nginx", "apache": "apache:http_server", "php": "php:php", "wordpress": "wordpress:wordpress",
    "openresty": "openresty:openresty", "litespeed": "litespeedtech:litespeed_web_server",
    "microsoft-iis": "microsoft:internet_information_services",
}
_memory: dict = {}          # one lookup per version per instance: NVD allows few requests without a key
_lock = threading.Lock()


def _remember(key: str, make):
    with _lock:
        if key in _memory:
            return _memory[key]
    value = make()
    if value is not None:
        with _lock:
            if len(_memory) > 500:
                _memory.clear()
            _memory[key] = value
    return value


def _score(cve: dict) -> float:
    metrics = cve.get("metrics", {})
    for name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(name, []):
            return float(metric.get("cvssData", {}).get("baseScore", 0))
    return 0.0


def server_cves(name: str, version: str) -> dict | None:
    """{count, high, ids} for a product and version; None if it is unknown to us or NVD did not answer."""
    product = CPE.get(name.lower())
    if not product or version.count(".") < 1:
        return None         # "PHP 7" names no release, and a match on it would be invented

    def lookup():
        headers = dict(HEADERS)
        if os.getenv("NVD_API_KEY"):
            headers["apiKey"] = os.environ["NVD_API_KEY"]
        try:
            r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", headers=headers, timeout=TIMEOUT,
                             params={"virtualMatchString": f"cpe:2.3:a:{product}:{version}", "resultsPerPage": 200})
            if r.status_code != 200:
                return None
            found = [(v["cve"]["id"], _score(v["cve"])) for v in r.json().get("vulnerabilities", [])]
        except (requests.RequestException, ValueError, KeyError):
            return None
        found.sort(key=lambda x: -x[1])
        return {"count": len(found), "high": sum(score >= 7 for _, score in found), "ids": [cve for cve, _ in found[:5]]}

    return _remember(f"nvd:{product}:{version}", lookup)


PLUGIN = re.compile(r"""/wp-content/plugins/([a-z0-9][a-z0-9_-]{1,60})/[^"'\s>]*""", re.IGNORECASE)
THEME = re.compile(r"""/wp-content/themes/([a-z0-9][a-z0-9_-]{1,60})/""", re.IGNORECASE)


def detect_plugins(html: str) -> dict:
    """{slug: version or ""}. The ?ver= of a file is usually the plugin's version, but some sites send WordPress's own."""
    plugins: dict = {}
    for match in PLUGIN.finditer(html):
        slug = match.group(1).lower()
        version = re.search(r"[?&]ver=(\d+(?:\.\d+)+)", match.group(0))
        if version or slug not in plugins:
            plugins[slug] = version.group(1) if version else plugins.get(slug, "")
    return dict(list(plugins.items())[:12])


def detect_theme(html: str) -> str:
    match = THEME.search(html)
    return match.group(1).lower() if match else ""


def latest_wordpress() -> str | None:
    def lookup():
        try:
            r = requests.get("https://api.wordpress.org/core/version-check/1.7/", headers=HEADERS, timeout=6)
            return r.json()["offers"][0]["version"] if r.status_code == 200 else None
        except (requests.RequestException, ValueError, KeyError, IndexError):
            return None
    return _remember("wp:core", lookup)


def plugin_info(slug: str) -> dict | None:
    """Directory data; {} if the directory does not list it (a paid plugin, or one removed); None if it did not answer."""
    def lookup():
        try:
            r = requests.get("https://api.wordpress.org/plugins/info/1.2/", headers=HEADERS, timeout=6,
                             params={"action": "plugin_information", "request[slug]": slug, "request[fields][sections]": 0})
            if r.status_code == 404:
                return {}
            if r.status_code != 200:
                return None
            data = r.json()
        except (requests.RequestException, ValueError):
            return None
        return {"latest": data.get("version", ""), "updated": str(data.get("last_updated", ""))[:10], "closed": bool(data.get("closed"))}
    return _remember(f"wp:plugin:{slug}", lookup)


def version_key(version: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", version)[:4])


def plugin_vulns(slug: str, version: str) -> dict | None:
    """Known weaknesses from WPScan, which needs a key. None without one, or if it did not answer."""
    key = os.getenv("WPSCAN_API_KEY")
    if not key or not version:
        return None

    def lookup():
        try:
            r = requests.get(f"https://wpscan.com/api/v3/plugins/{slug}", timeout=TIMEOUT,
                             headers={**HEADERS, "Authorization": f"Token token={key}"})
            if r.status_code == 404:
                return []
            return r.json().get(slug, {}).get("vulnerabilities", []) if r.status_code == 200 else None
        except (requests.RequestException, ValueError, AttributeError):
            return None

    vulns = _remember(f"wpscan:{slug}", lookup)
    if vulns is None:
        return None
    # No "fixed in" means no known fix, so it applies to this version too
    open_ones = [v for v in vulns if not v.get("fixed_in") or version_key(version) < version_key(v["fixed_in"])]
    return {"count": len(open_ones), "ids": [(v.get("references", {}).get("cve") or [""])[0] or str(v.get("id", ""))[:12] for v in open_ones[:3]]}
