"""
Safe, non-destructive checks for injection and reflected XSS on a site whose owner has been verified.

Every probe is a plain GET with a changed query value. Nothing is ever POSTed, so no form is submitted, no row
is written and no state changes. The payloads only read:

  SQL injection   a lone quote to look for a database error, and "AND 1=1" / "AND 1=2" to compare two SELECTs.
                  Never a stacked query, UNION, DROP, DELETE, UPDATE, INSERT or a time delay.
  Reflected XSS   a harmless marker such as <sytx1a2b3c>, to see whether < > " come back unescaped.
                  Never a working script or event handler: the marker cannot execute.

A hit means the input is probably mishandled; it is reported as "possible" and the owner is asked to confirm.
This module is reached only through scanner.deep after is_owner() passes.
"""

from __future__ import annotations

import difflib
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# Signatures a database prints when a quote breaks a query. Seeing one appear only after the quote is the signal.
SQL_ERRORS = re.compile(
    rb"SQL syntax|SQLSTATE|mysql_fetch|mysqli?_|num_rows|ORA-\d{5}|PLS-\d{5}|PostgreSQL.{0,40}ERROR|pg_query|"
    rb"SQLite3?::|SQLiteException|Unclosed quotation mark|quoted string not properly terminated|"
    rb"valid MySQL result|ODBC.{0,40}Driver|OLE DB|Microsoft JET|Incorrect syntax near|"
    rb"supplied argument is not a valid|Column count doesn.t match|Conversion failed when converting",
    re.IGNORECASE,
)
BASE_VALUE = "1"
MAX_PARAMS = 14
PER_PARAM_BUDGET = 6


def set_param(url: str, name: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, value if k == name else v) for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    if name not in dict(query):
        query.append((name, value))
    return urlunsplit(parts._replace(query=urlencode(query, doseq=True)))


def _normalise(body: bytes) -> bytes:
    """Drop digits and runs of space so that a counter, date or CSRF token does not look like a real difference."""
    return re.sub(rb"\s+", b" ", re.sub(rb"\d+", b"", body))[:40000]


def _ratio(a: bytes, b: bytes) -> float:
    return difflib.SequenceMatcher(None, a, b).quick_ratio()


def error_based_sqli(baseline: bytes, one_quote: bytes, two_quotes: bytes) -> bool:
    """A lone quote raises a DB error, a balanced pair does not: the quote reached the query unescaped."""
    appeared = bool(SQL_ERRORS.search(one_quote)) and not SQL_ERRORS.search(baseline)
    return appeared and not SQL_ERRORS.search(two_quotes)


def boolean_based_sqli(status: dict, body: dict) -> bool:
    """A condition that is always true looks like the normal page, one that is always false looks different."""
    for true_key, false_key in (("str_true", "str_false"), ("num_true", "num_false")):
        if true_key not in body or false_key not in body:
            continue
        base = _normalise(body["base"])
        same = _ratio(base, _normalise(body[true_key]))
        differ = _ratio(base, _normalise(body[false_key]))
        if status.get(true_key) == status.get("base") and same > 0.97 and same - differ > 0.08:
            return True
    return False


def xss_marker() -> str:
    return "sytx" + secrets.token_hex(3)


def reflected_xss(marker: str, body: bytes) -> bool:
    """The angle-bracket marker comes back exactly as sent, so the page did not escape < and >."""
    return f"<{marker}>".encode() in body


# ---------------------------------------------------------------- orchestration
def probe_param(url: str, name: str, send) -> dict:
    """send(url) -> (status_code, body) or None. Returns {"sqli": "error"|"boolean"|"", "xss": bool}."""
    base_value = next((v for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True) if k == name and v), BASE_VALUE)
    marker = xss_marker()
    tries = {
        "base": base_value,
        "quote1": base_value + "'",
        "quote2": base_value + "''",
        "str_true": base_value + "' AND '1'='1",
        "str_false": base_value + "' AND '1'='2",
        "num_true": base_value + " AND 1=1",
        "num_false": base_value + " AND 1=2",
        "xss": f"{base_value}<{marker}>",
    }
    status, body = {}, {}
    for key, value in tries.items():
        answer = send(set_param(url, name, value))
        if answer is None:
            return {"sqli": "", "xss": False}       # the site stopped answering: say nothing about this input
        status[key], body[key] = answer

    result = {"sqli": "", "xss": False}
    if error_based_sqli(body["base"], body["quote1"], body["quote2"]):
        result["sqli"] = "error"
    elif boolean_based_sqli(status, body):
        result["sqli"] = "boolean"
    if reflected_xss(marker, body["xss"]):
        result["xss"] = True
    return result


def collect_targets(links: list, forms: list) -> list:
    """(url, param) pairs worth testing: query parameters on links, and the fields of GET forms.
    Only GET targets, so a test is a read, never a submission that could create or change data."""
    targets: list = []
    seen = set()
    for url in links:
        for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            key = (urlsplit(url).path, name)
            if key not in seen:
                seen.add(key)
                targets.append((url, name))
    for action, names in forms:
        for name in names:
            key = (urlsplit(action).path, name)
            if key not in seen:
                seen.add(key)
                targets.append((set_param(action, name, BASE_VALUE), name))
    return targets[:MAX_PARAMS]
