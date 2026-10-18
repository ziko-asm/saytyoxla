"""Data types shared by the scanner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"


@dataclass
class Finding:
    id: str
    category: str          # "Təhlükəsizlik", "E-poçt", "Sürət", "Mobil və Google"
    title: str             # short label shown in the report
    status: str            # ok | warn | fail | info
    detail: str            # what we saw, in plain Azerbaijani
    fix: str = ""          # what to do about it (empty when status is ok)
    weight: int = 0        # points lost when the check fails (half when it warns)

    @property
    def penalty(self) -> float:
        return {FAIL: self.weight, WARN: self.weight / 2}.get(self.status, 0)


@dataclass
class Context:
    """Everything fetched once from the site; checks only read it."""
    input_url: str
    final_url: str = ""
    host: str = ""
    status_code: int | None = None
    headers: dict = field(default_factory=dict)     # lower-cased keys
    html: str = ""
    elapsed_ms: float | None = None
    html_bytes: int = 0
    redirect_chain: list = field(default_factory=list)
    http_to_https: bool | None = None               # does http:// end on https://?
    cert: dict | None = None                        # {"days_left", "issuer", "error"}
    txt_records: dict = field(default_factory=dict)  # {"spf": [...], "dmarc": [...]} or None on error
    error: str | None = None


@dataclass
class Report:
    url: str
    final_url: str
    score: int
    grade: str
    summary: str
    findings: list
    scanned_at: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["counts"] = {s: sum(f["status"] == s for f in d["findings"]) for s in (FAIL, WARN, OK)}
        return d
