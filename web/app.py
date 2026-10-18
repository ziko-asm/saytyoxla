"""
SaytYoxla web service.

    uvicorn web.app:app --reload          # http://127.0.0.1:8000

GET  /            the Azerbaijani front page (web/static/index.html)
POST /api/scan    {"url": "example.az"} -> report JSON
GET  /health      for the hosting platform
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import scanner
from scanner.safety import UnsafeTarget, normalize

STATIC = Path(__file__).parent / "static"
RATE_LIMIT = int(os.getenv("SCAN_RATE_LIMIT", "6"))      # scans per IP ...
RATE_WINDOW = 60                                        # ... per minute
CACHE_SECONDS = 600

app = FastAPI(title="SaytYoxla", version="0.2.0", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")

_hits: dict[str, deque] = defaultdict(deque)
_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()


class ScanRequest(BaseModel):
    url: str = Field(..., max_length=300)


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() or (request.client.host if request.client else "unknown")


def allow(ip: str, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    with _lock:
        q = _hits[ip]
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return False
        q.append(now)
        return True


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'; object-src 'none'")
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scan")
def scan(req: ScanRequest, request: Request):
    try:
        key = normalize(req.url)
    except UnsafeTarget as e:
        raise HTTPException(400, str(e)) from None

    hit = _cache.get(key)
    if hit and time.time() - hit[0] < CACHE_SECONDS:
        return JSONResponse(hit[1])

    if not allow(client_ip(request)):
        raise HTTPException(429, "Çox sayda yoxlama etdiniz. Bir dəqiqə gözləyib yenidən cəhd edin.")
    try:
        report = scanner.scan(req.url).to_dict()
    except UnsafeTarget as e:
        raise HTTPException(400, str(e)) from None
    _cache[key] = (time.time(), report)
    return JSONResponse(report)
