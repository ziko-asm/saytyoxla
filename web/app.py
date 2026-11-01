"""
SaytYoxla web service.

    uvicorn web.app:app --reload          # http://127.0.0.1:8000

GET  /            the Azerbaijani front page (web/static/index.html)
POST /api/scan    {"url": "example.az"} -> report JSON
GET  /health      for the hosting platform
GET  /robots.txt, /sitemap.xml, /llms.txt   for search engines and AI crawlers (web/seo.py)
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import scanner
from scanner.safety import UnsafeTarget, normalize
from web import seo

STATIC = Path(__file__).parent / "static"
REACT = Path(__file__).parent / "react"      # built by react-ui (npm run build)
RATE_LIMIT = int(os.getenv("SCAN_RATE_LIMIT", "6"))      # scans per IP ...
RATE_WINDOW = 60                                        # ... per minute
CACHE_SECONDS = 600

app = FastAPI(title="SaytYoxla", version="0.2.0", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
app.mount("/react", StaticFiles(directory=REACT), name="react")

# The scan form embedded on ayfar (the author's portfolio) calls /api/scan from the browser.
# Only those origins may; the per-IP rate limit still applies because the request comes from the visitor.
ALLOWED_ORIGINS = [o.strip() for o in os.getenv(
    "ALLOWED_ORIGINS", "https://ayfar.vercel.app,https://ayfar.az,https://www.ayfar.az").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["POST"],
                   allow_headers=["Content-Type"], max_age=86400)

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


@app.get("/beta", include_in_schema=False)
def beta():
    """The React front end, served side by side with the current page until it replaces it."""
    return FileResponse(REACT / "index.html")


@app.get("/robots.txt", include_in_schema=False)
def robots():
    return PlainTextResponse(seo.robots_txt())


@app.get("/sitemap.xml", include_in_schema=False)
def sitemap():
    return Response(seo.sitemap_xml(), media_type="application/xml")


@app.get("/llms.txt", include_in_schema=False)
def llms():
    return PlainTextResponse(seo.llms_txt())


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


# Keep this last: it matches any single path segment, so earlier routes win.
@app.get("/{filename}", include_in_schema=False)
def google_verify(filename: str):
    body = seo.google_verification(filename)
    if body is None:
        raise HTTPException(404, "Not Found")
    return PlainTextResponse(body)
