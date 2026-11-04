"""
SaytYoxla web service.

    uvicorn web.app:app --reload          # http://127.0.0.1:8000

GET  /            the Azerbaijani front page (React, built from react-ui/ into web/react/)
GET  /en/, /ru/   the same page in English and Russian
GET  /hesabat/, /en/report/, /ru/otchet/   survey of Azerbaijani websites (web/survey.py)
GET  /haqqimizda/, /mexfilik/, /sertler/ and their en/ru versions   about, privacy, terms (web/pages.py)
GET  /classic     the previous plain-JavaScript page (web/static/index.html)
GET  /aletler/, /en/tools/, /ru/instrumenty/   the Tools part of the site
POST /api/scan    {"url": "example.az", "lang": "az|en|ru"} -> report JSON
POST /api/tool    {"url": "example.az", "tool": "ssl|email", "lang": "az|en|ru"} -> one narrow check
POST /api/deep    {"url": "example.az", "module": "surface|mail|tech|tls|reputation|active"} -> one part of the deep analysis
POST /api/ownership  {"url": "example.az"} -> what to publish to prove the site is yours
GET  /health      for the hosting platform
GET  /robots.txt, /sitemap.xml, /llms.txt   for search engines and AI crawlers (web/seo.py)
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

import scanner
from scanner import deep as scanner_deep
from scanner import i18n
from scanner import tools as scanner_tools
from scanner.safety import UnsafeTarget, normalize
from web import pages, ratelimit, seo, survey

log = logging.getLogger("saytyoxla")
STATIC = Path(__file__).parent / "static"
REACT = Path(__file__).parent / "react"      # built by react-ui (npm run build)
CACHE_SECONDS = 600
CACHE_MAX = 500                              # finished reports kept per instance (oldest dropped first)

app = FastAPI(title="SaytYoxla", version="0.3.0", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")
app.mount("/react", StaticFiles(directory=REACT), name="react")

# The scan form embedded on ayfar (the author's portfolio) calls /api/scan from the browser.
# Only those origins may; the per-IP rate limit still applies because the request comes from the visitor.
ALLOWED_ORIGINS = [o.strip() for o in os.getenv(
    "ALLOWED_ORIGINS", "https://ayfar.vercel.app,https://ayfar.az,https://www.ayfar.az").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_methods=["POST"],
                   allow_headers=["Content-Type"], max_age=86400)


class HeadAsGet:
    """Answer HEAD like GET without the body. The page routes are GET-only, so HEAD got 405, which uptime
    monitors and link checkers read as a broken page."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "HEAD":
            return await self.app(scope, receive, send)

        async def no_body(message):
            if message["type"] == "http.response.body":
                message = {**message, "body": b""}
            await send(message)
        await self.app({**scope, "method": "GET"}, receive, no_body)


app.add_middleware(HeadAsGet)

limiter = ratelimit.Limiter.from_env()
_cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
_lock = threading.Lock()


class ScanRequest(BaseModel):
    url: str = Field(..., max_length=300)
    lang: str = Field("az", max_length=5)      # az | en | ru; anything else falls back to az
    fresh: bool = False                        # skip the 10-minute result cache (the rate limit still applies)


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, exc: RequestValidationError):
    """`detail` is always one sentence for the user: the pages show it as it is, and FastAPI's default
    (a list of objects) made React throw and blank the whole page."""
    body = exc.body if isinstance(exc.body, dict) else {}
    lang = body.get("lang") if isinstance(body.get("lang"), str) else None
    too_long = any(e["type"] == "string_too_long" and e["loc"][-1] == "url" for e in exc.errors())
    message = "Ünvan çox uzundur. Yalnız domeni yazın, məsələn: example.az" if too_long \
        else "Ünvan düzgün görünmür. Nümunə: example.az"
    return JSONResponse({"detail": i18n.text(message, i18n.lang_of(lang))}, status_code=422)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    """People who follow a wrong link get a page; the API and missing files keep their short answer."""
    path = request.url.path
    if exc.status_code == 404 and not path.startswith(("/api/", "/static/", "/react/")):
        return HTMLResponse(pages.not_found(path), status_code=404)
    return await http_exception_handler(request, exc)


def client_ip(request: Request) -> str:
    return ratelimit.client_ip(request.headers, request.client.host if request.client else None)


def cache_get(key: str) -> dict | None:
    with _lock:
        hit = _cache.get(key)
        if hit and time.time() - hit[0] < CACHE_SECONDS:
            return hit[1]
        _cache.pop(key, None)
        return None


def cache_put(key: str, report: dict) -> None:
    with _lock:
        _cache[key] = (time.time(), report)
        _cache.move_to_end(key)
        while len(_cache) > CACHE_MAX:
            _cache.popitem(last=False)


def cache_control(path: str, method: str) -> str | None:
    """Hashed React assets never change; other files and pages may be served from Vercel's edge for a
    while, so most visits never start the Python function. The scan API is never cached."""
    if path.startswith("/api/"):
        return "no-store"
    if method not in ("GET", "HEAD"):
        return None
    if path.startswith(("/react/assets/", "/static/fonts/")):     # content-hashed or versioned names
        return "public, max-age=31536000, s-maxage=31536000, immutable"
    if path.startswith("/static/"):
        return "public, max-age=86400, s-maxage=86400"
    return "public, max-age=0, s-maxage=300, stale-while-revalidate=86400"


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    cc = cache_control(request.url.path, request.method)
    if cc and response.status_code == 200 or cc == "no-store":
        response.headers["Cache-Control"] = cc
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'; object-src 'none'")
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


@app.get("/", include_in_schema=False)
def index():
    """The React front end (react-ui, built into web/react)."""
    return FileResponse(REACT / "index.html")


@app.get("/en/", include_in_schema=False)
@app.get("/ru/", include_in_schema=False)
def index_lang(request: Request):
    """English and Russian pages (react-ui/make_pages.py)."""
    return FileResponse(REACT / request.url.path.strip("/") / "index.html")


@app.get("/hesabat/", include_in_schema=False)
@app.get("/en/report/", include_in_schema=False)
@app.get("/ru/otchet/", include_in_schema=False)
def survey_page(request: Request):
    """Aggregate results of scanning Azerbaijani websites (no site names)."""
    if not survey.DATA.exists():          # not published yet
        raise HTTPException(404, "Not Found")
    lang = next(l for l, p in survey.PATHS.items() if p == request.url.path)
    return HTMLResponse(survey.page(lang))


@app.get("/aletler/", include_in_schema=False)
@app.get("/en/tools/", include_in_schema=False)
@app.get("/ru/instrumenty/", include_in_schema=False)
def tools_page(request: Request):
    """The Tools part of the site: the same React build, which picks the page by its address."""
    lang = next(l for l, p in pages.TOOLS_PATHS.items() if p == request.url.path)
    home = (REACT / pages.HOMES[lang].strip("/") / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(pages.tools_page(home, lang))


@app.get("/haqqimizda/", include_in_schema=False)
@app.get("/en/about/", include_in_schema=False)
@app.get("/ru/o-nas/", include_in_schema=False)
@app.get("/mexfilik/", include_in_schema=False)
@app.get("/en/privacy/", include_in_schema=False)
@app.get("/ru/konfidencialnost/", include_in_schema=False)
@app.get("/sertler/", include_in_schema=False)
@app.get("/en/terms/", include_in_schema=False)
@app.get("/ru/usloviya/", include_in_schema=False)
def info_page(request: Request):
    """About, privacy and terms (web/pages.py)."""
    return HTMLResponse(pages.page(*pages.ROUTES[request.url.path]))


@app.get("/aletler", include_in_schema=False)
@app.get("/en/tools", include_in_schema=False)
@app.get("/ru/instrumenty", include_in_schema=False)
@app.get("/haqqimizda", include_in_schema=False)
@app.get("/en/about", include_in_schema=False)
@app.get("/ru/o-nas", include_in_schema=False)
@app.get("/mexfilik", include_in_schema=False)
@app.get("/en/privacy", include_in_schema=False)
@app.get("/ru/konfidencialnost", include_in_schema=False)
@app.get("/sertler", include_in_schema=False)
@app.get("/en/terms", include_in_schema=False)
@app.get("/ru/usloviya", include_in_schema=False)
@app.get("/hesabat", include_in_schema=False)
@app.get("/en/report", include_in_schema=False)
@app.get("/ru/otchet", include_in_schema=False)
@app.get("/en", include_in_schema=False)
@app.get("/ru", include_in_schema=False)
def index_lang_slash(request: Request):
    return RedirectResponse(request.url.path + "/", status_code=301)


@app.get("/classic", include_in_schema=False)
def classic():
    """The previous plain-JavaScript page, kept as a fallback."""
    return FileResponse(STATIC / "index.html")


@app.get("/beta", include_in_schema=False)
def beta():
    """Old link from the preview period: the React page is the home page now."""
    return RedirectResponse("/", status_code=301)


@app.get("/favicon.ico", include_in_schema=False)
@app.get("/apple-touch-icon.png", include_in_schema=False)
def icon(request: Request):
    """Browsers, crawlers and phones ask for these names at the root (react-ui/make_icons.py draws them)."""
    return FileResponse(STATIC / request.url.path.lstrip("/"))


@app.get("/site.webmanifest", include_in_schema=False)
def manifest():
    return FileResponse(STATIC / "site.webmanifest", media_type="application/manifest+json")


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
    lang = i18n.lang_of(req.lang)
    try:
        key = normalize(req.url)
    except UnsafeTarget as e:
        raise HTTPException(400, i18n.text(str(e), lang)) from None

    hit = None if req.fresh else cache_get(key)
    if hit:
        return JSONResponse({**i18n.report(hit, lang), "cached": True, "benchmarks": survey.benchmarks()})

    if not limiter.allow(client_ip(request)):
        raise HTTPException(429, i18n.text("Çox sayda yoxlama etdiniz. Bir dəqiqə gözləyib yenidən cəhd edin.", lang))
    try:
        report = scanner.scan(req.url).to_dict()
    except UnsafeTarget as e:
        raise HTTPException(400, i18n.text(str(e), lang)) from None
    cache_put(key, report)
    return JSONResponse({**i18n.report(report, lang), "cached": False, "benchmarks": survey.benchmarks()})


class ToolRequest(BaseModel):
    url: str = Field(..., max_length=300)
    tool: Literal["ssl", "email"]
    lang: str = Field("az", max_length=5)
    fresh: bool = False


@app.post("/api/tool")
def tool(req: ToolRequest, request: Request):
    """One narrow check (scanner/tools.py). The other tools on the page read the full scan's result."""
    lang = i18n.lang_of(req.lang)
    try:
        key = f"tool:{req.tool}:{normalize(req.url)}"
    except UnsafeTarget as e:
        raise HTTPException(400, i18n.text(str(e), lang)) from None
    hit = None if req.fresh else cache_get(key)
    if hit:
        return JSONResponse({**i18n.report(hit, lang), "cached": True, "benchmarks": survey.benchmarks()})
    if not limiter.allow(client_ip(request)):
        raise HTTPException(429, i18n.text("Çox sayda yoxlama etdiniz. Bir dəqiqə gözləyib yenidən cəhd edin.", lang))
    try:
        result = scanner_tools.TOOLS[req.tool](req.url)
    except UnsafeTarget as e:
        raise HTTPException(400, i18n.text(str(e), lang)) from None
    cache_put(key, result)
    return JSONResponse({**i18n.report(result, lang), "cached": False, "benchmarks": survey.benchmarks()})


class DeepRequest(BaseModel):
    url: str = Field(..., max_length=300)
    module: Literal["surface", "mail", "tech", "tls", "reputation", "active"]
    lang: str = Field("az", max_length=5)
    fresh: bool = False


@app.post("/api/deep")
def deep_scan(req: DeepRequest, request: Request):
    """One part of the deep analysis (scanner/deep.py). Words are chosen by the page; only errors are sentences."""
    lang = i18n.lang_of(req.lang)
    try:
        key = f"deep:{req.module}:{normalize(req.url)}"
    except UnsafeTarget as e:
        raise HTTPException(400, i18n.text(str(e), lang)) from None
    # Whether a site may be probed is decided anew each time: ownership can end
    hit = None if req.fresh or req.module == "active" else cache_get(key)
    if hit:
        return JSONResponse({**hit, "cached": True})
    if not limiter.allow(client_ip(request), rules=ratelimit.DEEP_RULES):
        raise HTTPException(429, i18n.text("Çox sayda yoxlama etdiniz. Bir dəqiqə gözləyib yenidən cəhd edin.", lang))
    try:
        result = scanner_deep.MODULES[req.module](req.url)
    except UnsafeTarget as e:
        raise HTTPException(400, i18n.text(str(e), lang)) from None
    except Exception:       # one part failing must leave the others standing
        log.exception("Deep module %s failed", req.module)
        raise HTTPException(502, i18n.text("Bu hissə indi yoxlanıla bilmədi. Bir az sonra yenidən cəhd edin.", lang)) from None
    if req.module != "active":
        cache_put(key, result)
    return JSONResponse({**result, "cached": False})


class OwnershipRequest(BaseModel):
    url: str = Field(..., max_length=300)
    lang: str = Field("az", max_length=5)


@app.post("/api/ownership")
def ownership(req: OwnershipRequest):
    """What to publish to prove a site is yours. Computed only, so it needs no limit."""
    try:
        return scanner_deep.ownership(req.url)
    except UnsafeTarget as e:
        raise HTTPException(400, i18n.text(str(e), i18n.lang_of(req.lang))) from None


@app.get("/.well-known/saytyoxla.txt", include_in_schema=False)
def own_ownership_file(request: Request):
    """SaytYoxla's proof that it owns itself, so its own deep check can run on the live site."""
    return PlainTextResponse(scanner_deep.ownership_token(request.url.hostname or ""))


# Keep this last: it matches any single path segment, so earlier routes win.
@app.get("/{filename}", include_in_schema=False)
def google_verify(filename: str):
    key = seo.indexnow_key(filename)
    if key:
        return PlainTextResponse(key)
    body = seo.google_verification(filename)
    if body is None:
        raise HTTPException(404, "Not Found")
    return PlainTextResponse(body)
