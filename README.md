# SaytYoxla

Free 30-second health and security check for small-business websites in Azerbaijan, with a plain-language report in Azerbaijani, English and Russian.

The scanner only looks at what any visitor's browser sees: one page load, the TLS certificate and two public DNS records (SPF, DMARC). It never probes hidden paths or tries to break in. Addresses that resolve to private or internal networks are refused.

## Checks
| Area | Checks |
|---|---|
| Security | HTTPS, certificate expiry, HTTP to HTTPS redirect, HSTS, clickjacking protection, nosniff, CSP, Referrer-Policy, version disclosure, mixed content |
| E-mail | SPF, DMARC |
| Speed | server response time, HTML size |
| Mobile and Google | viewport, title, meta description |

Each finding has a status, a plain explanation and a fix. The score is 0 to 100 with a grade from A to F.

## Run
```bash
pip install -r requirements-dev.txt     # requirements.txt (runtime) + pytest, ruff, httpx
pytest -q
ruff check .
python -m scanner example.az            # command line report
uvicorn web.app:app --reload            # website at http://127.0.0.1:8000
```

`requirements.txt` pins exact versions of the runtime dependencies; upgrade them on purpose and run the tests (`scanner/fetch.py` builds on urllib3's connection classes).

## Security model
The service fetches addresses that strangers type in, so it is built not to become a tool against other networks.

| Risk | Protection | Code | Tests |
|---|---|---|---|
| SSRF to internal addresses | only http/https, ports 80/443, no credentials in the URL; every DNS answer must be a public address | `scanner/safety.py` | `tests/test_fetch_security.py`, `tests/test_scanner.py` |
| DNS rebinding (the name resolves to a public address for the check and an internal one for the request) | each hop is resolved once and the connection goes to that checked address; the host name is kept for the Host header, TLS SNI and certificate validation | `scanner/fetch.py` (`_PinnedAdapter`) | `test_dns_rebinding_cannot_reach_internal_address`, `test_pinned_request_keeps_the_host_name` |
| Redirect to an internal service or another port | every redirect hop is checked like a typed address (scheme, port, credentials, public address), at most 5 hops | `scanner/safety.py` (`check_hop`) | `test_redirect_*` |
| Slow or endless responses | one time budget per page load (15 s, body included), 3 MB cap, 45 s function limit | `scanner/fetch.py`, `vercel.json` | `test_slow_server_cannot_hold_the_scan` |
| Abuse of the scan API | per IP 6 scans a minute and 60 a day, 120 a minute for the whole service, counted in Redis so the limits hold across serverless instances; the client address comes from a header the platform sets, never from a forgeable X-Forwarded-For entry | `web/ratelimit.py` | `tests/test_ratelimit.py` |
| Browser-side attacks on the site | CSP (`script-src 'self'`, no third-party origins), HSTS, `X-Frame-Options: DENY`, nosniff, Referrer-Policy, Permissions-Policy; reports are rendered as text (React escaping, `esc()` on the classic page); CORS only for the author's portfolio | `web/app.py` | `tests/test_web.py` |

### Rate limits in production (Redis)
Serverless instances do not share memory, so the limits need a shared counter. Create a free Redis database at [Upstash](https://upstash.com) (or add Vercel KV, which is Upstash underneath) and set in the Vercel project:

```
UPSTASH_REDIS_REST_URL=https://....upstash.io
UPSTASH_REDIS_REST_TOKEN=...
```

(`KV_REST_API_URL` / `KV_REST_API_TOKEN` from Vercel KV work too. The URL may be pasted as the bare endpoint shown in Upstash's console, `name-12345.upstash.io`; quotes and spaces are ignored.) The function log says `Scan limits are counted in Redis at <host>` when the variables are read, and `Redis rate limit unavailable (<cause>)` if Redis refuses a request. The limits can be changed with `SCAN_RATE_LIMIT`, `SCAN_DAILY_LIMIT` and `SCAN_GLOBAL_LIMIT`. Without Redis, or if Redis does not answer, the limits are counted per instance and the service keeps working.

## Website
`web/app.py` (FastAPI) serves the React front end (`react-ui/`, built into `web/react/`) in Azerbaijani, English and Russian, the survey report, and the previous plain-JavaScript page at `/classic`. `POST /api/scan` is rate-limited (see above) and results are cached for 10 minutes; the response says `"cached": true` when it came from that cache, and a request with `"fresh": true` skips the cache (the rate limit still applies). The report page has a "Check again (fresh result)" button that sends it, so a site owner who just fixed something sees the new result immediately. Static files and pages carry cache headers so that most visits are answered by Vercel's edge without starting the Python function; hashed assets and fonts are cached for a year.

To change the front end: edit `react-ui/`, then `python3 make_pages.py && npm ci && npm run build` in `react-ui/` and commit `web/react/` too (CI checks that it matches a fresh build).

The Inter font is served from `web/static/fonts/` (SIL Open Font License 1.1), so pages make no request to Google.

## Search engines
`web/seo.py` serves `/robots.txt`, `/sitemap.xml`, `/llms.txt` and the Google Search Console verification file. The front page carries a canonical URL, Open Graph tags (`web/static/og-image.png`) and JSON-LD (WebSite, WebApplication, Person, FAQPage — keep the FAQ schema in sync with the visible FAQ). If the site moves to its own domain, set `SITE_URL` and update the canonical/OG URLs in `index.html`.

## Deploy
Vercel: import this repo (`vercel.json` routes every request to `api/index.py`) and set the Redis variables above.
Or on Render: New → Blueprint → this repo (`render.yaml`).

## Continuous integration
`.github/workflows/ci.yml` runs on every pull request and push to `main`: `ruff check`, the full test suite, and a fresh React build that must match the committed `web/react/`.

## License
All rights reserved, see [LICENSE](LICENSE). Third-party components keep their own licenses.

By [Ziya Azizov (ayfar)](https://ayfar.dev) · [LinkedIn](https://www.linkedin.com/in/ziyaazizov).
