# SaytYoxla

Free 30-second health and security check for small-business websites in Azerbaijan, with a plain-language report in Azerbaijani.

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
pip install -r requirements.txt
pytest -q
python -m scanner example.az            # command line report
uvicorn web.app:app --reload            # website at http://127.0.0.1:8000
```

## Website
`web/app.py` (FastAPI) serves an Azerbaijani page with a scan form, a step-by-step "Saytı necə işlətməli?" guide, the report grouped by area with a fix for every problem, print/PDF export and a WhatsApp button. `POST /api/scan` is rate-limited per IP and results are cached for 10 minutes. Set your WhatsApp number in `web/static/app.js` (`WA_NUMBER`).

Deploy on Render: New → Blueprint → this repo (`render.yaml`).

By [Ziya Azizov](https://www.linkedin.com/in/ziya-azizov-91bba638a).
