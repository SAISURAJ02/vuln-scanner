# Vulnerability Scanner Dashboard

A full-stack web app that scans a target (URL or localhost) for common security
misconfigurations and displays results on a live dashboard with a computed risk score.

## What it checks

- **HTTP security headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **SSL/TLS** — weak protocol versions, certificate expiry, HTTPS enforcement
- **Cookies** — missing `Secure` / `HttpOnly` flags
- **Info disclosure** — server version leakage in headers
- **Outdated JS libraries** — jQuery / Angular / Bootstrap version fingerprinting
- **Open ports** — localhost/private targets only (see "Scope & Ethics" below)

## Architecture

```
vuln-scanner/
├── backend/
│   ├── scanner.py     # scan logic (all checks)
│   ├── db.py           # SQLite storage
│   ├── app.py           # Flask REST API
│   └── requirements.txt
└── frontend/
    ├── src/App.jsx      # dashboard UI
    └── ...               # Vite + React setup
```

**Flow:** React form → POST `/api/scan` → Flask calls `scanner.run_scan()` →
findings + risk score saved to SQLite → returned to frontend → rendered as
cards + severity breakdown. Scan history is fetched via GET `/api/scans`.

## Setup & Run

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Runs on `http://localhost:5000`.

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Runs on `http://localhost:5173`.

Open the frontend URL, enter a target (e.g. `example.com` or `localhost:8000`), and click Scan.

## Scope & Ethics (worth mentioning in the interview)

Port scanning is **only performed against localhost/private IP targets**.
For public URLs, only passive checks are run — the same requests any normal
browser visit would trigger (fetching headers, checking the TLS handshake,
reading response HTML). Actively port-scanning third-party infrastructure
without authorization can be illegal in many jurisdictions; this tool is
designed to avoid that by scope-checking the target before deciding which
checks to run.

## Possible extensions (if asked "what would you add next")

- Auth (JWT) so scans are tied to a user account
- Scheduled/recurring scans with diff-based alerting
- Export findings as PDF/CSV report
- Plug in a real CVE feed (e.g. NVD API) instead of the small hardcoded library list
