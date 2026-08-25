# Vulnerability Scanner Dashboard

A full-stack web app that scans a target (URL or localhost) for common security
misconfigurations and displays results on a live dashboard with a computed risk score.

## What it checks

- **HTTP security headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **SSL/TLS** — weak protocol versions, certificate expiry, HTTPS enforcement
- **Cookies** — missing `Secure` / `HttpOnly` flags
- **Info disclosure** — server version leakage in headers
- **Outdated JS libraries** — jQuery / Angular / Bootstrap version fingerprinting
- **Open ports** — localhost/private targets
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


