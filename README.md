# ProbeThat 🔍
> Free AI-powered penetration testing tool for startups

ProbeThat scans a URL and generates a professional security report using automated scanners + Claude AI analysis. No login required.

---

## Project Structure

```
pentest-tool/
├── frontend/
│   └── index.html          # Single-file web app (serve with any static host)
└── backend/
    ├── main.py             # FastAPI server — scan endpoints
    ├── ai_analysis.py      # Groq API integration
    ├── report_generator.py # PDF report generation
    ├── requirements.txt
    └── scanner/
        ├── headers.py      # HTTP headers & cookie audit
        ├── ssl_check.py    # TLS/SSL analysis
        ├── dns_check.py    # DNS checks (zone transfer, SPF, DMARC)
        ├── crawler.py      # Sensitive path discovery
        └── ports.py        # Port & service scanning
```

---

## Setup

### 1. Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
uvicorn main:app --reload --port 8000
```

Backend will be available at: `http://localhost:8000`
API docs at: `http://localhost:8000/docs`

### 2. Frontend

The frontend is a single HTML file — serve it with any static server:

```bash
cd frontend

# Option A: Python simple server
python -m http.server 3000

# Option B: npx serve
npx serve .
```

Open `http://localhost:3000` in your browser.

---

## Deployment

### Backend (Fly.io / Railway / Render)

```bash
# Fly.io example
fly launch
fly secrets set ANTHROPIC_API_KEY=your-key
fly deploy
```

Update `API_BASE` in `frontend/index.html` to your deployed backend URL.

### Frontend

Deploy `frontend/index.html` to:
- **Vercel**: drag & drop
- **Netlify**: drag & drop
- **GitHub Pages**: push to repo

### Production Checklist

- [ ] Update `API_BASE` in frontend to point to your backend
- [ ] Add rate limiting (e.g. 3 scans/hour per IP) — use `slowapi`
- [ ] Set `allow_origins` in CORS to your frontend domain only
- [ ] Replace in-memory `scan_jobs` dict with Redis for multi-instance deployments
- [ ] Add a reverse proxy (nginx/Caddy) in front of uvicorn
- [ ] Store PDFs in S3/R2 instead of /tmp
- [ ] Set up monitoring / alerting on the scan endpoint
- [ ] Consider a queue (Celery + Redis) for scan jobs under load

---

## Scan Modules

| Module | What it checks |
|--------|---------------|
| `headers.py` | CSP, HSTS, X-Frame-Options, CORS, cookie flags, info disclosure |
| `ssl_check.py` | Cert expiry, weak ciphers, weak protocols, self-signed certs |
| `dns_check.py` | Zone transfer, SPF, DMARC, CAA records, subdomain enum |
| `crawler.py` | `.env`, `.git`, admin panels, backups, debug endpoints, GraphQL |
| `ports.py` | 30 common ports: databases, RDP, Docker, Elasticsearch, etc. |

---

## Abuse Prevention

For a public tool, strongly consider adding:

```python
# In main.py — add rate limiting with slowapi
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@app.post("/scan")
@limiter.limit("3/hour")
async def start_scan(...):
    ...
```

And a domain allowlist/blocklist to prevent scanning of known-sensitive targets (e.g., government, hospital, banking domains).

---

## Legal

This tool is for use **only on systems you own or have explicit written permission to test**. Unauthorized scanning may violate the CFAA (US), Computer Misuse Act (UK), or equivalent laws in your jurisdiction. By using this tool, you accept all legal responsibility for your scans.

---

## Built With

- **FastAPI** — async Python web framework
- **Claude (claude-opus-4-6)** — AI analysis and remediation
- **ReportLab** — PDF generation
- **dnspython** — DNS queries
- **requests** — HTTP probing
