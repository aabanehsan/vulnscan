# VulnScan — Multi-Stage Vulnerability Scanner

> Engineered in Python + Flask to detect OWASP Top 10 vulnerabilities including XSS, SQL injection, auth bypass, IDOR, and security misconfigurations. Includes modular WAF/IDS bypass payload generators and automated structured reporting.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat&logo=flask)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-blue?style=flat)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## Features

- **Multi-stage scanning** — crawls target, fingerprints WAF, then runs modular scanners per OWASP category
- **XSS detection** — reflected and stored, with 12 WAF bypass variants (unicode, encoding, comment obfuscation)
- **SQL injection** — error-based, boolean-blind, time-based blind (MySQL / MSSQL / PostgreSQL / SQLite)
- **Auth testing** — JWT alg:none confusion, default credential probing
- **IDOR/BOLA** — automated numeric ID enumeration across discovered endpoints
- **Security headers** — audits HSTS, CSP, X-Frame-Options, and more
- **WAF/IDS detection** — fingerprints Cloudflare, AWS WAF, Akamai, Imperva, F5, ModSecurity
- **Real-time frontend** — live terminal log stream via Server-Sent Events
- **Structured reports** — exports HTML reports with CVSS scores and prioritized remediation

---

## Project Structure

```
vulnscan/
├── backend/
│   ├── app.py                    # Flask app — routes + scan orchestrator
│   ├── requirements.txt
│   ├── scanners/
│   │   ├── xss_scanner.py        # Reflected + Stored XSS, WAF bypass payloads
│   │   ├── sqli_scanner.py       # Error-based, time-based blind SQLi
│   │   ├── auth_scanner.py       # JWT alg:none, default credentials
│   │   └── idor_scanner.py       # IDOR/BOLA + Security header audit
│   ├── utils/
│   │   ├── crawler.py            # Link + form crawler
│   │   └── waf_detector.py       # WAF fingerprinting
│   └── reports/
│       └── report_generator.py   # HTML report with remediation guidance
├── frontend/
│   └── index.html                # Wired UI — calls real Flask API
├── .gitignore
└── README.md
```

---

## Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/vulnscan.git
cd vulnscan
```

### 2. Set up Python environment
```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Start the Flask backend
```bash
python app.py
# → Running on http://localhost:5000
```

### 4. Open the frontend
Open `frontend/index.html` directly in your browser — or serve it:
```bash
cd ../frontend
python3 -m http.server 8080
# → Open http://localhost:8080
```

### 5. Run a scan
Enter a target URL (e.g. `http://testphp.vulnweb.com`) and click **Execute Scan**.

> ⚠️ Only scan systems you own or have explicit written permission to test.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Engine health check |
| POST | `/api/scan/start` | Start a new scan |
| GET | `/api/scan/<id>` | Poll scan status + findings |
| GET | `/api/scan/<id>/stream` | SSE stream of real-time logs |
| GET | `/api/scan/<id>/report` | Download HTML report |
| POST | `/api/scan/<id>/abort` | Abort running scan |

### Start scan payload
```json
{
  "target": "https://example.com",
  "modules": ["xss", "sqli", "auth", "idor", "headers"]
}
```

---

## Legal Disclaimer

This tool is for **authorized security testing only**. Never use against systems without explicit written permission. The authors accept no liability for misuse.

---

## Tech Stack

- **Backend** — Python 3.10+, Flask, Requests, BeautifulSoup4
- **Frontend** — Vanilla HTML/CSS/JS, Server-Sent Events
- **Testing methodology** — OWASP Testing Guide v4.2
