Website Vulnerability Checker

Lightweight educational tool to perform basic-to-medium website security checks and produce a user-friendly vulnerability score (1–10) with a dashboard, trend chart, and remediation guidance.

## Features
- HTTPS detection and redirect checks
- Common security header checks (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- Server header / fingerprinting exposure
- Simple risk scoring (1–10) and textual summary
- Dashboard UI with dark mode, navigation, and trend chart
- Unit tests for core scanner logic

## Quick Start
Clone or open the project and create a virtual environment, then install dependencies and run the app.

Windows (PowerShell):
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r website-vuln-checker/requirements.txt
python website-vuln-checker/app.py
# Open http://127.0.0.1:5000 in your browser
```

macOS / Linux:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r website-vuln-checker/requirements.txt
python website-vuln-checker/app.py
# Open http://127.0.0.1:5000 in your browser
```

## How Scoring Works (summary)
- Score 1–3: High risk — multiple critical checks failed (no HTTPS, missing HSTS/CSP, severe header leakage).
- Score 4–6: Medium risk — some important headers or configurations missing.
- Score 7–10: Low risk — basic protections present, only minor issues remain.

Primary checks that influence score: HTTPS, HSTS/Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Server header.

## Usage
1. Open the web UI at `http://127.0.0.1:5000`.
2. Enter a website URL and click the scan button.
3. Review the risk score, identified vulnerabilities, and remediation suggestions.
4. Use the `History`, `Reports`, and `Settings` pages for extra context.
