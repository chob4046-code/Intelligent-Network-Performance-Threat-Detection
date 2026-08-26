# NetWatch – Intelligent Network Performance & Threat Detection

NetWatch is a defensive network-operations dashboard for authorized environments. It measures TCP service availability and latency, stores historical measurements, detects simple performance anomalies, and records security events.

## Features
- TCP connectivity and latency monitoring
- Configurable monitored targets
- Historical performance data
- Threshold-based anomaly detection
- Security event and alert logging
- Admin login with password hashing and login throttling
- SQLite persistence
- JSON API
- Responsive dashboard
- Automated tests and GitHub Actions CI

## Safety
Only add hosts and services that you own or are explicitly authorized to monitor. NetWatch does not perform packet interception, credential attacks, exploit attempts, or unauthorized scanning.

## Quick start

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
cp .env.example .env
python run.py
```

Open `http://127.0.0.1:5000`.

Default development credentials are configured through environment variables. Change them before deployment.

## Configuration
`SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `DB_PATH`, `MONITOR_INTERVAL`, `CONNECT_TIMEOUT`, and `ANOMALY_LATENCY_MS` are supported.

## Architecture
Browser → Flask API/UI → monitoring service → TCP sockets → SQLite → alerts/events.

## Tests

```bash
pytest -q
```

## Production notes
Use HTTPS behind a production WSGI server, a strong secret key, a non-default admin password, restricted network access, backups, and appropriate log retention. This project is an educational defensive monitoring platform, not a replacement for an enterprise SIEM/NDR product.
