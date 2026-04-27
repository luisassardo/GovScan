# Deploying GovScan on Railway

1. Push repo to GitHub (private)
2. Railway → New Project → Deploy from GitHub
3. Set env vars: `GOVSCAN_API_KEYS`, `GOVSCAN_RATE_LIMIT`, `SECRET_KEY`
4. Generate keys: `python3 -c "import secrets; print(secrets.token_urlsafe(24))"`
5. Share: `https://govscan-v1.vectorcritico.com/api/scan?url=site.gob.gt&key=KEY`

## Endpoints
- `GET /api/scan?url=https://thewebsitetoaudit&key=the-key-provided` — Scan URL
- `GET /api/status?key=the-key-provided` — Rate limit
- `GET /api/methodology` — Scoring docs (no auth)
