# GovScan v1.0

**Government Website Security Scanner** — Passive, non-intrusive security posture assessment for government websites.

Built for the [DIGECAM investigation](https://vectorcritico.com) by Vector Crítico. Used to audit 134 Guatemalan government websites on April 14, 2026.

## What it does

GovScan checks two dimensions of a website's public-facing security:

1. **SSL/TLS** (45% of score): Certificate validity, HTTPS enforcement, encryption quality
2. **HTTP Security Headers** (55% of score): CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection

Everything measured is publicly visible to any browser. No vulnerability exploitation, no credential testing, no brute forcing.

## Quick start

### Command-line scanner

```bash
pip install requests openpyxl
python govscan/scanner.py templates/gt_executive_2024.xlsx -o results/
```

### Web interface (Railway deployment)

1. Fork this repo
2. Connect to [Railway](https://railway.app)
3. Set environment variable: `GOVSCAN_TOKEN=your-secret-token`
4. Deploy — Railway auto-detects the Procfile

The web interface requires a token to prevent abuse. Share tokens only with trusted journalists and researchers.

### API endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | No | Web interface |
| `/health` | GET | No | Health check |
| `/api/scan?url=X&token=Y` | GET | Token | Scan single URL |
| `/api/batch` | POST | Token | Scan up to 20 URLs |

Rate limit: 10 scans per hour per IP.

## Scoring

See [docs/METHODOLOGY.md](docs/METHODOLOGY.md) for complete breakdown.

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 85–100 | Good security posture |
| B | 70–84 | Acceptable, some gaps |
| C | 55–69 | Moderate risk |
| D | 40–54 | Deficient (DIGECAM: 41/100) |
| E | 25–39 | Poor |
| F | 0–24 | Critical |

## Responsible disclosure

Do not publish specific IPs, ports, or exploitable details. Focus on systemic patterns.

## License

MIT — Use freely, attribute when publishing.

## Credits

- **Vector Crítico** — Investigation and development
- **Luis Assardo** — Lead investigator
- Scoring: OWASP, Mozilla Observatory, CIS Benchmarks
