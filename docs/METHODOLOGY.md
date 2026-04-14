# GovScan v1.0 — Scoring Methodology
## How we grade government websites / Cómo calificamos los sitios web gubernamentales

---

## Overview / Resumen

GovScan evaluates two dimensions of a website's public-facing security posture, using only passive, non-intrusive techniques. No vulnerability exploitation, no credential testing, no brute forcing. Everything measured is publicly visible to any browser visiting the site.

GovScan evalúa dos dimensiones de la postura de seguridad pública de un sitio web, utilizando únicamente técnicas pasivas y no intrusivas. Sin explotación de vulnerabilidades, sin pruebas de credenciales, sin fuerza bruta. Todo lo que se mide es públicamente visible para cualquier navegador que visite el sitio.

---

## The Two Pillars / Los dos pilares

### Pillar 1: SSL/TLS (45% of final score)

SSL/TLS is the encryption layer that protects data in transit between the user's browser and the server. We test:

**Does SSL work at all?** Can the site be reached via HTTPS (port 443)?

**Is the certificate valid?** A valid certificate means it was issued by a trusted Certificate Authority (like DigiCert, Let's Encrypt, or Comodo), it hasn't expired, and it matches the domain name. Self-signed certificates — where the site vouches for itself rather than being verified by a third party — fail this check.

**Is HTTPS enforced?** When a user types `http://site.gob.gt` (without the "s"), does the site automatically redirect them to the secure `https://` version? If not, users can accidentally transmit data without encryption.

#### SSL scoring breakdown / Desglose de puntuación SSL

| Condition | Points | Rationale |
|-----------|--------|-----------|
| SSL works + certificate verified by a trusted CA | 80 | The fundamental baseline: encryption exists and is trustworthy |
| SSL works but certificate is NOT verified (self-signed, expired, or mismatched) | 30 | Encryption exists but cannot be trusted — a browser will show a warning |
| No SSL at all (site only works on HTTP) | 0 | All data transmits in plaintext — passwords, personal data, everything |
| HTTPS is enforced (HTTP automatically redirects to HTTPS) | +20 | Prevents users from accidentally using the unencrypted version |
| **Maximum possible** | **100** | |

**Why 80 for valid SSL and only 30 for invalid?** A self-signed certificate provides encryption but no identity verification. A user has no way to know if they're talking to the real government server or to an attacker impersonating it. The 50-point gap reflects this critical difference. Free, valid certificates are available from Let's Encrypt at zero cost — there is no financial barrier to getting a proper certificate.

---

### Pillar 2: HTTP Security Headers (55% of final score)

HTTP security headers are instructions that a website sends to the browser saying "here's how to protect the user while viewing this site." They are configured on the server and cost nothing to implement. They defend against the most common categories of web attacks: cross-site scripting (XSS), clickjacking, data injection, and information theft.

We check for seven headers. Each has a weight based on its defensive importance:

#### Headers scoring breakdown / Desglose de puntuación de encabezados

| Header | Points | What it prevents |
|--------|--------|-----------------|
| **Content-Security-Policy (CSP)** | 15 | The most important header. Tells the browser exactly which scripts, styles, and resources are allowed to execute. Prevents cross-site scripting (XSS) and code injection — the attack category most relevant to the DIGECAM breach. |
| **Strict-Transport-Security (HSTS)** | 15 | Forces the browser to always use HTTPS for this site, even if the user types HTTP. Prevents protocol downgrade attacks and cookie hijacking. |
| **X-Frame-Options** | 10 | Prevents the site from being embedded in a hidden frame on another site (clickjacking). Without this, an attacker can overlay invisible buttons on a legitimate page to trick users into clicking something malicious. |
| **X-Content-Type-Options** | 10 | Prevents the browser from "guessing" the type of a file. Without this, an attacker can disguise a script as an image and trick the browser into executing it. |
| **Referrer-Policy** | 5 | Controls what information is sent when a user clicks a link leaving the site. Without it, sensitive URLs (including session tokens in query strings) can leak to third-party sites. |
| **Permissions-Policy** | 5 | Controls which browser features (camera, microphone, geolocation) the site can access. Limits damage if the site is compromised. |
| **X-XSS-Protection** | 3 | A legacy browser-side XSS filter. Partially deprecated in favor of CSP, but still scored because it provides defense-in-depth for older browsers. |

#### Additional scoring factors

| Condition | Points | Rationale |
|-----------|--------|-----------|
| Site is reachable (HTTP status < 500) | +5 | Basic availability |
| Site uses HTTPS | +10 | The page itself loaded over an encrypted connection |
| HTTP→HTTPS redirect works | +10 | Users arriving via HTTP are protected automatically |
| Information disclosure (per leaked header) | -3 each | Headers like `X-Powered-By: PHP/8.3.16` reveal the exact software version to attackers, making it easier to find matching exploits. Each leaked header subtracts points. |
| **Maximum possible (theoretical)** | **88** | Capped at 100 |

**Why is CSP weighted equally with HSTS at 15 points?** Both address critical but different attack vectors. CSP prevents code injection (the #1 web vulnerability category per OWASP). HSTS prevents protocol downgrade. Neither can substitute for the other. A site needs both.

**Why is X-XSS-Protection only 3 points?** It's a legacy mechanism that modern browsers are phasing out. CSP is the proper replacement. We still score it because (a) many government sites are accessed by older browsers, and (b) defense-in-depth is a valid principle.

---

## Final Score Calculation / Cálculo de la puntuación final

```
Final Score = (SSL Score × 0.45) + (Headers Score × 0.55)
```

| Grade | Score Range | Meaning |
|-------|-----------|---------|
| **A** | 85–100 | Good security posture. SSL is properly configured, HTTPS is enforced, and most or all security headers are present. This is the achievable standard. |
| **B** | 70–84 | Acceptable. SSL works, but some important headers are missing. The site has invested in security but hasn't completed the job. |
| **C** | 55–69 | Moderate risk. Basic SSL is in place but significant gaps exist in header configuration. Common among sites using Cloudflare (which provides SSL) but without custom header configuration. |
| **D** | 40–54 | Deficient. SSL may work, but the site lacks most defensive headers. The user's browser receives minimal instructions on how to protect them. This is where DIGECAM scored (41/100). |
| **E** | 25–39 | Poor. Major security gaps. SSL may be misconfigured or missing headers entirely. |
| **F** | 0–24 | Critical. The site may not have SSL at all, may not be reachable, or has fundamental security failures. |

**Why 45/55 weighting instead of 50/50?** SSL is binary in nature — once you have a valid certificate and enforce HTTPS, you've captured most of the SSL score. Headers, by contrast, have more granularity and more direct impact on application-layer security (which is where most breaches occur, including DIGECAM's). The slight tilt toward headers reflects that operational security practices matter more than the presence of a certificate.

---

## What GovScan Does NOT Measure / Lo que GovScan NO mide

This is equally important for transparency:

| NOT measured | Why |
|-------------|-----|
| Application vulnerabilities (SQLi, XSS, RCE) | Active vulnerability scanning would be intrusive and potentially illegal without authorization |
| Software versions (PHP, Apache, CMS) | While Shodan captures this data, GovScan's scanner only examines headers. Software version data in this investigation came from separate OSINT sources (Shodan), not from GovScan itself. |
| Password policies | Cannot be tested without credentials |
| Database security | Not visible from the public internet |
| Internal network segmentation | Not visible from outside |
| Backup and recovery procedures | Not visible from outside |
| Compliance with Decreto 57-2008 (LAIP) | Planned for Phase 2b, separate methodology |
| Physical security | Not in scope |

**A high GovScan score does not mean a site is unhackable.** It means the site has implemented the publicly verifiable security measures that international standards consider mandatory. A site with a perfect 100/100 could still be vulnerable to application-level bugs, misconfigurations, or insider threats. But a site with a low score has demonstrably failed to implement free, basic, well-documented protections — and that failure is a reliable predictor of deeper problems.

---

## Standards and References / Estándares y referencias

GovScan's header selection and scoring weights are informed by:

- **OWASP Secure Headers Project** — The definitive list of recommended HTTP response headers for web security. All seven headers we check are on OWASP's recommended list.
- **Mozilla Observatory** — Mozilla's open-source website security scanner, which grades sites on a similar header-based methodology. Our scoring model is simpler but aligned in priorities.
- **Mozilla Web Security Guidelines** — Mozilla's documentation on which headers to implement and why.
- **NIST SP 800-95** — Guide to Secure Web Services, which recommends transport layer security and proper header configuration.
- **CIS Benchmarks** — Center for Internet Security benchmarks for web server hardening, which include header configuration requirements.

The grade scale (A through F) was chosen for immediate comprehensibility — it maps to the universal academic grading system that requires no technical background to understand. A "D" means the same thing it means in school: you're passing, barely, and you're one bad day away from failing.

---

## Reproducibility / Reproducibilidad

GovScan is open-source. Any journalist, researcher, or government IT team can:

1. Download the scanner (`govscan_scanner.py`)
2. Prepare an inventory of websites in XLSX format (or use our template)
3. Run: `python3 scanner.py inventory.xlsx -o results/`
4. Get identical results (within the margin of network variability)

The scan uses standard Python libraries (`requests`, `openpyxl`) and requires no paid API keys or proprietary tools. Results are output in CSV and JSON for analysis in any tool.

---

*GovScan v1.0 — Methodology document*
*Version: April 14, 2026*
