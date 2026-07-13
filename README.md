# 🛡️ Domain Recon — Security Controls Review

A lightweight tool that takes a **domain name** and reviews the **security
controls** published around it, then presents the results as a **web dashboard**
with a **CSV export**. Built for learning and for defensive security posture
checks.

Everything it does is **passive**: it only reads publicly available data and the
target's own published records. It performs **no exploitation, brute-forcing, or
intrusive scanning**. Use it only on domains you own or are authorized to assess.

---

## What it checks

| Category | Controls reviewed |
|----------|-------------------|
| **DNS Footprint** | A / AAAA / MX / NS records, nameserver redundancy & diversity, IPv6 |
| **Email Authentication** | SPF (policy strength), DMARC (policy & reporting), DKIM (common-selector discovery) |
| **DNS Integrity** | DNSSEC signing, CAA issuance restriction |
| **TLS / Certificate** | Certificate validity & expiry, issuer, SANs, negotiated protocol, legacy TLS 1.0/1.1 support |
| **HTTP Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HTTP→HTTPS upgrade, cookie flags, info-disclosure headers |
| **Domain Registration** | Registrar, registration & expiry dates, registrar lock, registry DNSSEC delegation (via RDAP) |
| **Attack Surface** | Subdomains discovered from public Certificate Transparency logs (crt.sh), sensitive-looking hostnames |

Each finding gets a status (**PASS / WARN / FAIL / INFO**), a severity, a
plain-English explanation, and a remediation recommendation. An overall
**0–100 score and letter grade** summarizes posture.

---

## Quick start

```bash
# 1. Install dependencies (Python 3.9+)
pip install -r requirements.txt

# 2. Launch the dashboard
python app.py

# 3. Open http://127.0.0.1:5000 and enter a domain
```

### Command line

```bash
python cli.py example.com                 # print a report to the terminal
python cli.py example.com --csv out.csv   # also save findings as CSV
python cli.py example.com --json out.json # also save the full report as JSON
```

The CLI exits non-zero when any control **FAILs**, so it can gate a CI pipeline.

---

## HTTP API

| Endpoint | Description |
|----------|-------------|
| `GET /api/scan?domain=example.com` | JSON report |
| `GET /api/scan.csv?domain=example.com` | CSV download |
| `GET /healthz` | Health check |

---

## Project layout

```
app.py                 Flask web server (dashboard + JSON/CSV API)
cli.py                 Command-line runner
reconlib/
  scanner.py           Orchestrates all checks, scores results
  models.py            Finding model, scoring
  utils.py             Domain normalization, DNS resolver
  export.py            CSV serialization
  checks/              One module per control family
templates/index.html   Dashboard markup
static/style.css       Dashboard styling (light/dark aware)
static/app.js          Dashboard logic + client-side CSV export
```

## How the score works

Every check starts the domain at 100 points. Non-passing findings subtract a
penalty weighted by status and severity (e.g. a high-severity FAIL like a
missing SPF record costs more than a low-severity WARN). The result maps to a
letter grade: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F. INFO findings never affect
the score — they describe footprint and attack surface, not defects.

## Notes & limitations

- **DKIM** uses provider-specific selector names, so absence in the probe does
  not prove DKIM is unconfigured — it is reported as INFO, not FAIL.
- **crt.sh** can be slow or rate-limited; that check degrades to an ERROR
  finding rather than failing the scan.
- Network egress to DNS, the target on 80/443, `rdap.org`, and `crt.sh` is
  required.

## License

MIT — see [LICENSE](LICENSE).
