# SurfaceDrift

[![Live Deployment](https://img.shields.io/badge/Vercel-surface--drift.vercel.app-black?logo=vercel)](https://surface-drift.vercel.app/scan)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Category](https://img.shields.io/badge/Category-EASM%20%2F%20CTEM-red.svg)](#core-capabilities)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Enterprise%20v14-orange.svg)](#mitre-attck-enterprise-matrix-alignment)
[![Threat Intel](https://img.shields.io/badge/Threat%20Intel-EPSS%20%2B%20CISA%20KEV-00f0ff.svg)](#threat-prioritization-epss--cisa-kev)
[![Real-Time Telemetry](https://img.shields.io/badge/Telemetry-SSE%20Terminal%20Console-43e2d2.svg)](#scanner-telemetry-console)

**SurfaceDrift** is an enterprise-grade, open-source **External Attack Surface Management (EASM)** and **Continuous Threat Exposure Management (CTEM)** platform. Engineered for security engineers, red teams, DevSecOps practitioners, and academic defense presentations, SurfaceDrift unifies high-speed perimeter reconnaissance with 15 deep active exposure validation engines, MITRE ATT&CK Enterprise Matrix mapping, graph-based multi-hop attack path chaining, continuous time-series drift tracking, and copy-pasteable remediation playbooks.

Hosted permanently in production on Vercel: **[https://surface-drift.vercel.app/scan](https://surface-drift.vercel.app/scan)**

---

## Architecture & Workflow

```
[Target Domain]
      │
      ▼
┌────────────────────────────────────────────────────────┐
│  Phase 1: High-Speed Perimeter Reconnaissance (EASM)   │
│  • Parallel Async OSINT (crt.sh, AlienVault, H-Target) │
│  • Sub-3s Execution with Circuit-Breaker Resilience    │
│  • Multithreaded DNS Resolution & IP Mapping           │
│  • BGP ASN Routing & Network CIDR Identification       │
│  • Public AWS S3 Storage Permutation Scraping          │
│  • Corporate Email & Identity Pattern Profiling        │
└────────────────────────────────────────────────────────┘
      │
      ▼
┌────────────────────────────────────────────────────────┐
│  Granular Recon Exports                                │
│  • Download IPs, Subdomains, Emails, Employees, JSON   │
└────────────────────────────────────────────────────────┘
      │
      ▼
┌────────────────────────────────────────────────────────┐
│  Phase 2: SurfaceDrift Exposure Validation (CTEM)      │
│  • Real-Time Color-Coded SSE Telemetry Console         │
│  • 15 Deep Vulnerability & Misconfiguration Engines    │
│  • 14-Cloud Subdomain Takeover Vulnerability Auditing  │
│  • Multi-Cloud Storage Probing (S3, Azure Blob, GCP)   │
│  • Direct WAF / CDN Origin IP Bypass Detection         │
│  • FIRST.org EPSS & CISA KEV Threat Prioritization    │
│  • RFC 7208 / 7489 Email Spoofing & BEC Evaluation     │
│  • High-Entropy JavaScript API Secrets Extraction      │
│  • Shadow API & Swagger / OpenAPI Schema Discovery     │
│  • End-of-Life (EOL) Software & Runtime Mapping        │
│  • Broken Link Hijacking (BLH) Supply Chain Radar      │
│  • Exposed Config Probing (/.git, /.env, Backups)      │
│  • SSL/TLS Cryptographic Posture & HSTS Verification   │
│  • Leaked Corporate Identity & Breach Intelligence     │
│  • Typosquatting Brand Phishing Radar (Active MX)      │
│  • Automated SecOps Remediation Playbooks (DNS/CLI)    │
└────────────────────────────────────────────────────────┘
      │
      ▼
┌────────────────────────────────────────────────────────┐
│  Phase 3: Threat Contextualization & Reporting         │
│  • MITRE ATT&CK Enterprise Matrix Alignment (TA0043-07)│
│  • Graph-Based Multi-Hop Attack Path Chaining          │
│  • Continuous Surface Drift Delta Tracking (Δ Assets)  │
│  • Composite Posture Score (0–100) & Letter Grade (A-F)│
│  • AI Executive Threat Summary (Gemini 1.5 Flash)      │
│  • Consolidated Combined Report Package (.zip)         │
└────────────────────────────────────────────────────────┘
```

---

## Core Capabilities

### 1. High-Speed Perimeter Reconnaissance (EASM)
- **Sub-3s Parallel Async OSINT Engine:** Concurrently queries Certificate Transparency logs (`crt.sh`), AlienVault OTX, and HackerTarget using non-blocking asynchronous requests with strict 3.5s per-source circuit breakers. Drops Phase 1 discovery from >90s to **~2.2 seconds**.
- **Anti-Tarpit Browser Mimicry:** Prevents datacenter IP rate-limiting and Cloudflare tarpits by transmitting realistic Chrome browser headers.
- **Multithreaded DNS Engine:** Efficient batch-bounded DNS resolution mapping hostnames to IPv4 addresses without memory overhead.
- **BGP Network Correlation:** Queries BGP routing tables (`bgpview.io`) to discover ownership ASNs, network CIDRs, and hosting providers.
- **Identity & Email Harvesting:** Scrapes corporate emails and reconstructs naming conventions (`{first}.{last}@target.com`).

### 2. Deep Exposure Validation (15 CTEM Engines)
1. **HTTP Probing & Fingerprinting:** Concurrently queries ports 80/443 to detect status codes, page titles, server banners, and technology stacks (WordPress, Next.js, Laravel).
2. **Subdomain Takeover Auditing:** Evaluates DNS CNAME records against 14 cloud service signatures (AWS S3, GitHub Pages, Heroku, Shopify, Fastly, Zendesk, WordPress, etc.).
3. **Multi-Cloud Storage Audit:** Generates permutations across AWS S3 (`s3.amazonaws.com`), Azure Blob (`blob.core.windows.net`), and GCP (`storage.googleapis.com`) to identify public read/write object stores.
4. **WAF / CDN Origin Bypass Hunter:** Connects directly to backend IP addresses with custom `Host` headers to identify origin servers uncloaked by Cloudflare or Fastly.
5. **EPSS & CISA KEV Prioritizer:** Queries FIRST.org Exploit Prediction Scoring System and cross-references against CISA Known Exploited Vulnerabilities catalog.
6. **Email Spoofing & BEC Evaluation:** Evaluates RFC 7208 (SPF) and RFC 7489 (DMARC) alignment, alerting when unauthenticated spoofing is trivial.
7. **JavaScript Secrets Scanner:** High-entropy regex engine scraping client-side JavaScript bundles for leaked AWS keys, Stripe live tokens, and Google API secrets.
8. **Shadow API & Swagger Discovery:** Probes for unauthenticated Swagger/OpenAPI documentation (`/swagger.json`, `/openapi.json`) and GraphQL introspection endpoints.
9. **End-of-Life Software (EOL):** Identifies outdated PHP, Apache, Nginx, jQuery, and Python runtimes with known public exploit vectors.
10. **Broken Link Hijacking (BLH):** Crawls outbound hyperlinks to detect expired domains returning `NXDOMAIN` that adversaries can register to hijack traffic.
11. **Exposed Configuration Prober:** Detects exposed source code and database dumps (`/.git/config`, `/.env`, `/backup.zip`, `/db.sql`).
12. **SSL/TLS Cryptographic Posture:** Validates X.509 certificate expiration dates, forward secrecy ciphers, and `Strict-Transport-Security` (HSTS) headers.
13. **Identity Breach Intelligence:** Correlates discovered corporate emails against breach signature archives to flag compromised accounts and leaked passwords.
14. **Typosquatting Phishing Radar:** Generates visual homoglyphs and typosquats, performing DNS and MX queries to flag registered lookalikes configured for active phishing.
15. **Automated Remediation Playbooks:** Generates actionable, copy-pasteable SecOps fixes (AWS CLI commands, DNS TXT records, hardened Nginx configs).

### 3. MITRE ATT&CK Enterprise Matrix Alignment
SurfaceDrift automatically aligns all technical findings with the **MITRE ATT&CK Enterprise Matrix** across 6 key tactics:
- **TA0043 Reconnaissance:** Public S3 buckets (`T1596.001`), Historical DNS & Certs (`T1596.002`).
- **TA0042 Resource Development:** Subdomain takeovers (`T1584.001`), Broken link hijacking (`T1584.004`), Phishing lookalikes (`T1583.001`).
- **TA0001 Initial Access:** Actively weaponized CISA KEV exploits (`T1190`), Domain spoofing & spearphishing (`T1566.002`), EOL runtimes (`T1190`).
- **TA0005 Defense Evasion:** Direct WAF origin bypass (`T1564`), Deprecated TLS & missing HSTS (`T1588.003`).
- **TA0006 Credential Access:** Exposed `.env` and `.git` (`T1552.005`), Hardcoded JS secrets (`T1552.001`), Leaked corporate passwords (`T1589.001`).
- **TA0007 Discovery:** HTTP service probing (`T1046`), Undocumented APIs and Swagger specs (`T1595.002`).

### 4. Graph-Based Attack Path Chaining
Models adversary traversal from perimeter assets to high-impact compromise sinks:
- **Multi-Hop Traversal Chains:** Demonstrates how low-severity findings (e.g. permissive SPF + lookalike domain with active MX) combine into critical Business Email Compromise (BEC) campaigns.
- **WAF Bypass to Cloud Compromise:** Traces historical DNS leaks $\to$ direct origin server $\to$ exposed `/.env` file $\to$ AWS cloud takeover.
- **Subdomain Takeover to Supply Chain Defacement:** Traces dangling CNAME $\to$ claimed S3 bucket $\to$ malicious JS injection $\to$ cookie theft.

### 5. Continuous Surface Drift Delta Engine
Computes fine-grained differential tracking between recurring scans:
- **Deterministic Fingerprinting:** Generates SHA-256 asset hashes over subdomains, IPs, open ports, and cloud storage buckets.
- **Delta Sets:** Reports $\Delta$ newly discovered assets, decommissioned hosts, newly opened ports, and newly emerged vulnerabilities.
- **Score Velocity:** Tracks changes in posture score ($\Delta \text{Risk Score}$) and grade transitions ($A \to D$) to alert SecOps to unauthorized perimeter changes.

---

## Project Structure

```text
Surface-Drift/
├── AttackSurfaceMapper.py         # Phase 1 CLI reconnaissance driver
├── keylist.asm.example            # Optional API key template
├── requirements.txt               # Root dependencies
├── SURFACEDRIFT_EXPLAINER.md      # Comprehensive technical architecture & viva defense guide
├── VERCEL_HOSTING_GUIDE.md        # Cloud serverless deployment & operational handbook
├── vercel.json                    # Vercel serverless configuration (maxDuration: 60)
└── asm-web-ui/                    # SurfaceDrift Web Engine & CTEM Workspace
    ├── server.py                  # FastAPI server, REST routes, and SSE streaming pipeline
    ├── database.py                # SQLite scan history & session persistence
    ├── requirements.txt           # Web server dependencies
    ├── vercel.json                # Serverless deployment configuration
    ├── static/                    # Dark cyberpunk single-page application
    │   ├── index.html             # Single-pane-of-glass interface with 15-module grid
    │   ├── app.js                 # SSE streaming client, attack graph, MITRE matrix, Fast Auth
    │   └── styles.css             # Cyberpunk theme, score gauges, & terminal telemetry
    └── surfacedrift/              # CTEM Deep Assessment Modules
        ├── advanced_runner.py     # Pipeline orchestrator with real-time SSE streaming
        ├── passive_osint.py       # Parallel async OSINT engine with 3.5s circuit breakers
        ├── http_probing.py        # Asynchronous HTTP probing & tech stack detector
        ├── takeover.py            # 14-signature CNAME takeover auditor
        ├── cloud_auditor.py       # S3, Azure, GCP bucket permutation prober
        ├── waf_origin.py          # Direct origin IP detection & WAF bypass hunter
        ├── cdn_detector.py        # BGP ASN & CDN reverse-proxy identifier
        ├── epss_kev.py            # FIRST.org EPSS & CISA KEV threat prioritizer
        ├── email_security.py      # SPF & DMARC RFC compliance analyzer
        ├── secrets_scanner.py     # High-entropy client-side JS secrets scanner
        ├── api_discovery.py       # Shadow API, OpenAPI/Swagger & GraphQL prober
        ├── eol_analyzer.py        # End-of-life runtime & dependency audit
        ├── blh_detector.py        # Broken Link Hijacking (BLH) crawler
        ├── config_prober.py       # Sensitive file (/.git, /.env, backups) prober
        ├── tls_auditor.py         # Async TLS handshake & HSTS compliance prober
        ├── breach_intel.py        # Leaked credential & corporate identity breach auditor
        ├── typosquat_monitor.py   # Typosquatting & lookalike phishing domain radar
        ├── mitre_mapping.py       # MITRE ATT&CK Enterprise Matrix mapping engine
        ├── attack_graph.py        # Directed multi-hop attack path graph generator
        ├── drift_engine.py        # Continuous surface drift delta calculation engine
        ├── remediation_playbooks.py # Actionable fix generation (DNS/AWS/Nginx)
        ├── risk_scoring.py        # 0-100 composite posture deduction formula
        └── gemini_summarizer.py   # Gemini API & deterministic threat summary generator
```

---

## Quick Start

### 1. Local Installation

```bash
# Clone the repository
git clone https://github.com/Maya-69/Surface-Drift.git
cd Surface-Drift

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux / macOS
# .venv\Scripts\activate        # Windows PowerShell

# Install dependencies
pip install -r requirements.txt
pip install -r asm-web-ui/requirements.txt
```

### 2. Launch the Web UI

From the `asm-web-ui` directory:

```bash
cd asm-web-ui
python server.py
```

Or via Windows launcher scripts in the root:
```powershell
.\run-web.bat    # Windows Command Prompt / Double-click
.\run-web.ps1    # PowerShell (Bypasses execution policy restrictions)
```

Open your browser at **`http://localhost:8000`**.

### 3. Cloud Deployment (Vercel)

SurfaceDrift is fully configured for deployment on Vercel:
1. Fork or push this repository to GitHub.
2. Import the repository into your [Vercel Dashboard](https://vercel.com).
3. The included [`vercel.json`](vercel.json) automatically routes `/api/*` to the FastAPI backend and serves static assets directly from edge CDNs with `maxDuration: 60`.
4. Optionally configure Google OAuth credentials or Gemini API keys in Vercel project environment variables.

---

## Usage Guide

1. **Enter Target Domain:** Input your scope domain (e.g., `pentest-ground.com` or `demo.owasp-juice.shop`).
2. **Select Mode:** Choose between **Passive Mode** (safe parallel OSINT queries) or **Active Mode** (includes direct multithreaded port and DNS probing).
3. **Monitor Reconnaissance:** Watch real-time progress and live terminal events in the **Scanner Telemetry Console**.
4. **Export Recon Intelligence:** Download granular intelligence files: `IPs (.txt)`, `Subdomains (.txt)`, `Emails (.txt)`, or `Employees (.json)`.
5. **SurfaceDrift CTEM Bridge:** Customize the 15-module grid or click **Run SurfaceDrift Assessment**.
6. **Watch Real-Time CTEM Telemetry:** Stream live color-coded findings in the SSE terminal console.
7. **Inspect MITRE Matrix & Attack Graph:** Review tactics in the MITRE ATT&CK Enterprise Matrix and visualize multi-hop traversal paths in the interactive Attack Graph.
8. **Review Posture & Remediation:** Inspect composite grade (A–F), deduction itemization, and copy-pasteable playbook scripts.
9. **Download Consolidated Bundle:** Click **Download All Combined Package (.ZIP)** for complete multi-phase assessment artifacts.

---

## License

This project is open-source software licensed under the **[MIT License](LICENSE)**.
Authored by **Mayuresh Sawant** ([@Maya-69](https://github.com/Maya-69)).