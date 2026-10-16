# SurfaceDrift

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Interface](https://img.shields.io/badge/Interface-Web%20Dashboard%20%7C%20CLI-00f0ff.svg)](#quick-start)
[![Category](https://img.shields.io/badge/Category-EASM%20%2F%20CTEM-red.svg)](#core-capabilities)
[![Real-Time Telemetry](https://img.shields.io/badge/Telemetry-SSE%20Terminal%20Console-43e2d2.svg)](#scanner-telemetry-console)

**SurfaceDrift** is an enterprise-grade, open-source **External Attack Surface Management (EASM)** and **Continuous Threat Exposure Management (CTEM)** platform. Engineered for security engineers, red teams, and DevSecOps practitioners, SurfaceDrift unifies deep automated perimeter reconnaissance with active exposure validation, Exploit Prediction Scoring System (EPSS) threat prioritization, CISA KEV catalog audits, composite posture grading, and automated executive threat synthesis.

---

## Architecture & Workflow

```
[Target Domain]
      │
      ▼
┌────────────────────────────────────────────────────────┐
│  Phase 1: Attack Surface Reconnaissance                │
│  • Passive OSINT (crt.sh, AlienVault OTX, HackerTarget)│
│  • Multithreaded DNS Brute-Forcing & Resolution        │
│  • BGP ASN Routing & Network CIDR Discovery            │
│  • Public AWS S3 Storage Permutation Scraping          │
│  • Identity Harvesting & Corporate Email Profiling     │
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
│  • Real-Time Color-Coded SSE Telemetry Terminal        │
│  • HTTP/HTTPS Probing & Technology Fingerprinting      │
│  • 14-Signature Subdomain Takeover Vulnerability Audit │
│  • Multi-Cloud Storage Exposure (S3 / Azure / GCP)     │
│  • WAF / CDN Direct Origin IP Bypass Hunter            │
│  • FIRST.org EPSS & CISA KEV Threat Prioritization    │
│  • RFC 7208 / 7489 Email Spoofing Defense Evaluation   │
└────────────────────────────────────────────────────────┘
      │
      ▼
┌────────────────────────────────────────────────────────┐
│  Phase 3: Posture Scoring & Consolidated Reporting     │
│  • Composite Posture Score (0–100) & Letter Grade (A-F)│
│  • Executive Threat Exposure Summary                   │
│  • Consolidated Combined Report Package (.zip)         │
└────────────────────────────────────────────────────────┘
```

---

## Core Capabilities

### 1. Perimeter Reconnaissance
- **Multi-Vector Subdomain Discovery:** Gathers assets from Certificate Transparency logs (`crt.sh`), AlienVault OTX, and HackerTarget without sending direct packets.
- **High-Performance DNS Engine:** Memory-efficient, batch-bounded multithreaded DNS brute-forcing that resolves hundreds of candidates in seconds while strictly capping RAM usage.
- **BGP Network Correlation:** Resolves hostnames to IP addresses and queries BGP routing tables (`bgpview.io`) to map ownership ASNs and routing prefixes.
- **Identity & Email Harvesting:** Scrapes organizational emails and reconstructs enterprise naming patterns (e.g., `{first}.{last}@domain.com`) via Hunter.io.

### 2. SurfaceDrift Exposure Validation (CTEM)
- **HTTP Probing & Fingerprinting:** Concurrently queries ports 80/443 to extract HTTP status codes, page titles, server banners, and technological footprints.
- **Subdomain Takeover Auditing:** Evaluates DNS CNAME records against 14 known vulnerable cloud service signatures (AWS S3, GitHub Pages, Heroku, Shopify, Zendesk, Fastly, Ghost, Tumblr, Bitbucket, WordPress, Pantheon, Readme.io, Surge.sh, and Firebase).
- **Multi-Cloud Storage Audit:** Generates domain permutations across AWS S3 (`s3.amazonaws.com`), Azure Blob Storage (`blob.core.windows.net`), and Google Cloud Storage (`storage.googleapis.com`) to identify public read/write misconfigurations.
- **WAF / CDN Origin Bypass Hunter:** Flags origin IPs that sit behind Cloudflare, CloudFront, or Fastly, alerting operators to origin exposure vectors.
- **Exploit Prediction (EPSS & CISA KEV):** Queries the FIRST.org Exploit Prediction Scoring System and cross-references against the CISA Known Exploited Vulnerabilities catalog, categorizing threats into `HIGH`, `MED`, and `LOW` exposure tiers.
- **Email Security Posture:** Audits SPF and DMARC enforcement records, warning when domain impersonation or unauthenticated spoofing is feasible.

### 3. Posture Scoring & Executive Reporting
- **Transparent Scoring Engine:** Mathematical baseline of 100 points with itemized deductions for confirmed takeovers (-30 pts), public buckets (-30 pts), unauthenticated email spoofing (-20 pts), and weaponized CVEs (-35 pts).
- **Letter Grades (A through F):** Transparent security grade reflecting perimeter hygiene.
- **Executive Threat Summary:** Generates a structured Markdown executive briefing detailing strategic exposure, key findings, and prioritized remediation steps.
- **Unified ZIP Archive:** One-click download containing all recon text files (`ips.txt`, `subdomains.txt`, `emails.txt`, `employees.json`), executive summary (`executive_threat_summary.md`), and raw JSON reports.

---

## Project Structure

```text
Surface-Drift/
├── asm.py                      # Core reconnaissance CLI pipeline
├── asm-web-ui/                 # SurfaceDrift Web Dashboard & API Server
│   ├── server.py               # FastAPI server & scan manager
│   ├── database.py             # SQLite scan history & caching persistence
│   ├── static/                 # Dark cyberpunk single-page application
│   │   ├── index.html          # Unified single-pane-of-glass interface
│   │   ├── app.js              # SSE streaming, client-side state, download handlers
│   │   └── styles.css          # Cyberpunk styling, gauges, & terminal telemetry
│   ├── surfacedrift/           # CTEM & Exposure Validation Engine
│   │   ├── advanced_runner.py  # Orchestrator with real-time SSE logging callbacks
│   │   ├── http_probing.py     # Concurrent HTTP probing & fingerprinting
│   │   ├── takeover.py         # 14-signature CNAME takeover auditor
│   │   ├── cloud_auditor.py    # Multi-cloud storage permission tester
│   │   ├── cdn_detector.py     # BGP ASN & CDN origin bypass detector
│   │   ├── epss_kev.py         # FIRST.org EPSS & CISA KEV threat prioritizer
│   │   ├── email_security.py   # SPF/DMARC compliance analyzer
│   │   ├── risk_scoring.py     # 0-100 composite posture scoring engine
│   │   └── gemini_summarizer.py# Executive threat summary synthesis
│   └── requirements.txt        # Web UI dependencies
├── modules/                    # Reconnaissance collectors
│   ├── buckethunter.py         # S3 bucket enumerator
│   ├── hosthunter.py           # DNS resolution & SSL certificate analyzer
│   ├── hunterio.py             # Hunter.io email harvester
│   ├── subbrute.py             # Multithreaded DNS brute-forcing
│   ├── subhunter.py            # Passive subdomain aggregator
│   └── whois_collector.py      # IP and ASN WHOIS parser
├── resources/                  # Subdomain wordlists & resolver lists
├── keylist.asm.example         # Optional API key template
├── requirements.txt            # Root dependencies
└── LICENSE                     # Open source MIT License
```

---

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/Maya-69/Surface-Drift.git
cd Surface-Drift

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate    # Linux / macOS
# .venv\Scripts\activate     # Windows

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

Or via PowerShell from the root:
```powershell
.\run-web.ps1
```

Open your browser at **`http://localhost:8000`** (or `http://localhost:5000`).

---

## Usage Guide

1. **Enter Target Domain:** Input your target (e.g. `pentest-ground.com` or `example.com`).
2. **Select Mode:** Choose between **Passive Mode** (safe OSINT queries only) or **Active Mode** (includes direct multithreaded DNS probes).
3. **Monitor Reconnaissance:** Watch live progress and discovered endpoints in the real-time **Scanner Telemetry Console**.
4. **Export Recon Intelligence:** Click individual buttons to download `IPs (.txt)`, `Subdomains (.txt)`, `Emails (.txt)`, or `Employees (.json)`.
5. **SurfaceDrift CTEM Bridge:** Choose which deep validation checks to run (Takeovers, Cloud Storage, WAF Bypass, EPSS/KEV, Email Posture) and click **Run SurfaceDrift Assessment**.
6. **Watch Real-Time CTEM Telemetry:** Observe live color-coded validation logs in the **SurfaceDrift CTEM Telemetry Console**.
7. **Review Posture & Executive Summary:** Inspect the composite grade (A–F), deduction details, deep findings cards, and executive threat summary.
8. **Download Consolidated Bundle:** Click **Download All Combined Package (.ZIP)** for complete multi-phase assessment artifacts.

---

## API Keys (Optional)

SurfaceDrift functions completely without paid API keys out of the box using free sources (`crt.sh`, FIRST.org EPSS, CISA KEV, direct DNS, and HTTP probing).

To enable commercial OSINT feeds, copy `keylist.asm.example` to `keylist.asm`:
```ini
HunterIO: YOUR_KEY_HERE
Shodan: YOUR_KEY_HERE
VirusTotal: YOUR_KEY_HERE
CensysID: YOUR_ID_HERE
CensysSecret: YOUR_SECRET_HERE
```

---

## License

This project is open-source software licensed under the **[MIT License](LICENSE)**.
