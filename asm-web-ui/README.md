# SurfaceDrift Web Engine & CTEM Workspace

This directory contains the web dashboard, API layer, and Continuous Threat Exposure Management (CTEM) engine for **SurfaceDrift**. Built with high-performance asynchronous **FastAPI**, an interactive dark-cyberpunk SPA frontend, and Server-Sent Events (SSE) real-time streaming telemetry.

Hosted in production on Vercel at **[https://surface-drift.vercel.app/scan](https://surface-drift.vercel.app/scan)**.

---

## Architecture Overview

```
                      ┌──────────────────────────────────────────────┐
                      │    Browser Client (Vanilla ES6 SPA)          │
                      │    • Terminal Telemetry Parser               │
                      │    • Attack Path Graph (Canvas/SVG)          │
                      │    • MITRE ATT&CK Matrix Interactive View    │
                      │    • Surface Drift Baseline Comparison       │
                      └──────────────────────┬───────────────────────┘
                                             │ HTTP REST / SSE Stream
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │    FastAPI Application (server.py)           │
                      │    • Session & Auth (Google OAuth + FastAuth)│
                      │    • Ephemeral & Cloud Database Persistence  │
                      │    • Vercel Serverless Detection             │
                      └──────────────┬───────────────────────────────┘
                                     │
           ┌─────────────────────────┴────────────────────────┐
           ▼                                                  ▼
┌──────────────────────────────────────┐  ┌──────────────────────────────────────┐
│ Phase 1: High-Speed Native Recon     │  │ Phase 2: CTEM Pipeline Runner        │
│ (surfacedrift/passive_osint.py)      │  │ (surfacedrift/advanced_runner.py)    │
│ • Parallel crt.sh, HackerTarget, OTX │  │ • 15 Deep Vulnerability Audits       │
│ • 3.5s Circuit Breakers (~2.2s total)│  │ • MITRE Matrix Mapping Engine        │
│ • Async DNS & Port Bounding          │  │ • Multi-Hop Attack Path Generator    │
└──────────────────────────────────────┘  │ • Surface Drift Delta Engine         │
                                          │ • Gemini AI Threat Summarizer        │
                                          └──────────────────────────────────────┘
```

---

## Directory Structure

```text
asm-web-ui/
├── server.py                  # FastAPI application, authentication, scan coordinator & SSE routes
├── database.py                # SQLite / PostgreSQL persistence for scans, history, and user profiles
├── requirements.txt           # Python dependencies for the web server and CTEM modules
├── vercel.json                # Serverless deployment configuration (maxDuration: 60)
├── static/                    # Frontend client assets
│   ├── index.html             # Single-page interface with 15-module grid, terminals, & gauges
│   ├── app.js                 # State machine, SSE streaming parser, attack graph, & fast auth
│   └── styles.css             # Dark cyberpunk styles, glow gauges, & terminal telemetry
└── surfacedrift/              # CTEM Deep Exposure Assessment Modules
    ├── advanced_runner.py     # Central pipeline runner & SSE stream generator
    ├── passive_osint.py       # Parallel async OSINT engine with 3.5s circuit breakers
    ├── http_probing.py        # Asynchronous HTTP probing & tech stack fingerprinting
    ├── takeover.py            # 14-signature CNAME cloud takeover auditor
    ├── cloud_auditor.py       # S3, Azure Blob, GCP bucket permission & permutation tester
    ├── waf_origin.py          # Direct origin IP detection & WAF bypass hunter
    ├── cdn_detector.py        # BGP ASN & CDN reverse-proxy identifier
    ├── epss_kev.py            # FIRST.org EPSS & CISA KEV real-time threat prioritizer
    ├── email_security.py      # SPF & DMARC RFC 7208/7489 spoofing posture analyzer
    ├── secrets_scanner.py     # High-entropy JavaScript client-side secrets extraction
    ├── api_discovery.py       # Shadow API, OpenAPI/Swagger & GraphQL introspection prober
    ├── eol_analyzer.py        # End-of-life runtime & dependency audit
    ├── blh_detector.py        # Broken Link Hijacking (BLH) crawler & NXDOMAIN auditor
    ├── config_prober.py       # Sensitive configuration (/.git, /.env, backups) prober
    ├── tls_auditor.py         # Async TLS handshake, cipher suite & HSTS compliance prober
    ├── breach_intel.py        # Leaked credential & corporate identity breach auditor
    ├── typosquat_monitor.py   # Typosquatting & lookalike phishing domain radar
    ├── mitre_mapping.py       # MITRE ATT&CK Enterprise Matrix mapping engine
    ├── attack_graph.py        # Directed multi-hop attack path graph generator
    ├── drift_engine.py        # Continuous surface drift delta calculation engine
    ├── remediation_playbooks.py # Actionable fix generation (DNS/AWS/Nginx)
    ├── risk_scoring.py        # 0-100 composite posture deduction formula & letter grade
    └── gemini_summarizer.py   # Gemini API & deterministic executive summary generator
```

---

## API Endpoints Reference

### Authentication
- `GET /api/auth/me` — Returns the authenticated user session or guest profile.
- `GET /api/auth/google/login` — Initiates Google OAuth 2.0 authorization code flow.
- `GET /api/auth/google/callback` — Exchanges Google OAuth authorization code for session cookie.
- `POST /api/auth/fast-auth` — 1-Click instant authentication for demo environments and viva presentations.
- `POST /api/auth/logout` — Clears active session cookies.

### Reconnaissance & Scans
- `POST /api/scans` — Initiates Phase 1 perimeter reconnaissance. Body: `{"target": "example.com", "mode": "active"|"passive", "authorized": true}`.
- `GET /api/scans/{scan_id}` — Returns scan progress, discovered assets, open ports, and live logs.
- `GET /api/scans/history` — Lists historical completed scans for the authenticated user.
- `DELETE /api/scans/{scan_id}` — Deletes a scan record and associated output artifacts.

### SurfaceDrift CTEM Deep Validation
- `POST /api/scans/{scan_id}/continue-surfacedrift-stream` — **Core SSE Endpoint**: Streams real-time color-coded CTEM module logs, findings, attack graphs, and final posture report.
- `POST /api/scans/{scan_id}/continue-surfacedrift` — Synchronous fallback endpoint for non-streaming clients.
- `GET /api/scans/{scan_id}/surfacedrift` — Retrieves cached Phase 2 CTEM assessment results.
- `GET /api/scans/{scan_id}/drift` — Computes continuous threat exposure delta ($\Delta$) against prior scans of the same target.

### Exports & Artifacts
- `GET /api/scans/{scan_id}/download-combined` — Packages all Phase 1 recon text files (`ips.txt`, `subdomains.txt`, `emails.txt`) and Phase 2 CTEM reports (`surfacedrift_advanced_report.json`, `surfacedrift_executive_summary.md`) into a single ZIP archive.
- `GET /api/scans/{scan_id}/download-advanced-json` — Downloads the raw JSON CTEM assessment payload.
- `GET /api/scans/{scan_id}/download-summary-md` — Downloads the formatted executive threat summary Markdown document.

---

## Running Locally

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the FastAPI server:**
   ```bash
   python server.py
   ```

3. **Open browser:**
   Navigate to `http://127.0.0.1:8000`.

---

## Vercel Serverless Hosting

When deployed on Vercel:
- `api/index.py` handles incoming requests as a serverless ASGI app.
- File writes are automatically redirected to `/tmp`.
- Reconnaissance executes synchronously within the active HTTP request context, preventing AWS Lambda container CPU freezing.
- `maxDuration: 60` provides generous execution time for deep multi-module audits.