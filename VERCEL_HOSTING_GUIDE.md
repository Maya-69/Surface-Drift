# SurfaceDrift — Vercel Cloud Hosting & Deployment Guide

This document provides a comprehensive operational guide for hosting **SurfaceDrift** on **Vercel**, explaining how the deployment works, its permanence, serverless architecture, Google OAuth integration, and how to push updates.

---

## 1. Is SurfaceDrift Hosted on Vercel Permanently?

### **Yes, your deployment is permanent.**
* The live production URL (e.g., `https://surface-drift.vercel.app`) remains **online 24/7/365** on Vercel's Hobby plan.
* It does **not** shut down, sleep, or expire after periods of inactivity.
* As long as your GitHub repository remains connected and you do not delete the project in your Vercel dashboard, it is permanently hosted.

---

## 2. Architecture: How Vercel Runs SurfaceDrift

SurfaceDrift is configured as a high-performance **Serverless ASGI Application**:

```
                              ┌───────────────────────────────────────────────┐
                              │            Vercel Global Edge CDN             │
                              └───────┬───────────────────────────────┬───────┘
                                      │                               │
                       Static Assets  │               API Requests    │
                      (/static/*, JS) │               (/api/*, /scan) │
                                      ▼                               ▼
                      ┌───────────────────────┐       ┌───────────────────────────────┐
                      │   Edge Static Cache   │       │ Vercel Serverless Function    │
                      │ (Instant 0ms delivery)│       │ (FastAPI via api/index.py)    │
                      └───────────────────────┘       └───────────────┬───────────────┘
                                                                      │
                                                      ┌───────────────▼───────────────┐
                                                      │  Ephemeral /tmp or Cloud DB   │
                                                      │  (SQLite / PostgreSQL / Neon) │
                                                      └───────────────────────────────┘
```

1. **Static Files (`/static/*`, CSS, JS, SVGs)**:
   Served directly from Vercel's global CDN with low latency.
2. **Serverless Function (`api/index.py`)**:
   FastAPI routes are executed on-demand inside AWS Lambda micro-containers managed by Vercel.
3. **Filesystem Considerations**:
   Vercel serverless functions have a read-only filesystem except for the `/tmp` folder. SurfaceDrift automatically detects the Vercel environment (`os.getenv("VERCEL")`) and redirects temporary scan artifacts and SQLite files to `/tmp`.

---

## 3. Storage & Scan History: Ephemeral vs. Cloud Database

| Deployment | Storage Mode | Persistence Behavior |
|---|---|---|
| **Local (`python server.py`)** | Local SQLite (`data/asm_history.db`) | **Permanent** on your local hard drive. |
| **Vercel Default** | `/tmp/asm_history.db` | **Ephemeral** — retained while serverless container is warm; resets on cold boots. |
| **Vercel + Cloud DB** | PostgreSQL (Supabase / Neon) | **Permanent 100% cloud persistence** across all users and devices. |

> [!TIP]
> If you want your scan history and user logins to be preserved permanently on Vercel across cold starts, create a free database at [Supabase](https://supabase.com) or [Neon.tech](https://neon.tech), and add the `DATABASE_URL` environment variable in your Vercel project settings.

---

## 4. Google OAuth 2.0 Configuration for Vercel

To ensure Google Sign-In works seamlessly both in production on Vercel and during local development, your Google Cloud Console OAuth 2.0 Client ID must have the following configuration:

### Authorised JavaScript Origins
* `http://localhost:8000`
* `http://127.0.0.1:8000`
* `https://surface-drift.vercel.app`

### Authorised Redirect URIs
* `http://localhost:8000`
* `http://localhost:8000/api/auth/google/callback`
* `http://127.0.0.1:8000`
* `http://127.0.0.1:8000/api/auth/google/callback`
* `https://surface-drift.vercel.app`
* `https://surface-drift.vercel.app/api/auth/google/callback`

### Vercel Environment Variables
In your Vercel dashboard (`Settings` -> `Environment Variables`):
* `GOOGLE_CLIENT_ID` = `your-client-id.apps.googleusercontent.com`
* `GOOGLE_CLIENT_SECRET` = `GOCSPX-your-secret`

---

## 5. Security & Access Model: Guest vs. Authenticated

SurfaceDrift enforces a two-tier access security boundary:

```
┌─────────────────────────────────┐          ┌──────────────────────────────────┐
│        GUEST USER (UNAUTH)      │          │     AUTHENTICATED USER (GOOGLE)  │
├─────────────────────────────────┤          ├──────────────────────────────────┤
│ • Phase 1 OSINT Recon: ALLOWED  │          │ • Phase 1 OSINT Recon: ALLOWED   │
│ • History Recording: DISABLED   │          │ • History Recording: SAVED TO DB │
│ • Phase 2 Probing: BLOCKED (401)│          │ • Phase 2 Probing: UNLOCKED      │
│ • Ephemeral session only        │          │ • Attack Surface Drift Tracking  │
└─────────────────────────────────┘          └──────────────────────────────────┘
```

1. **Guest Mode (Unauthenticated)**:
   - When a guest clicks "Start Assessment", a modal informs them that nothing will be saved to history and Phase 2 is locked.
   - The scan only lives in temporary memory (`JOBS`) for the current active browser session.
   - Any attempt to trigger Phase 2 Deep Probing (`/api/scans/{id}/continue-surfacedrift-stream`) is blocked by both frontend enforcement and a backend `HTTP 401 Unauthorized` check.

2. **Authenticated Mode (Signed In with Google)**:
   - Scans are recorded to the user's scan history.
   - Unlocks the entire **16-engine Phase 2 Deep Probing suite**:
     - JavaScript Secrets & API Key Extraction
     - Shadow API & Swagger/OpenAPI Discovery
     - End-of-Life (EOL) & Vulnerable Dependency Mapping
     - Broken Link Hijacking (BLH) Detector
     - WAF & Origin Bypass Mapping
     - Exposed Configuration Probing (`.env`, `.git`)
     - SSL/TLS Cryptographic Posture
     - Breached Identity & Credential Intelligence
     - Typosquatting & Phishing Threat Monitor
     - Automated Remediation Playbooks & Fix Snippets

---

## 6. How to Deploy Updates (Continuous Deployment)

Vercel is hooked directly to your GitHub repository: `https://github.com/Maya-69/Surface-Drift.git`.

Whenever you make any changes to the code locally:

```powershell
# 1. Stage changes
git add .

# 2. Commit
git commit -m "feat: Add guest restrictions and update Vercel deployment configs"

# 3. Push to GitHub
git push origin main
```

**What happens next?**
* Vercel immediately receives a webhook from GitHub.
* It builds the serverless container and invalidates the edge cache.
* Within **15 to 30 seconds**, your live site at `https://surface-drift.vercel.app` is updated with zero downtime.

---

## 7. How to Run Locally

If you want to run SurfaceDrift on your local machine:

1. **Navigate to the web UI directory**:
   ```powershell
   cd asm-web-ui
   ```

2. **Configure local environment**:
   Create or edit `.env` in `asm-web-ui`:
   ```env
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   ```

3. **Start the server**:
   ```powershell
   python server.py
   ```

4. **Open in browser**:
   Visit `http://localhost:8000` or `http://127.0.0.1:8000`.
