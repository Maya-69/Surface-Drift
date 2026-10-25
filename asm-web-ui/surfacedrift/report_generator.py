"""
SurfaceDrift CTEM & Attack Surface Assessment Report Generator.
Generates comprehensive, self-contained HTML (with Print/PDF styling) and Markdown reports.
"""

from __future__ import annotations

import html
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _escape(text: Any) -> str:
    if text is None:
        return ""
    return html.escape(str(text))


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def generate_html_report(
    target: str,
    scan_id: str,
    summary: Optional[Dict[str, Any]] = None,
    advanced: Optional[Dict[str, Any]] = None,
    generated_at: Optional[str] = None,
) -> str:
    """
    Generate a standalone, enterprise-grade, printable HTML security assessment report.
    """
    summary = summary or {}
    advanced = advanced or {}
    gen_time = generated_at or _now_str()

    posture = advanced.get("posture") or {}
    score = posture.get("score", 100)
    grade = (posture.get("grade") or "A").upper()
    breakdown = posture.get("breakdown") or []

    sections = summary.get("sections") or {}
    subdomains = sections.get("subdomains") or []
    ip_records = sections.get("ip_records") or []
    dns_records = sections.get("dns_records") or []
    ports_and_vulns = sections.get("ports_and_vulns") or []
    email_sec_phase1 = sections.get("email_security") or {}

    findings = advanced.get("findings") or {}
    http_probes = findings.get("http_probing") or {}
    live_hosts = [h for h in (http_probes.get("results") or []) if h.get("is_live")]
    live_count = http_probes.get("live_hosts_count", len(live_hosts))

    takeovers = (findings.get("subdomain_takeovers") or {}).get("items") or []
    cloud_buckets = (findings.get("cloud_storage") or {}).get("buckets") or []
    waf_bypasses = (findings.get("waf_bypass") or {}).get("origins") or []
    threat_vulns = (findings.get("threat_prioritization") or {}).get("cves") or []
    email_sec = findings.get("email_security") or email_sec_phase1
    js_secrets = (findings.get("js_secrets") or {}).get("findings") or []
    shadow_apis = (findings.get("shadow_apis") or {}).get("endpoints") or []
    exposed_cfgs = (findings.get("exposed_configs") or {}).get("exposed_files") or []
    tls_data = findings.get("tls_posture") or {}
    breach_identities = (findings.get("breach_intel") or {}).get("breached_identities") or []
    typosquats = (findings.get("typosquatting") or {}).get("active_squats") or []
    remediation_playbooks = findings.get("remediation_playbooks") or advanced.get("remediation") or []
    mitre_data = advanced.get("mitre_attack") or {}
    attack_graph = advanced.get("attack_graph") or {}

    ai_content = (advanced.get("ai_executive_summary") or {}).get("content") or ""
    if not ai_content:
        ai_content = f"Assessment completed for target domain {target}. SurfaceDrift identified {len(subdomains)} subdomains across {len(ip_records)} IP addresses."

    # Convert simple markdown headers/bold to basic HTML
    formatted_ai_summary = ""
    for line in ai_content.splitlines():
        trimmed = line.strip()
        if not trimmed:
            formatted_ai_summary += "<p></p>"
            continue
        if trimmed.startswith("### "):
            formatted_ai_summary += f"<h4>{_escape(trimmed[4:])}</h4>"
        elif trimmed.startswith("#### "):
            formatted_ai_summary += f"<h5>{_escape(trimmed[5:])}</h5>"
        elif trimmed.startswith("- "):
            formatted_ai_summary += f"<li>{_escape(trimmed[2:])}</li>"
        else:
            formatted_ai_summary += f"<p>{_escape(trimmed)}</p>"

    # Grade coloring
    grade_colors = {
        "A": {"bg": "rgba(34, 197, 94, 0.15)", "border": "#22c55e", "text": "#4ade80"},
        "B": {"bg": "rgba(59, 130, 246, 0.15)", "border": "#3b82f6", "text": "#60a5fa"},
        "C": {"bg": "rgba(234, 179, 8, 0.15)", "border": "#eab308", "text": "#facc15"},
        "D": {"bg": "rgba(249, 115, 22, 0.15)", "border": "#f97316", "text": "#fb923c"},
        "F": {"bg": "rgba(239, 68, 68, 0.15)", "border": "#ef4444", "text": "#f87171"},
    }
    g_col = grade_colors.get(grade, grade_colors["A"])

    status_label = "Optimal Exposure Posture" if grade == "A" else ("Moderate Risk" if grade in ("B", "C") else "Elevated Critical Exposure")

    # Render HTML document
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SurfaceDrift Assessment Report — {_escape(target)}</title>
  <style>
    :root {{
      --bg: #070d10;
      --card-bg: #0c151a;
      --border: rgba(67, 226, 210, 0.18);
      --accent: #43e2d2;
      --accent-glow: rgba(67, 226, 210, 0.25);
      --text: #e2ece9;
      --text-muted: #8ea39c;
      --crit: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --low: #3b82f6;
      --info: #06b6d4;
      --ok: #22c55e;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font-sans);
      font-size: 14px;
      line-height: 1.6;
      padding: 30px 20px 80px;
    }}

    .report-container {{
      max-width: 1140px;
      margin: 0 auto;
    }}

    /* Action Toolbar (Screen Only) */
    .report-toolbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 20px;
      background: rgba(12, 21, 26, 0.85);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 24px;
      backdrop-filter: blur(10px);
    }}
    .toolbar-title {{
      font-family: var(--font-mono);
      font-size: 11px;
      letter-spacing: 0.1em;
      color: var(--accent);
      text-transform: uppercase;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .toolbar-title span {{
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--accent);
      box-shadow: 0 0 10px var(--accent);
    }}
    .toolbar-actions {{
      display: flex;
      gap: 10px;
    }}
    .btn {{
      display: inline-flex;
      align-items: center;
      gap: 7px;
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      text-decoration: none;
      transition: all 0.2s ease;
      border: 1px solid transparent;
    }}
    .btn-primary {{
      background: var(--accent);
      color: #061917;
      font-weight: 600;
    }}
    .btn-primary:hover {{
      background: #5ff0e1;
      box-shadow: 0 0 14px var(--accent-glow);
    }}
    .btn-secondary {{
      background: rgba(255, 255, 255, 0.05);
      border-color: rgba(255, 255, 255, 0.15);
      color: var(--text);
    }}
    .btn-secondary:hover {{
      background: rgba(255, 255, 255, 0.1);
      border-color: var(--accent);
    }}

    /* Header Banner */
    .report-header {{
      background: linear-gradient(135deg, rgba(12, 21, 26, 0.95), rgba(7, 13, 16, 0.95));
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 32px 36px;
      margin-bottom: 24px;
      position: relative;
      overflow: hidden;
    }}
    .report-header::before {{
      content: "";
      position: absolute;
      top: -80px;
      right: -80px;
      width: 260px;
      height: 260px;
      background: radial-gradient(circle, rgba(67, 226, 210, 0.18), transparent 70%);
      pointer-events: none;
    }}
    .header-topline {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }}
    .classification-tag {{
      display: inline-block;
      font-family: var(--font-mono);
      font-size: 10px;
      letter-spacing: 0.15em;
      text-transform: uppercase;
      padding: 3px 9px;
      border-radius: 3px;
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.4);
      color: #f87171;
    }}
    .meta-time {{
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-muted);
    }}
    .report-title {{
      font-size: 28px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #ffffff;
      margin-bottom: 8px;
    }}
    .report-subtitle {{
      color: var(--text-muted);
      font-size: 13px;
    }}
    .report-meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-top: 24px;
      padding-top: 20px;
      border-top: 1px solid rgba(255, 255, 255, 0.08);
    }}
    .meta-cell strong {{
      display: block;
      font-size: 10px;
      font-family: var(--font-mono);
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 4px;
    }}
    .meta-cell span {{
      font-size: 13px;
      font-weight: 500;
      color: var(--text);
    }}
    .meta-cell code {{
      font-family: var(--font-mono);
      color: var(--accent);
      background: rgba(67, 226, 210, 0.08);
      padding: 2px 6px;
      border-radius: 3px;
    }}

    /* Score & Executive Posture Card */
    .posture-card {{
      display: grid;
      grid-template-columns: 240px 1fr;
      gap: 24px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 28px;
      margin-bottom: 24px;
    }}
    @media (max-width: 800px) {{
      .posture-card {{ grid-template-columns: 1fr; }}
    }}
    .posture-score-box {{
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 20px;
      border-radius: 8px;
      background: {g_col["bg"]};
      border: 2px solid {g_col["border"]};
      text-align: center;
    }}
    .grade-badge {{
      font-size: 64px;
      font-weight: 800;
      line-height: 1;
      color: {g_col["text"]};
      margin-bottom: 6px;
      font-family: var(--font-mono);
    }}
    .score-ratio {{
      font-size: 20px;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 4px;
    }}
    .posture-label {{
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      font-family: var(--font-mono);
    }}
    .posture-narrative {{
      display: flex;
      flex-direction: column;
      justify-content: center;
    }}
    .narrative-title {{
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 12px;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .narrative-body {{
      color: var(--text-muted);
      font-size: 13px;
      line-height: 1.7;
    }}
    .narrative-body p {{ margin-bottom: 10px; }}
    .narrative-body strong {{ color: var(--text); }}
    .narrative-body li {{ margin-left: 20px; margin-bottom: 6px; }}

    /* KPI Metrics Grid */
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }}
    .metric-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      transition: border 0.2s;
    }}
    .metric-value {{
      font-family: var(--font-mono);
      font-size: 26px;
      font-weight: 700;
      color: #ffffff;
      line-height: 1.1;
      margin-bottom: 6px;
    }}
    .metric-label {{
      font-size: 11px;
      color: var(--text-muted);
      line-height: 1.3;
    }}
    .metric-alert {{
      border-color: rgba(239, 68, 68, 0.4);
      background: rgba(239, 68, 68, 0.05);
    }}
    .metric-alert .metric-value {{
      color: #f87171;
    }}

    /* Section Cards */
    .section-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 26px;
      margin-bottom: 24px;
    }}
    .section-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 14px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      margin-bottom: 18px;
    }}
    .section-title {{
      font-size: 16px;
      font-weight: 600;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .section-badge {{
      font-family: var(--font-mono);
      font-size: 10px;
      padding: 3px 8px;
      border-radius: 4px;
      background: rgba(67, 226, 210, 0.12);
      border: 1px solid var(--border);
      color: var(--accent);
    }}

    /* Tables */
    .table-responsive {{
      overflow-x: auto;
      margin-top: 10px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      text-align: left;
    }}
    th {{
      font-family: var(--font-mono);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      padding: 10px 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
      background: rgba(0, 0, 0, 0.2);
    }}
    td {{
      padding: 10px 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.05);
      color: var(--text);
      vertical-align: middle;
    }}
    tr:hover td {{
      background: rgba(255, 255, 255, 0.02);
    }}
    code {{
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--accent);
      background: rgba(67, 226, 210, 0.08);
      padding: 2px 5px;
      border-radius: 3px;
    }}

    /* Badges */
    .badge {{
      display: inline-block;
      padding: 2px 7px;
      border-radius: 3px;
      font-family: var(--font-mono);
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
    }}
    .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .badge-high {{ background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.4); }}
    .badge-med {{ background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.4); }}
    .badge-low {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4); }}
    .badge-info {{ background: rgba(6, 182, 212, 0.2); color: #22d3ee; border: 1px solid rgba(6, 182, 212, 0.4); }}
    .badge-ok {{ background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.4); }}

    /* Findings List */
    .finding-item {{
      background: rgba(0, 0, 0, 0.25);
      border: 1px solid rgba(255, 255, 255, 0.07);
      border-radius: 6px;
      padding: 14px 16px;
      margin-bottom: 10px;
    }}
    .finding-top {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }}
    .finding-title {{
      font-weight: 600;
      color: #ffffff;
      font-size: 13px;
    }}
    .finding-desc {{
      color: var(--text-muted);
      font-size: 12px;
      line-height: 1.5;
    }}
    .finding-code {{
      margin-top: 8px;
      background: #04080a;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 4px;
      padding: 8px 12px;
      font-family: var(--font-mono);
      font-size: 11px;
      color: #8ce4dc;
      overflow-x: auto;
      white-space: pre-wrap;
    }}

    /* Playbook Card */
    .playbook-card {{
      background: rgba(12, 21, 26, 0.85);
      border: 1px solid var(--border);
      border-left: 4px solid var(--accent);
      border-radius: 6px;
      padding: 16px 20px;
      margin-bottom: 12px;
    }}
    .playbook-card.crit {{ border-left-color: var(--crit); }}
    .playbook-card.high {{ border-left-color: var(--high); }}

    /* Deductions */
    .deductions-list {{
      display: flex;
      flex-direction: column;
      gap: 6px;
      margin-top: 8px;
    }}
    .deduction-row {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 12px;
      border-radius: 4px;
      background: rgba(239, 68, 68, 0.08);
      border: 1px solid rgba(239, 68, 68, 0.2);
      font-size: 12px;
    }}
    .deduction-row strong {{ color: #f87171; font-family: var(--font-mono); }}

    /* Empty state */
    .empty-state {{
      color: var(--text-muted);
      font-style: italic;
      font-size: 12px;
      padding: 10px 0;
    }}

    /* Footer */
    .report-footer {{
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid rgba(255, 255, 255, 0.1);
      display: flex;
      justify-content: space-between;
      align-items: center;
      color: var(--text-muted);
      font-size: 11px;
      font-family: var(--font-mono);
    }}

    /* Print / PDF Stylesheet — Matches HTML Preview Exact Styling */
    @media print {{
      body {{
        background: #070d10 !important;
        color: #e2ece9 !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
        padding: 10px 0 !important;
        font-size: 11pt !important;
      }}
      .report-toolbar {{ display: none !important; }}
      .report-header, .posture-card, .section-card, .metric-card, .finding-item, .playbook-card {{
        background: #0c151a !important;
        color: #e2ece9 !important;
        border: 1px solid rgba(67, 226, 210, 0.28) !important;
        break-inside: avoid;
        page-break-inside: avoid;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }}
      .report-title, .narrative-title, .section-title, .finding-title, .score-ratio {{
        color: #ffffff !important;
      }}
      .report-subtitle, .narrative-body, .finding-desc, .metric-label {{
        color: #8ea39c !important;
      }}
      th {{
        background: rgba(0, 0, 0, 0.4) !important;
        color: #8ea39c !important;
        border-bottom: 1px solid rgba(255, 255, 255, 0.15) !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }}
      td {{
        border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
        color: #e2ece9 !important;
      }}
      code, .finding-code {{
        background: #04080a !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        color: #8ce4dc !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }}
      .posture-score-box {{
        background: {g_col["bg"]} !important;
        border: 2px solid {g_col["border"]} !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }}
      .grade-badge {{
        color: {g_col["text"]} !important;
      }}
      .btn {{ display: none !important; }}
      .badge {{
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }}
    }}
  </style>
</head>
<body>
  <div class="report-container">
    <!-- Top Action Toolbar -->
    <header class="report-toolbar">
      <div class="toolbar-title">
        <span></span>
        SurfaceDrift Continuous Threat Exposure Assessment
      </div>
      <div class="toolbar-actions">
        <button class="btn btn-primary" onclick="window.print()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="6 9 6 2 18 2 18 9"></polyline>
            <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path>
            <rect x="6" y="14" width="12" height="8"></rect>
          </svg>
          Print / Save PDF
        </button>
        <a class="btn btn-secondary" href="surfacedrift_advanced_report.json" download="surfacedrift-{_escape(target)}-raw.json">
          Download JSON
        </a>
      </div>
    </header>

    <!-- Header Banner -->
    <div class="report-header">
      <div class="header-topline">
        <span class="classification-tag">CONFIDENTIAL // SECURITY AUDIT</span>
        <span class="meta-time">Generated: {_escape(gen_time)}</span>
      </div>
      <h1 class="report-title">Attack Surface &amp; CTEM Assessment Report</h1>
      <p class="report-subtitle">Multi-Vector External Perimeter Mapping, Deep Exposure Probing &amp; Remediation Playbooks</p>

      <div class="report-meta-grid">
        <div class="meta-cell">
          <strong>Target Perimeter</strong>
          <span><code>{_escape(target)}</code></span>
        </div>
        <div class="meta-cell">
          <strong>Assessment ID</strong>
          <span><code>{_escape(scan_id)}</code></span>
        </div>
        <div class="meta-cell">
          <strong>Audit Scope</strong>
          <span>Passive OSINT Recon + Phase 2 Deep Probing</span>
        </div>
        <div class="meta-cell">
          <strong>Compliance Standards</strong>
          <span>MITRE ATT&amp;CK, CISA KEV, FIRST EPSS</span>
        </div>
      </div>
    </div>

    <!-- Posture Card -->
    <div class="posture-card">
      <div class="posture-score-box">
        <div class="grade-badge">{grade}</div>
        <div class="score-ratio">{score} / 100</div>
        <div class="posture-label">{status_label}</div>
      </div>
      <div class="posture-narrative">
        <div class="narrative-title">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon>
          </svg>
          Executive Threat Exposure Summary
        </div>
        <div class="narrative-body">
          {formatted_ai_summary}
        </div>

        {f'''
        <div style="margin-top: 14px;">
          <strong style="font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-family: var(--font-mono);">Deductions Breakdown:</strong>
          <div class="deductions-list">
            {"".join(f'<div class="deduction-row"><span>{_escape(d.get("category"))}: {_escape(d.get("description"))}</span><strong>-{d.get("deduction", 0)} pts</strong></div>' for d in breakdown)}
          </div>
        </div>
        ''' if breakdown else ''}
      </div>
    </div>

    <!-- Key Metrics Grid -->
    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-value">{len(subdomains)}</div>
        <div class="metric-label">Subdomains Discovered</div>
      </div>
      <div class="metric-card">
        <div class="metric-value">{live_count}</div>
        <div class="metric-label">Live HTTP/S Services</div>
      </div>
      <div class="metric-card">
        <div class="metric-value">{len(ip_records)}</div>
        <div class="metric-label">Target IPv4 Addresses</div>
      </div>
      <div class="metric-card { 'metric-alert' if takeovers else '' }">
        <div class="metric-value">{len(takeovers)}</div>
        <div class="metric-label">CNAME Takeovers</div>
      </div>
      <div class="metric-card { 'metric-alert' if cloud_buckets else '' }">
        <div class="metric-value">{len(cloud_buckets)}</div>
        <div class="metric-label">Cloud Storage Buckets</div>
      </div>
      <div class="metric-card { 'metric-alert' if js_secrets else '' }">
        <div class="metric-value">{len(js_secrets)}</div>
        <div class="metric-label">Exposed JS Secrets</div>
      </div>
      <div class="metric-card { 'metric-alert' if shadow_apis else '' }">
        <div class="metric-value">{len(shadow_apis)}</div>
        <div class="metric-label">Shadow API Endpoints</div>
      </div>
      <div class="metric-card { 'metric-alert' if exposed_cfgs else '' }">
        <div class="metric-value">{len(exposed_cfgs)}</div>
        <div class="metric-label">Sensitive Config Files</div>
      </div>
      <div class="metric-card { 'metric-alert' if waf_bypasses else '' }">
        <div class="metric-value">{len(waf_bypasses)}</div>
        <div class="metric-label">WAF Origin Bypasses</div>
      </div>
      <div class="metric-card { 'metric-alert' if breach_identities else '' }">
        <div class="metric-value">{len(breach_identities)}</div>
        <div class="metric-label">Breached Identity Leaks</div>
      </div>
    </div>

    <!-- Section: 15 Deep Exposure Findings -->
    <div class="section-card">
      <div class="section-header">
        <div class="section-title">
          1. High-Priority Deep Exposure Findings (Phase 2 Probing)
        </div>
        <span class="section-badge">15 Audited Modules</span>
      </div>

      <!-- Subdomain Takeovers -->
      <div class="finding-item">
        <div class="finding-top">
          <span class="finding-title">Subdomain Takeover &amp; Orphaned CNAMEs</span>
          <span class="badge { 'badge-critical' if takeovers else 'badge-ok' }">{len(takeovers)} Detected</span>
        </div>
        <p class="finding-desc">
          Audits DNS CNAME records pointing to decommissioned third-party cloud services (AWS S3, GitHub Pages, Heroku, Azure, etc.) that can be claimed by unauthorized actors.
        </p>
        {f'''<div class="table-responsive"><table><thead><tr><th>Subdomain</th><th>CNAME Target</th><th>Cloud Provider</th><th>Severity</th></tr></thead><tbody>
        {"".join(f'<tr><td><code>{_escape(t.get("subdomain"))}</code></td><td>{_escape(t.get("cname"))}</td><td>{_escape(t.get("provider", "Unknown"))}</td><td><span class="badge badge-critical">{_escape(t.get("severity", "CRITICAL"))}</span></td></tr>' for t in takeovers)}
        </tbody></table></div>''' if takeovers else '<p class="empty-state">✓ No dangling CNAME records detected on scanned subdomains.</p>'}
      </div>

      <!-- Public Cloud Buckets -->
      <div class="finding-item">
        <div class="finding-top">
          <span class="finding-title">Public Cloud Storage Buckets (S3, Azure, GCP)</span>
          <span class="badge { 'badge-critical' if cloud_buckets else 'badge-ok' }">{len(cloud_buckets)} Buckets</span>
        </div>
        <p class="finding-desc">
          Tests brand permutations across Amazon S3, Google Cloud Storage, and Azure Blob containers for unauthenticated public listing and file access.
        </p>
        {f'''<div class="table-responsive"><table><thead><tr><th>Bucket Name</th><th>Provider</th><th>Access Level</th><th>Status</th></tr></thead><tbody>
        {"".join(f'<tr><td><code>{_escape(b.get("name"))}</code></td><td>{_escape(b.get("provider", "S3"))}</td><td><span class="badge { "badge-critical" if b.get("is_dangerous") else "badge-info" }">{_escape(b.get("access_level", "PUBLIC"))}</span></td><td>{_escape(b.get("url", ""))}</td></tr>' for b in cloud_buckets)}
        </tbody></table></div>''' if cloud_buckets else '<p class="empty-state">✓ No unprotected public cloud buckets detected for target permutations.</p>'}
      </div>

      <!-- JavaScript Secrets & API Keys -->
      <div class="finding-item">
        <div class="finding-top">
          <span class="finding-title">Exposed JavaScript Secrets &amp; API Keys</span>
          <span class="badge { 'badge-high' if js_secrets else 'badge-ok' }">{len(js_secrets)} Secrets</span>
        </div>
        <p class="finding-desc">
          Extracts client-side JavaScript bundles to identify high-entropy cryptographic keys, AWS access secrets, Stripe/OpenAI tokens, and private database credentials.
        </p>
        {f'''<div class="table-responsive"><table><thead><tr><th>File Location</th><th>Secret Type</th><th>Preview / Fingerprint</th><th>Severity</th></tr></thead><tbody>
        {"".join(f'<tr><td><code>{_escape(s.get("file_url"))}</code></td><td>{_escape(s.get("secret_type"))}</td><td><code>{_escape(s.get("preview"))}</code></td><td><span class="badge badge-high">{_escape(s.get("severity", "HIGH"))}</span></td></tr>' for s in js_secrets)}
        </tbody></table></div>''' if js_secrets else '<p class="empty-state">✓ No high-entropy API keys or credentials found in probed client scripts.</p>'}
      </div>

      <!-- Shadow APIs & Swagger -->
      <div class="finding-item">
        <div class="finding-top">
          <span class="finding-title">Shadow APIs, OpenAPI &amp; GraphQL Introspection</span>
          <span class="badge { 'badge-med' if shadow_apis else 'badge-ok' }">{len(shadow_apis)} Endpoints</span>
        </div>
        <p class="finding-desc">
          Discovers unauthenticated API documentation, Swagger/OpenAPI endpoints, and enabled GraphQL schemas that expose internal system endpoints to the public.
        </p>
        {f'''<div class="table-responsive"><table><thead><tr><th>Endpoint URL</th><th>Type</th><th>Status Code</th></tr></thead><tbody>
        {"".join(f'<tr><td><code>{_escape(a.get("url"))}</code></td><td>{_escape(a.get("type", "REST"))}</td><td><code>{_escape(a.get("status_code", 200))}</code></td></tr>' for a in shadow_apis)}
        </tbody></table></div>''' if shadow_apis else '<p class="empty-state">✓ No unauthenticated shadow APIs or exposed documentation interfaces found.</p>'}
      </div>

      <!-- Sensitive Exposed Configs -->
      <div class="finding-item">
        <div class="finding-top">
          <span class="finding-title">Exposed Configurations &amp; Environment Files</span>
          <span class="badge { 'badge-critical' if exposed_cfgs else 'badge-ok' }">{len(exposed_cfgs)} Files</span>
        </div>
        <p class="finding-desc">
          Probes web roots for sensitive configuration repositories including <code>/.env</code>, <code>/.git/config</code>, <code>/docker-compose.yml</code>, and server backups.
        </p>
        {f'''<div class="table-responsive"><table><thead><tr><th>Exposed URL</th><th>File Type</th><th>Status Code</th></tr></thead><tbody>
        {"".join(f'<tr><td><code>{_escape(c.get("url"))}</code></td><td>{_escape(c.get("file_type"))}</td><td><code>{_escape(c.get("status_code", 200))}</code></td></tr>' for c in exposed_cfgs)}
        </tbody></table></div>''' if exposed_cfgs else '<p class="empty-state">✓ No publicly accessible environment files, git repositories, or backups found.</p>'}
      </div>

      <!-- WAF Origin Bypass -->
      <div class="finding-item">
        <div class="finding-top">
          <span class="finding-title">WAF Bypass &amp; Direct Backend Origin Exposure</span>
          <span class="badge { 'badge-high' if waf_bypasses else 'badge-ok' }">{len(waf_bypasses)} Origins</span>
        </div>
        <p class="finding-desc">
          Identifies direct backend IP addresses that respond to HTTP Host header spoofing, allowing adversaries to circumvent Cloudflare, AWS CloudFront, or Akamai WAF protections.
        </p>
        {f'''<div class="table-responsive"><table><thead><tr><th>Origin IP</th><th>Confidence Score</th><th>Verification Evidence</th></tr></thead><tbody>
        {"".join(f'<tr><td><code>{_escape(w.get("ip"))}</code></td><td>{_escape(w.get("score", "High"))}%</td><td>{_escape(w.get("evidence", "HTTP Host match"))}</td></tr>' for w in waf_bypasses)}
        </tbody></table></div>''' if waf_bypasses else '<p class="empty-state">✓ All web traffic appears properly shielded behind edge proxy and WAF layers.</p>'}
      </div>

      <!-- Weaponized Vulnerabilities (KEV & EPSS) -->
      <div class="finding-item">
        <div class="finding-top">
          <span class="finding-title">Threat Prioritization (CISA KEV &amp; FIRST EPSS)</span>
          <span class="badge { 'badge-critical' if threat_vulns else 'badge-ok' }">{len(threat_vulns)} Weaponized CVEs</span>
        </div>
        <p class="finding-desc">
          Cross-references detected services against real-time FIRST.org Exploit Prediction Scoring (EPSS) and CISA's Known Exploited Vulnerabilities catalog.
        </p>
        {f'''<div class="table-responsive"><table><thead><tr><th>CVE ID</th><th>EPSS Score</th><th>CISA KEV</th><th>Severity</th></tr></thead><tbody>
        {"".join(f'<tr><td><code>{_escape(v.get("cve"))}</code></td><td>{_escape(v.get("epss_score", 0))}%</td><td><span class="badge { "badge-critical" if v.get("cisa_kev") else "badge-info" }">{ "YES" if v.get("cisa_kev") else "NO" }</span></td><td><span class="badge badge-critical">{_escape(v.get("severity", "HIGH"))}</span></td></tr>' for v in threat_vulns)}
        </tbody></table></div>''' if threat_vulns else '<p class="empty-state">✓ No known actively exploited or high-EPSS CVEs correlated with perimeter banners.</p>'}
      </div>

      <!-- Email Security (SPF & DMARC) -->
      <div class="finding-item">
        <div class="finding-top">
          <span class="finding-title">Email Spoofing Radar (RFC 7208 SPF &amp; RFC 7489 DMARC)</span>
          <span class="badge { 'badge-high' if email_sec.get('spoofable') or email_sec.get('is_spoofable') else 'badge-ok' }">{ "SPOOFABLE" if email_sec.get("spoofable") or email_sec.get("is_spoofable") else "ENFORCED" }</span>
        </div>
        <p class="finding-desc">
          Evaluates domain mail exchanger policies to prevent fraudulent spearphishing and CEO fraud under <code>@{_escape(target)}</code>.
        </p>
        <div class="finding-code">SPF Status: {_escape(email_sec.get("spf_status") or email_sec.get("spf", "Not Configured"))}
DMARC Policy: {_escape(email_sec.get("dmarc_status") or email_sec.get("dmarc", "Not Configured"))}
Spoofing Feasibility: {"HIGH RISK — Domain can be forged due to missing or permissive (~all) enforcement." if email_sec.get("spoofable") or email_sec.get("is_spoofable") else "PROTECTED — Strict rejection or quarantine policies configured."}</div>
      </div>

      <!-- Identity Breach & Credential Leaks -->
      <div class="finding-item">
        <div class="finding-top">
          <span class="finding-title">Identity Breach &amp; Credential Leaks</span>
          <span class="badge { 'badge-high' if breach_identities else 'badge-ok' }">{len(breach_identities)} Leaked Accounts</span>
        </div>
        <p class="finding-desc">
          Checks organizational employee email addresses against public breach disclosures and password dumps to defend against credential stuffing.
        </p>
        {f'''<div class="table-responsive"><table><thead><tr><th>Employee Email</th><th>Breaches Identified</th></tr></thead><tbody>
        {"".join(f'<tr><td><code>{_escape(i.get("email"))}</code></td><td>{_escape(", ".join(i.get("breach_names", [])) or "Public Data Dump")}</td></tr>' for i in breach_identities)}
        </tbody></table></div>''' if breach_identities else '<p class="empty-state">✓ No corporate identities detected in recent major public breach databases.</p>'}
      </div>

      <!-- Typosquatting Radar -->
      <div class="finding-item">
        <div class="finding-top">
          <span class="finding-title">Brand Protection &amp; Typosquatting Phishing Radar</span>
          <span class="badge { 'badge-high' if typosquats else 'badge-ok' }">{len(typosquats)} Active Squats</span>
        </div>
        <p class="finding-desc">
          Monitors lookalike homoglyphs, omitted characters, and bitsquatting domains that have active mailservers (MX) configured for customer impersonation.
        </p>
        {f'''<div class="table-responsive"><table><thead><tr><th>Lookalike Domain</th><th>MX Server Configured</th><th>Threat Classification</th></tr></thead><tbody>
        {"".join(f'<tr><td><code>{_escape(sq.get("domain"))}</code></td><td>{"YES" if sq.get("has_mx") else "NO"}</td><td><span class="badge { "badge-critical" if sq.get("threat_level") == "WEAPONIZED_PHISHING" else "badge-med" }">{_escape(sq.get("threat_level", "SUSPICIOUS"))}</span></td></tr>' for sq in typosquats)}
        </tbody></table></div>''' if typosquats else '<p class="empty-state">✓ No weaponized lookalike domains with active mail exchangers detected.</p>'}
      </div>
    </div>

    <!-- Section: MITRE ATT&CK Matrix -->
    {f'''
    <div class="section-card">
      <div class="section-header">
        <div class="section-title">
          2. MITRE ATT&amp;CK Enterprise Matrix Alignment
        </div>
        <span class="section-badge">{mitre_data.get("summary", {}).get("techniques_with_findings", 0)} Techniques Active</span>
      </div>
      <p class="finding-desc" style="margin-bottom: 14px;">
        Maps perimeter security exposures to standard adversary tactics and techniques documented in the MITRE ATT&amp;CK Enterprise knowledge base.
      </p>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>Tactic</th>
              <th>Technique ID</th>
              <th>Technique Name</th>
              <th>Observed Evidence</th>
            </tr>
          </thead>
          <tbody>
            {"".join(
              f'<tr><td><code>{_escape(tac.get("name", t_id))}</code></td><td><code>{_escape(tech.get("id"))}</code></td><td>{_escape(tech.get("name"))}</td><td>{_escape(", ".join(tech.get("evidence", [])) or "Threat indicator confirmed")}</td></tr>'
              for t_id, tac in (mitre_data.get("tactics") or {}).items()
              for tech in tac.get("techniques", [])
              if tech.get("findings_count", 0) > 0 or tech.get("active")
            ) or '<tr><td colspan="4" class="empty-state">✓ Zero MITRE techniques triggered by active findings.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
    ''' if mitre_data else ''}

    <!-- Section: Attack Surface Recon Inventory -->
    <div class="section-card">
      <div class="section-header">
        <div class="section-title">
          3. Attack Surface Inventory (Phase 1 Baseline)
        </div>
        <span class="section-badge">{len(subdomains)} Subdomains / {len(ip_records)} Hosts</span>
      </div>

      <!-- Live Hosts Table -->
      <h4 style="margin: 14px 0 8px; color: #ffffff; font-size: 13px;">Live Probed HTTP/HTTPS Services ({len(live_hosts)})</h4>
      <div class="table-responsive" style="max-height: 320px; overflow-y: auto;">
        <table>
          <thead>
            <tr>
              <th>Endpoint URL</th>
              <th>Status</th>
              <th>Page Title</th>
              <th>Web Server</th>
              <th>Tech Stack</th>
            </tr>
          </thead>
          <tbody>
            {"".join(
              f'<tr><td><code>{_escape(h.get("url"))}</code></td><td><span class="badge { "badge-ok" if h.get("status_code", 0) == 200 else "badge-info" }">{_escape(h.get("status_code", 200))}</span></td><td>{_escape(h.get("title") or "—")}</td><td>{_escape(h.get("server") or "—")}</td><td>{_escape(", ".join(h.get("tech_stack", [])) or "—")}</td></tr>'
              for h in live_hosts
            ) or '<tr><td colspan="5" class="empty-state">No live HTTP services found.</td></tr>'}
          </tbody>
        </table>
      </div>

      <!-- Discovered IP Addresses -->
      <h4 style="margin: 20px 0 8px; color: #ffffff; font-size: 13px;">Target IP Addresses &amp; Open Ports ({len(ip_records)})</h4>
      <div class="table-responsive" style="max-height: 320px; overflow-y: auto;">
        <table>
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Open Ports</th>
              <th>ASN / Network</th>
              <th>Location</th>
              <th>Vulnerabilities</th>
            </tr>
          </thead>
          <tbody>
            {"".join(
              f'<tr><td><code>{_escape(r.get("ip"))}</code></td><td><code>{_escape(r.get("ports_raw") or ", ".join(r.get("ports", [])) or "—")}</code></td><td>{_escape(r.get("asn") or "")} {_escape(r.get("asn_description") or "")}</td><td>{_escape(r.get("location") or "—")}</td><td>{_escape(r.get("vulnerabilities_raw") or ", ".join(r.get("vulnerabilities", [])) or "None detected")}</td></tr>'
              for r in ip_records
            ) or '<tr><td colspan="5" class="empty-state">No IP records cataloged.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Section: SecOps Remediation Playbooks -->
    <div class="section-card">
      <div class="section-header">
        <div class="section-title">
          4. Prioritized SecOps Remediation Action Plan
        </div>
        <span class="section-badge">{len(remediation_playbooks)} Actionable Playbooks</span>
      </div>
      <p class="finding-desc" style="margin-bottom: 16px;">
        Production-ready hardening commands and policy snippets to eliminate identified exposures. Apply in order of severity.
      </p>

      {f'''
      {"".join(
        f'<div class="playbook-card { "crit" if p.get("severity") == "CRITICAL" else ("high" if p.get("severity") == "HIGH" else "") }">'
        f'<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">'
        f'<strong style="color: #ffffff; font-size: 13px;">{_escape(p.get("title"))}</strong>'
        f'<span class="badge { "badge-critical" if p.get("severity") == "CRITICAL" else "badge-high" }">{_escape(p.get("severity", "CRITICAL"))}</span>'
        f'</div>'
        f'<p style="color: var(--text-muted); font-size: 12px; margin-bottom: 8px;">{_escape(p.get("playbook"))}</p>'
        f'<div class="finding-code">{_escape(p.get("code_snippet") or p.get("code") or "")}</div>'
        f'</div>'
        for p in remediation_playbooks
      )}
      ''' if remediation_playbooks else '<p class="empty-state">✓ Zero critical vulnerabilities require immediate remediation playbooks.</p>'}
    </div>

    <!-- Footer -->
    <footer class="report-footer">
      <div>
        SurfaceDrift Threat Exposure Engine v2.0 &bull; Automated Defense Assessment
      </div>
      <div>
        Target: {_escape(target)} &bull; Scan ID: {_escape(scan_id)}
      </div>
    </footer>
  </div>
</body>
</html>
"""


def generate_markdown_report(
    target: str,
    scan_id: str,
    summary: Optional[Dict[str, Any]] = None,
    advanced: Optional[Dict[str, Any]] = None,
    generated_at: Optional[str] = None,
) -> str:
    """
    Generate a comprehensive, structured Markdown assessment report.
    """
    summary = summary or {}
    advanced = advanced or {}
    gen_time = generated_at or _now_str()

    posture = advanced.get("posture") or {}
    score = posture.get("score", 100)
    grade = (posture.get("grade") or "A").upper()
    breakdown = posture.get("breakdown") or []

    sections = summary.get("sections") or {}
    subdomains = sections.get("subdomains") or []
    ip_records = sections.get("ip_records") or []

    findings = advanced.get("findings") or {}
    http_probes = findings.get("http_probing") or {}
    live_hosts = [h for h in (http_probes.get("results") or []) if h.get("is_live")]

    takeovers = (findings.get("subdomain_takeovers") or {}).get("items") or []
    cloud_buckets = (findings.get("cloud_storage") or {}).get("buckets") or []
    waf_bypasses = (findings.get("waf_bypass") or {}).get("origins") or []
    threat_vulns = (findings.get("threat_prioritization") or {}).get("cves") or []
    email_sec = findings.get("email_security") or sections.get("email_security") or {}
    js_secrets = (findings.get("js_secrets") or {}).get("findings") or []
    shadow_apis = (findings.get("shadow_apis") or {}).get("endpoints") or []
    exposed_cfgs = (findings.get("exposed_configs") or {}).get("exposed_files") or []
    breach_identities = (findings.get("breach_intel") or {}).get("breached_identities") or []
    typosquats = (findings.get("typosquatting") or {}).get("active_squats") or []
    remediation_playbooks = findings.get("remediation_playbooks") or advanced.get("remediation") or []
    mitre_data = advanced.get("mitre_attack") or {}

    ai_content = (advanced.get("ai_executive_summary") or {}).get("content") or ""

    status_label = "Optimal" if grade == "A" else ("Moderate Risk" if grade in ("B", "C") else "Elevated Critical Exposure")

    lines = [
        f"# SurfaceDrift Security Assessment Report: `{target}`",
        "",
        f"**Generated:** `{gen_time}`  ",
        f"**Assessment ID:** `{scan_id}`  ",
        f"**Audit Classification:** `CONFIDENTIAL // CTEM AUDIT`  ",
        "",
        "---",
        "",
        "## 1. Executive Summary & Exposure Posture",
        "",
        f"- **Exposure Score:** `{score} / 100`",
        f"- **Posture Grade:** **Grade {grade}** (*{status_label}*)",
        f"- **Audited Scope:** Discovered `{len(subdomains)}` subdomains, `{len(live_hosts)}` live HTTP endpoints, and `{len(ip_records)}` IPv4 assets.",
        "",
    ]

    if ai_content:
        lines.append("### Executive Threat Narrative")
        lines.append(ai_content.strip())
        lines.append("")

    if breakdown:
        lines.append("### Posture Deductions")
        lines.append("| Category | Penalty | Reason |")
        lines.append("|---|---|---|")
        for b in breakdown:
            lines.append(f"| {b.get('category')} | `-{b.get('deduction')} pts` | {b.get('description')} |")
        lines.append("")

    lines.extend([
        "---",
        "",
        "## 2. Key Threat & Exposure Metrics",
        "",
        "| Metric | Count / Status | Severity |",
        "|---|---|---|",
        f"| Discovered Subdomains | `{len(subdomains)}` | Baseline |",
        f"| Live HTTP Services | `{len(live_hosts)}` | Baseline |",
        f"| Public IPv4 Addresses | `{len(ip_records)}` | Baseline |",
        f"| CNAME Subdomain Takeovers | `{len(takeovers)}` | {'CRITICAL' if takeovers else 'OPTIMAL'} |",
        f"| Exposed Cloud Buckets (S3/Azure/GCP) | `{len(cloud_buckets)}` | {'CRITICAL' if cloud_buckets else 'OPTIMAL'} |",
        f"| High-Entropy JS API Keys | `{len(js_secrets)}` | {'HIGH' if js_secrets else 'OPTIMAL'} |",
        f"| Shadow APIs / Swagger Endpoints | `{len(shadow_apis)}` | {'MEDIUM' if shadow_apis else 'OPTIMAL'} |",
        f"| Exposed Configs (`.env`/`.git`) | `{len(exposed_cfgs)}` | {'CRITICAL' if exposed_cfgs else 'OPTIMAL'} |",
        f"| WAF Bypass Direct Origin IPs | `{len(waf_bypasses)}` | {'HIGH' if waf_bypasses else 'OPTIMAL'} |",
        f"| Weaponized CVEs (KEV/EPSS) | `{len(threat_vulns)}` | {'CRITICAL' if threat_vulns else 'OPTIMAL'} |",
        f"| Email Spoofing Posture | `{'SPOOFABLE' if email_sec.get('spoofable') or email_sec.get('is_spoofable') else 'PROTECTED'}` | {'HIGH' if email_sec.get('spoofable') or email_sec.get('is_spoofable') else 'OPTIMAL'} |",
        f"| Breached Identity Accounts | `{len(breach_identities)}` | {'HIGH' if breach_identities else 'OPTIMAL'} |",
        f"| Lookalike Typosquatting Domains | `{len(typosquats)}` | {'HIGH' if typosquats else 'OPTIMAL'} |",
        "",
        "---",
        "",
        "## 3. Deep Vulnerability & Probing Findings",
        "",
    ])

    # Takeovers
    lines.append("### 3.1 Subdomain Takeovers")
    if takeovers:
        lines.append("| Subdomain | CNAME Target | Cloud Provider | Severity |")
        lines.append("|---|---|---|---|")
        for t in takeovers:
            lines.append(f"| `{t.get('subdomain')}` | `{t.get('cname')}` | {t.get('provider')} | **{t.get('severity', 'CRITICAL')}** |")
    else:
        lines.append("✓ Zero dangling CNAME records detected.")
    lines.append("")

    # Buckets
    lines.append("### 3.2 Cloud Storage Audit")
    if cloud_buckets:
        lines.append("| Bucket Name | Provider | Access Level | URL |")
        lines.append("|---|---|---|---|")
        for b in cloud_buckets:
            lines.append(f"| `{b.get('name')}` | {b.get('provider')} | **{b.get('access_level')}** | {b.get('url')} |")
    else:
        lines.append("✓ Zero open or public cloud storage buckets detected.")
    lines.append("")

    # JS Secrets
    lines.append("### 3.3 Client-Side JavaScript Secrets")
    if js_secrets:
        lines.append("| Location | Secret Type | Preview | Severity |")
        lines.append("|---|---|---|---|")
        for s in js_secrets:
            lines.append(f"| `{s.get('file_url')}` | {s.get('secret_type')} | `{s.get('preview')}` | **{s.get('severity', 'HIGH')}** |")
    else:
        lines.append("✓ Zero hardcoded credentials or API keys found in client bundles.")
    lines.append("")

    # Shadow APIs
    lines.append("### 3.4 Shadow APIs & Documentation")
    if shadow_apis:
        lines.append("| Endpoint | Type | Status Code |")
        lines.append("|---|---|---|")
        for a in shadow_apis:
            lines.append(f"| `{a.get('url')}` | {a.get('type')} | `{a.get('status_code')}` |")
    else:
        lines.append("✓ Zero shadow API specs or documentation roots discovered.")
    lines.append("")

    # Exposed Configs
    lines.append("### 3.5 Sensitive Environment & Backup Files")
    if exposed_cfgs:
        lines.append("| URL | File Type | Status Code |")
        lines.append("|---|---|---|")
        for c in exposed_cfgs:
            lines.append(f"| `{c.get('url')}` | `{c.get('file_type')}` | `{c.get('status_code')}` |")
    else:
        lines.append("✓ Zero exposed `.env`, `.git`, or backup files accessible over HTTP.")
    lines.append("")

    # WAF Bypass
    lines.append("### 3.6 WAF Origin IP Bypasses")
    if waf_bypasses:
        lines.append("| Origin IP | Confidence Score | Evidence |")
        lines.append("|---|---|---|")
        for w in waf_bypasses:
            lines.append(f"| `{w.get('ip')}` | {w.get('score')}% | {w.get('evidence')} |")
    else:
        lines.append("✓ All inbound HTTP/S requests properly filtered through reverse-proxy/WAF.")
    lines.append("")

    # MITRE Matrix
    if mitre_data:
        lines.extend([
            "---",
            "",
            "## 4. MITRE ATT&CK Enterprise Matrix Mapping",
            "",
            "| Tactic | Technique ID | Technique Name | Evidence |",
            "|---|---|---|---|",
        ])
        tactics = mitre_data.get("tactics") or {}
        has_any = False
        for t_id, tac in tactics.items():
            for tech in tac.get("techniques", []):
                if tech.get("findings_count", 0) > 0 or tech.get("active"):
                    has_any = True
                    lines.append(f"| {tac.get('name', t_id)} | `{tech.get('id')}` | {tech.get('name')} | {', '.join(tech.get('evidence', []))} |")
        if not has_any:
            lines.append("| — | — | No techniques triggered | None |")
        lines.append("")

    # Remediation Playbooks
    lines.extend([
        "---",
        "",
        "## 5. Prioritized SecOps Remediation Playbooks",
        "",
    ])
    if remediation_playbooks:
        for p in remediation_playbooks:
            lines.extend([
                f"### [{p.get('severity', 'CRITICAL')}] {p.get('title')}",
                f"**Playbook Description:** {p.get('playbook')}",
                "",
                "```bash",
                f"{p.get('code_snippet') or p.get('code') or ''}".strip(),
                "```",
                "",
            ])
    else:
        lines.append("✓ No immediate remediation playbooks needed.")
        lines.append("")

    lines.extend([
        "---",
        f"*Report synthesized by SurfaceDrift CTEM Platform &bull; Assessment ID: {scan_id}*",
        "",
    ])

    return "\n".join(lines)


async def generate_pdf_report(
    target: str,
    scan_id: str,
    summary: Optional[Dict[str, Any]] = None,
    advanced: Optional[Dict[str, Any]] = None,
    html_content: Optional[str] = None,
) -> Optional[bytes]:
    """
    Generate a pixel-perfect PDF report matching the HTML preview styling using Playwright.
    """
    if html_content is None:
        html_content = generate_html_report(target, scan_id, summary, advanced)

    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(args=["--no-sandbox", "--disable-setuid-sandbox"])
            page = await browser.new_page()
            await page.emulate_media(media="screen")
            await page.set_content(html_content, wait_until="networkidle")
            await page.add_style_tag(content=".report-toolbar { display: none !important; }")
            pdf_bytes = await page.pdf(
                format="A4",
                print_background=True,
                margin={"top": "10mm", "bottom": "10mm", "left": "10mm", "right": "10mm"}
            )
            await browser.close()
            return pdf_bytes
    except Exception as e:
        logger.warning("Playwright async PDF generation failed: %s", e)
        return None


def generate_pdf_report_sync(
    target: str,
    scan_id: str,
    summary: Optional[Dict[str, Any]] = None,
    advanced: Optional[Dict[str, Any]] = None,
    html_content: Optional[str] = None,
) -> Optional[bytes]:
    """
    Synchronously generate PDF report using Playwright.
    """
    if html_content is None:
        html_content = generate_html_report(target, scan_id, summary, advanced)

    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox", "--disable-setuid-sandbox"])
            page = browser.new_page()
            page.emulate_media(media="screen")
            page.set_content(html_content, wait_until="networkidle")
            page.add_style_tag(content=".report-toolbar { display: none !important; }")
            pdf_bytes = page.pdf(
                format="A4",
                print_background=True,
                margin={"top": "10mm", "bottom": "10mm", "left": "10mm", "right": "10mm"}
            )
            browser.close()
            return pdf_bytes
    except Exception as e:
        logger.warning("Playwright sync PDF generation failed: %s", e)
        return None
