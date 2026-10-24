from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


def _load_candidate_keys() -> List[str]:
    """Load Gemini API keys from environment or local keylist without exposing secrets."""
    keys: List[str] = []
    for var in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GEMINI_TOKEN"):
        val = os.getenv(var, "").strip()
        if val and val not in keys:
            keys.append(val)

    # Check keylist.asm in project root and parent directories
    for candidate_dir in [
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    ]:
        keyfile = os.path.join(candidate_dir, "keylist.asm")
        if os.path.isfile(keyfile):
            try:
                with open(keyfile, "r", encoding="utf-8") as f:
                    for line in f:
                        clean = line.strip()
                        if clean.startswith(("gemini", "Gemini", "GEMINI_API_KEY")):
                            parts = clean.split("=", 1) if "=" in clean else clean.split(":", 1)
                            if len(parts) == 2:
                                token = parts[1].strip().strip('"').strip("'")
                                if token and token not in keys:
                                    keys.append(token)
            except Exception:
                pass
    return keys


GEMINI_ENDPOINTS = [
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",
]


def call_gemini_api(prompt: str) -> Optional[str]:
    """Attempt calling Google Gemini API using candidate keys."""
    keys = _load_candidate_keys()
    if not keys:
        return None

    headers_payload = {"contents": [{"parts": [{"text": prompt}]}]}

    for key in keys:
        token = (key or "").strip()
        if not token:
            continue

        for endpoint in GEMINI_ENDPOINTS:
            # 1. Try URL query parameter key
            try:
                url = f"{endpoint}?key={token}"
                resp = requests.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json=headers_payload,
                    timeout=8,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        if text and len(text.strip()) > 50:
                            logger.info("Successfully generated summary via Gemini API (%s)", endpoint)
                            return text.strip()
            except Exception as e:
                logger.debug("Gemini query key attempt error: %s", e)

            # 2. Try Bearer token authorization header
            try:
                resp = requests.post(
                    endpoint,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {token}",
                    },
                    json=headers_payload,
                    timeout=8,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        if text and len(text.strip()) > 50:
                            logger.info("Successfully generated summary via Gemini Bearer auth (%s)", endpoint)
                            return text.strip()
            except Exception as e:
                logger.debug("Gemini bearer token attempt error: %s", e)

    return None


def generate_rule_based_executive_summary(
    target: str,
    score: int,
    grade: str,
    breakdown: List[Dict[str, Any]],
    subdomains_count: int,
    live_hosts_count: int,
    ips_count: int,
    takeovers: List[Dict[str, Any]],
    public_buckets: List[Dict[str, Any]],
    weaponized_vulns: List[Dict[str, Any]],
    waf_bypasses: List[Dict[str, Any]],
    email_sec: Dict[str, Any],
    breach_intel: Optional[Dict[str, Any]] = None,
    typosquatting: Optional[Dict[str, Any]] = None,
    exposed_configs: Optional[Dict[str, Any]] = None,
    shadow_apis: Optional[Dict[str, Any]] = None,
    js_secrets: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> str:
    """Generate an authoritative, complete executive threat assessment summary."""
    status_label = "Optimal" if grade == "A" else ("Moderate Risk" if grade in ("B", "C") else "Elevated Exposure")

    lines = [
        f"### Executive Threat Exposure Summary — `{target}`",
        "",
        f"**SurfaceDrift CTEM Posture Score:** `{score}/100` (Grade **{grade}** — *{status_label}*)",
        "",
        "#### 1. Strategic Exposure Overview",
        f"SurfaceDrift completed multi-vector perimeter mapping and continuous exposure validation for `{target}`. "
        f"The audited attack surface encompasses **{subdomains_count}** discovered subdomains "
        f"(with **{live_hosts_count}** actively responding HTTP/HTTPS endpoints) across **{ips_count}** public IPv4 addresses. "
        f"Overall exposure is rated as **Grade {grade}** reflecting {'no immediate critical exposures' if grade in ('A', 'B') else 'high-priority perimeter vulnerabilities requiring rapid remediation'}.",
        "",
    ]

    # 2. Key threat indicators
    critical_findings: List[str] = []

    if takeovers:
        critical_findings.append(
            f"**CRITICAL: Subdomain Takeover:** {len(takeovers)} dangling CNAME record(s) identified pointing to orphaned third-party cloud services. "
            f"Adversaries can claim these endpoints to serve arbitrary malicious payloads under `{target}`."
        )

    # Identity Breach
    breaches = (breach_intel or {}).get("breached_identities") or []
    if breaches:
        critical_findings.append(
            f"**IDENTITY BREACH RISK:** {len(breaches)} corporate employee account(s) exposed in historical public credential dumps. "
            f"Poses immediate risk for credential stuffing, password spraying, and unauthorized VPN/SaaS ingress."
        )

    # Brand Phishing / Typosquats
    squats = (typosquatting or {}).get("active_squats") or []
    phish_squats = [s for s in squats if s.get("threat_level") == "WEAPONIZED_PHISHING" or s.get("has_mx")]
    if phish_squats:
        critical_findings.append(
            f"**BRAND PHISHING RADAR:** {len(phish_squats)} active lookalike/typosquatted domain(s) configured with live mailservers (MX). "
            f"Adversaries can exploit these lookalike domains to stage deceptive spearphishing campaigns targeting customers and employees."
        )

    if public_buckets:
        dangerous_buckets = [b for b in public_buckets if b.get("is_dangerous") or b.get("access_level") in {"PUBLIC_READ", "PUBLIC_WRITE"}]
        count = len(dangerous_buckets) or len(public_buckets)
        critical_findings.append(
            f"**CLOUD STORAGE EXPOSURE:** {count} public cloud storage bucket(s) (AWS S3 / Azure / GCP) accessible without authentication, presenting direct data leakage risks."
        )

    if weaponized_vulns:
        critical_findings.append(
            f"**WEAPONIZED VULNERABILITIES:** {len(weaponized_vulns)} CVE(s) identified with elevated FIRST.org EPSS exploit probability or active CISA KEV exploitation."
        )

    if waf_bypasses:
        critical_findings.append(
            f"**WAF ORIGIN BYPASS:** {len(waf_bypasses)} direct backend origin IP(s) respond directly to requests, completely bypassing edge CDN and WAF security inspection."
        )

    # Exposed configs
    cfgs = (exposed_configs or {}).get("exposed_files") or []
    if cfgs:
        critical_findings.append(
            f"**EXPOSED CONFIGURATIONS:** {len(cfgs)} sensitive file(s) (`.env`, `.git/config`, or backup files) publicly readable over HTTP."
        )

    # Email Security
    spf_status = email_sec.get("spf_status", "NOT_FOUND")
    dmarc_status = email_sec.get("dmarc_status", "NOT_FOUND")
    spoofable = email_sec.get("spoofable", email_sec.get("is_spoofable", False))
    if spoofable:
        critical_findings.append(
            f"**EMAIL PHISHING RISK:** Domain email configuration lacks restrictive DMARC enforcement (SPF: `{spf_status}`, DMARC: `{dmarc_status}`). Attackers can forge emails as `@{target}` with high delivery success."
        )
    else:
        critical_findings.append(
            f"**EMAIL POSTURE ENFORCED:** Strict SPF (`{spf_status}`) and DMARC (`{dmarc_status}`) are enforced, preventing unauthenticated domain spoofing."
        )

    lines.append("#### 2. Key Threat & Exposure Indicators")
    for f in critical_findings:
        lines.append(f"- {f}")
    lines.append("")

    # 3. Deductions trail
    if breakdown:
        lines.append("#### 3. Posture Score Deductions")
        for item in breakdown:
            lines.append(f"- **[-{item.get('deduction', 0)} pts]** `{item.get('category')}`: {item.get('description')}")
        lines.append("")

    # 4. Recommendations Roadmap (Dynamic Sequential Numbering)
    lines.append("#### 4. Prioritized Remediation Roadmap")
    roadmap_items: List[str] = []

    if takeovers:
        roadmap_items.append("**Immediate (0–24h):** Reclaim or remove dangling DNS CNAME records to eliminate subdomain takeover vectors.")
    if public_buckets:
        roadmap_items.append("**Immediate (0–24h):** Enforce strict cloud storage bucket ACLs and disable public read/list permissions across cloud object stores.")
    if cfgs:
        roadmap_items.append("**Immediate (0–24h):** Remove or restrict access to exposed `.env`, `.git`, and archive backups from web roots.")
    if weaponized_vulns:
        roadmap_items.append("**High Priority (24–48h):** Patch or isolate assets exposed to known exploited CVEs and restrict administration ports.")
    if breaches:
        roadmap_items.append("**High Priority (24–48h):** Mandate password resets and enforce multi-factor authentication (MFA) for compromised corporate identities.")
    if phish_squats:
        roadmap_items.append("**Medium Priority (1–2 weeks):** Submit domain takedown requests or register defensive typosquats targeting active lookalike domains.")
    if waf_bypasses:
        roadmap_items.append("**Medium Priority (1–2 weeks):** Restrict origin server security groups to only accept traffic from designated CDN IP ranges.")
    if spoofable:
        roadmap_items.append("**Standard Baseline:** Upgrade DMARC policy from `p=none` to `p=quarantine` or `p=reject` to protect brand reputation against spoofing.")

    if not roadmap_items:
        roadmap_items.append("**Maintain Baseline:** Target shows strong perimeter hygiene with no immediate critical dangling endpoints. Maintain continuous exposure monitoring.")

    for idx, item in enumerate(roadmap_items, 1):
        lines.append(f"{idx}. {item}")

    lines.append("")
    lines.append("---")
    lines.append("*Generated by SurfaceDrift AI Synthesis Engine · Continuous Threat Exposure Management*")

    return "\n".join(lines)


def generate_executive_summary(
    target: str,
    score: int,
    grade: str,
    breakdown: List[Dict[str, Any]],
    subdomains_count: int,
    live_hosts_count: int,
    ips_count: int,
    takeovers: List[Dict[str, Any]],
    public_buckets: List[Dict[str, Any]],
    weaponized_vulns: List[Dict[str, Any]],
    waf_bypasses: List[Dict[str, Any]],
    email_sec: Dict[str, Any],
    breach_intel: Optional[Dict[str, Any]] = None,
    typosquatting: Optional[Dict[str, Any]] = None,
    exposed_configs: Optional[Dict[str, Any]] = None,
    shadow_apis: Optional[Dict[str, Any]] = None,
    js_secrets: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, str]:
    """
    Produce an executive summary using Gemini API if reachable,
    falling back to SurfaceDrift rule-based AI engine.
    """
    # 1. Prepare prompt for Gemini API
    prompt = f"""
You are an elite cybersecurity executive and red team threat exposure analyst.
Write an authoritative, complete Executive Threat Exposure & CTEM Summary in professional Markdown format for domain "{target}".

Scan Findings Data:
- Target Domain: {target}
- SurfaceDrift Score: {score}/100 (Grade: {grade})
- Subdomains Mapped: {subdomains_count} (Live HTTP hosts: {live_hosts_count})
- Public IP Addresses: {ips_count}
- Subdomain Takeover Vulnerabilities: {len(takeovers)} ({json.dumps(takeovers)})
- Cloud Buckets Leaked / Exposed: {len(public_buckets)} ({json.dumps(public_buckets)})
- Weaponized / CISA KEV CVEs: {len(weaponized_vulns)} ({json.dumps(weaponized_vulns)})
- WAF / CDN Origin Bypasses: {len(waf_bypasses)} ({json.dumps(waf_bypasses)})
- Email Security Posture: {json.dumps(email_sec)}
- Compromised Identities: {len((breach_intel or {}).get('breached_identities', []))}
- Active Typosquatting / Phishing Domains: {len((typosquatting or {}).get('active_squats', []))}
- Score Deductions: {json.dumps(breakdown)}

Structure your report into:
1. Executive Exposure Overview (score interpretation and posture)
2. Key Threat & Exposure Indicators (detailed bullet points for takeovers, breaches, phishing, and WAF bypass)
3. Posture Score Deductions
4. Prioritized Actionable Remediation Roadmap (numbered 1., 2., 3., with clear SLA timeframes)

Write clearly and authoritatively with bold highlights.
"""

    gemini_result = call_gemini_api(prompt)
    if gemini_result:
        return {
            "source": "gemini",
            "model": "Gemini 1.5 Flash",
            "content": gemini_result,
        }

    # Fallback to SurfaceDrift Rule-Based AI Engine
    local_summary = generate_rule_based_executive_summary(
        target=target,
        score=score,
        grade=grade,
        breakdown=breakdown,
        subdomains_count=subdomains_count,
        live_hosts_count=live_hosts_count,
        ips_count=ips_count,
        takeovers=takeovers,
        public_buckets=public_buckets,
        weaponized_vulns=weaponized_vulns,
        waf_bypasses=waf_bypasses,
        email_sec=email_sec,
        breach_intel=breach_intel,
        typosquatting=typosquatting,
        exposed_configs=exposed_configs,
        shadow_apis=shadow_apis,
        js_secrets=js_secrets,
    )
    return {
        "source": "surfacedrift-ai",
        "model": "SurfaceDrift Threat Synthesis AI",
        "content": local_summary,
    }
