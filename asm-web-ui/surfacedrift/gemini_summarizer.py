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

    # Check keylist.asm in project root
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

CANDIDATE_KEYS = _load_candidate_keys()

GEMINI_ENDPOINTS = [
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
    "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",
]


def call_gemini_api(prompt: str) -> Optional[str]:
    """Attempt calling Google Gemini API using candidate keys."""
    headers_payload = {"contents": [{"parts": [{"text": prompt}]}]}

    for key in CANDIDATE_KEYS:
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
                        if text:
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
                        if text:
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
) -> str:
    """Generate an authoritative, high-tier executive threat assessment summary."""
    status_label = "Optimal" if grade == "A" else ("Moderate Risk" if grade in ("B", "C") else "Elevated Exposure")

    lines = [
        f"### Executive Threat Exposure Summary — `{target}`",
        "",
        f"**SurfaceDrift CTEM Posture Score:** `{score}/100` (Grade **{grade}** — *{status_label}*)",
        "",
        "#### 1. Strategic Exposure Overview",
        f"SurfaceDrift completed multi-vector perimeter mapping and exposure validation for `{target}`. "
        f"The digital attack surface encompasses **{subdomains_count}** discovered subdomains "
        f"(with **{live_hosts_count}** actively responding HTTP/HTTPS endpoints) across **{ips_count}** public IPv4 addresses.",
        "",
    ]

    # Critical findings summary
    critical_findings: List[str] = []

    if takeovers:
        critical_findings.append(
            f"**CRITICAL:** {len(takeovers)} Subdomain Takeover vector(s) identified pointing to orphaned third-party services. "
            f"Attackers can register the dangling cloud endpoint to serve arbitrary malicious content under `{target}`."
        )

    if public_buckets:
        critical_findings.append(
            f"**HIGH EXPOSURE:** {len(public_buckets)} Cloud Storage bucket(s) detected with public access permissions, risking data leakage or unauthenticated tampering."
        )

    if weaponized_vulns:
        critical_findings.append(
            f"**CRITICAL VULNERABILITIES:** {len(weaponized_vulns)} actively weaponized or CISA KEV-catalogued CVE(s) identified on public-facing assets."
        )

    if waf_bypasses:
        critical_findings.append(
            f"**WAF BYPASS WARNING:** {len(waf_bypasses)} direct origin IP(s) discovered bypassing edge CDN/WAF defenses, enabling direct network-level attacks."
        )

    spf_status = email_sec.get("spf_status", "NOT_FOUND")
    dmarc_status = email_sec.get("dmarc_status", "NOT_FOUND")
    spoofable = email_sec.get("spoofable", False)

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

    # Deductions trail
    if breakdown:
        lines.append("#### 3. Posture Score Deductions")
        for item in breakdown:
            lines.append(f"- **[-{item.get('deduction', 0)} pts]** `{item.get('category')}`: {item.get('description')}")
        lines.append("")

    # Recommendations
    lines.append("#### 4. Prioritized Remediation Roadmap")
    if takeovers:
        lines.append("1. **Immediate (0-24h):** Reclaim or remove dangling DNS CNAME records to eliminate takeover vulnerability.")
    if public_buckets:
        lines.append("2. **Immediate (0-24h):** Enforce strict cloud storage bucket ACLs and disable public read/list permissions.")
    if weaponized_vulns:
        lines.append("3. **High Priority (24-48h):** Patch or isolate assets exposed to known exploited CVEs and restrict administration ports.")
    if waf_bypasses:
        lines.append("4. **Medium Priority (1-2 weeks):** Restrict origin server security groups to only accept traffic from designated CDN IP ranges.")
    if spoofable:
        lines.append("5. **Standard Baseline:** Upgrade DMARC policy from `p=none` to `p=quarantine` or `p=reject`.")

    if not (takeovers or public_buckets or weaponized_vulns or waf_bypasses or spoofable):
        lines.append("1. **Maintain Current Security Baseline:** Target shows strong baseline posture with no immediate critical dangling endpoints.")

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
) -> Dict[str, str]:
    """
    Produce an executive summary using Gemini API if reachable,
    falling back to SurfaceDrift rule-based AI engine.
    """
    # 1. Prepare prompt for Gemini API
    prompt = f"""
You are an elite cybersecurity executive and red team threat exposure analyst.
Write an authoritative, concise Executive Threat Exposure & CTEM Summary in professional Markdown format for domain "{target}".

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
- Score Deductions: {json.dumps(breakdown)}

Structure your report into:
1. Executive Exposure Overview (score interpretation and posture)
2. Critical Threat Vectors (subdomain takeovers, cloud leaks, weaponized CVEs)
3. Perimeter Defense Gaps (WAF bypasses, email spoofability)
4. Prioritized Actionable Remediation Roadmap (Immediate, Short-term, Long-term)

Use clear bullet points and bold highlights.
"""

    gemini_result = call_gemini_api(prompt)
    if gemini_result:
        return {
            "source": "gemini",
            "model": "Gemini 1.5 Flash",
            "content": gemini_result,
        }

    # Fallback to SurfaceDrift AI Synthesis Engine
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
    )
    return {
        "source": "surfacedrift-ai",
        "model": "SurfaceDrift Threat Synthesis AI",
        "content": local_summary,
    }
