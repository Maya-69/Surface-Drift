from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

# High-confidence Regex Patterns for credentials & tokens in JavaScript
SECRET_PATTERNS = [
    {
        "type": "AWS Access Key",
        "pattern": re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        "severity": "HIGH",
    },
    {
        "type": "Stripe Secret Key",
        "pattern": re.compile(r"sk_live_[0-9a-zA-Z]{24,32}"),
        "severity": "HIGH",
    },
    {
        "type": "Stripe Publishable Key",
        "pattern": re.compile(r"pk_live_[0-9a-zA-Z]{24,32}"),
        "severity": "LOW",
    },
    {
        "type": "Google API Key",
        "pattern": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "severity": "MED",
    },
    {
        "type": "Firebase Database URL",
        "pattern": re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"),
        "severity": "MED",
    },
    {
        "type": "Slack Webhook URL",
        "pattern": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
        "severity": "HIGH",
    },
    {
        "type": "GitHub Personal Token",
        "pattern": re.compile(r"gh[pous]_[0-9a-zA-Z]{36}"),
        "severity": "HIGH",
    },
    {
        "type": "Private RSA/EC Key Block",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "severity": "HIGH",
    },
]

SCRIPT_SRC_REGEX = re.compile(r"""<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)["']""", re.IGNORECASE)


def redact_secret(secret: str) -> str:
    """Mask secret token, leaving only leading/trailing identifiers."""
    if len(secret) <= 8:
        return secret[:2] + "****"
    return secret[:6] + "..." + secret[-4:]


async def scan_script_for_secrets(
    script_url: str,
    client: httpx.AsyncClient,
    max_bytes: int = 1_000_000,
) -> List[Dict[str, Any]]:
    """Download a single JS file and scan content with high-entropy regex patterns."""
    findings: List[Dict[str, Any]] = []
    try:
        resp = await client.get(script_url, timeout=4.0)
        if resp.status_code != 200:
            return findings

        # Limit content size to avoid regex performance issues on huge bundles
        content = resp.text[:max_bytes]

        for p in SECRET_PATTERNS:
            matches = p["pattern"].findall(content)
            for m in set(matches):
                findings.append({
                    "secret_type": p["type"],
                    "severity": p["severity"],
                    "redacted_value": redact_secret(m),
                    "script_url": script_url,
                })
    except Exception as exc:
        logger.debug("Failed fetching or scanning script %s: %s", script_url, exc)

    return findings


async def extract_and_scan_js_secrets(
    target_urls: List[str],
    max_scripts_per_host: int = 8,
) -> Dict[str, Any]:
    """
    Crawl live target pages, extract loaded .js scripts, and analyze for leaked credentials.
    """
    total_findings: List[Dict[str, Any]] = []
    scanned_scripts: Set[str] = set()

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=5.0) as client:
        for base_url in target_urls:
            try:
                resp = await client.get(base_url)
                if resp.status_code != 200:
                    continue

                html = resp.text
                script_srcs = SCRIPT_SRC_REGEX.findall(html)

                valid_scripts = []
                for src in script_srcs:
                    full_url = urljoin(base_url, src)
                    # Skip common heavy CDN libraries (react, lodash, cdnjs core)
                    if any(cdn in full_url.lower() for cdn in ("cdnjs.cloudflare.com", "unpkg.com", "cdn.jsdelivr.net")):
                        continue
                    if full_url not in scanned_scripts:
                        scanned_scripts.add(full_url)
                        valid_scripts.append(full_url)
                    if len(valid_scripts) >= max_scripts_per_host:
                        break

                for s_url in valid_scripts:
                    script_secrets = await scan_script_for_secrets(s_url, client)
                    total_findings.extend(script_secrets)

            except Exception as exc:
                logger.debug("Error probing %s for scripts: %s", base_url, exc)

    # Sort findings by severity (HIGH first)
    severity_order = {"HIGH": 0, "MED": 1, "LOW": 2}
    total_findings.sort(key=lambda x: severity_order.get(x["severity"], 3))

    return {
        "scripts_scanned_count": len(scanned_scripts),
        "secrets_found_count": len(total_findings),
        "findings": total_findings,
    }
