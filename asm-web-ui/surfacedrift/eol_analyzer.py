from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Dictionary of EOL / Legacy software versions with retirement info
EOL_RULES = [
    {
        "name": "PHP",
        "regex": re.compile(r"PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        "eol_threshold": (8, 1, 0),
        "latest_lts": "8.2+",
        "severity": "HIGH",
        "description": "PHP versions prior to 8.1 have reached Official End-of-Life (EOL) with no security patches.",
    },
    {
        "name": "jQuery",
        "regex": re.compile(r"jquery[/-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        "eol_threshold": (3, 5, 0),
        "latest_lts": "3.7+",
        "severity": "HIGH",
        "description": "jQuery < 3.5.0 contains known Cross-Site Scripting (XSS) vulnerabilities (CVE-2020-11022 / CVE-2020-11023).",
    },
    {
        "name": "Apache HTTP Server",
        "regex": re.compile(r"Apache/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        "eol_threshold": (2, 4, 49),
        "latest_lts": "2.4.58+",
        "severity": "HIGH",
        "description": "Apache HTTP Server versions prior to 2.4.50 are vulnerable to path traversal and remote code execution.",
    },
    {
        "name": "Nginx",
        "regex": re.compile(r"nginx/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        "eol_threshold": (1, 18, 0),
        "latest_lts": "1.24+",
        "severity": "MED",
        "description": "Legacy Nginx branch is end-of-life and missing HTTP/2 and modern SSL/TLS security hardening.",
    },
    {
        "name": "Python",
        "regex": re.compile(r"Python/([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
        "eol_threshold": (3, 8, 0),
        "latest_lts": "3.11+",
        "severity": "HIGH",
        "description": "Python versions older than 3.8 (including Python 2.x) are completely deprecated and unsupported.",
    },
    {
        "name": "ASP.NET",
        "regex": re.compile(r"(?:ASP\.NET|Microsoft-IIS)/([0-9]+\.[0-9]+)", re.IGNORECASE),
        "eol_threshold": (4, 5, 0),
        "latest_lts": "4.8 / .NET 8",
        "severity": "HIGH",
        "description": "Legacy ASP.NET / IIS runtime version has reached Microsoft End of Support.",
    },
]


def _parse_version_tuple(ver_str: str) -> Tuple[int, ...]:
    """Parse a version string like '5.6.40' into a tuple of ints (5, 6, 40)."""
    parts = re.findall(r"\d+", ver_str)
    return tuple(int(p) for p in parts[:3])


def audit_eol_technologies(
    probed_hosts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Passively inspect HTTP server banners, tech stack strings, and page titles
    for outdated, End-of-Life software dependencies.
    """
    findings: List[Dict[str, Any]] = []

    for host in probed_hosts:
        hostname = host.get("subdomain") or host.get("url") or "unknown"
        server_banner = host.get("server_banner") or ""
        tech_stack = host.get("tech_stack") or []
        page_title = host.get("page_title") or ""

        # Pool all passive indicators
        tokens = [server_banner, page_title] + (tech_stack if isinstance(tech_stack, list) else [])
        combined_text = " ".join(tokens)

        for rule in EOL_RULES:
            match = rule["regex"].search(combined_text)
            if match:
                detected_ver_str = match.group(1)
                detected_ver = _parse_version_tuple(detected_ver_str)
                threshold = rule["eol_threshold"]

                # Compare version tuple
                if detected_ver < threshold:
                    findings.append({
                        "hostname": hostname,
                        "product": rule["name"],
                        "detected_version": detected_ver_str,
                        "eol_threshold": ".".join(str(x) for x in threshold),
                        "recommended_version": rule["latest_lts"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                    })

    return {
        "eol_findings_count": len(findings),
        "findings": findings,
    }
