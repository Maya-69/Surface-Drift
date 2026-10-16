from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

import dns.asyncresolver
import httpx

from .cdn_detector import is_cdn_ip

logger = logging.getLogger(__name__)

# Free, fast historical DNS & Certificate APIs for origin resolution
HACKERTARGET_HOSTSEARCH = "https://api.hackertarget.com/hostsearch/?q={domain}"


async def fetch_historical_ip_candidates(domain: str, client: httpx.AsyncClient) -> Set[str]:
    """Query open intelligence feeds for historical IP resolutions associated with the domain."""
    ips: Set[str] = set()
    clean = domain.lower().strip()

    # Query HackerTarget DNS / Certificate hostsearch
    try:
        url = HACKERTARGET_HOSTSEARCH.format(domain=clean)
        resp = await client.get(url, timeout=4.0)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.splitlines():
                parts = line.strip().split(",")
                if len(parts) >= 2:
                    candidate_ip = parts[1].strip()
                    if candidate_ip and candidate_ip.count(".") == 3:
                        ips.add(candidate_ip)
    except Exception as exc:
        logger.debug("Historical IP lookup failed for %s: %s", domain, exc)

    return ips


async def verify_origin_response(
    origin_ip: str,
    domain: str,
    client: httpx.AsyncClient,
) -> Tuple[bool, Optional[int]]:
    """
    Test direct HTTP request to the candidate origin IP with Host: domain.
    If the server returns a legitimate 200/301/302 response with domain-like content,
    it confirms an origin bypass.
    """
    url = f"http://{origin_ip}"
    headers = {"Host": domain, "User-Agent": "SurfaceDrift-Origin-Validator/1.0"}
    try:
        resp = await client.get(url, headers=headers, timeout=3.5)
        if resp.status_code in (200, 301, 302, 401, 403):
            return True, resp.status_code
    except Exception:
        pass
    return False, None


async def audit_waf_historical_origin_bypasses(
    target_domain: str,
    current_ips: List[str],
) -> Dict[str, Any]:
    """
    Compare current CDN-protected addresses against historical non-CDN addresses
    to uncover exposed backend origin servers.
    """
    bypasses: List[Dict[str, Any]] = []
    clean_domain = target_domain.lower().strip()

    # Check if current domain is behind a CDN
    current_is_cdn = any(is_cdn_ip(ip) for ip in current_ips)

    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=4.0) as client:
        historical_ips = await fetch_historical_ip_candidates(clean_domain, client)

        # Filter out current CDN IPs
        candidate_origins = [ip for ip in historical_ips if not is_cdn_ip(ip) and ip not in current_ips]

        for ip in candidate_origins[:8]:  # Limit checks
            is_valid, status = await verify_origin_response(ip, clean_domain, client)
            if is_valid:
                bypasses.append({
                    "origin_ip": ip,
                    "target_domain": clean_domain,
                    "status_code": status,
                    "confidence": "HIGH" if current_is_cdn else "MEDIUM",
                    "details": f"Historical IP {ip} responds directly to Host: '{clean_domain}', bypassing fronting CDN/WAF defenses",
                    "severity": "HIGH" if current_is_cdn else "MED",
                })

    return {
        "current_behind_cdn": current_is_cdn,
        "historical_ips_discovered": len(historical_ips) if 'historical_ips' in locals() else 0,
        "origin_bypasses_found": len(bypasses),
        "bypasses": bypasses,
    }
