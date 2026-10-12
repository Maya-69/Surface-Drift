from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Known CDN ASNs and organization keyword matches
CDN_PROVIDERS: List[Dict[str, any]] = [
    {
        "provider": "Cloudflare",
        "asns": {"AS13335", "AS209242"},
        "keywords": ["cloudflare"],
    },
    {
        "provider": "AWS CloudFront",
        "asns": {"AS16509"},
        "keywords": ["cloudfront"],
    },
    {
        "provider": "Fastly",
        "asns": {"AS54113"},
        "keywords": ["fastly"],
    },
    {
        "provider": "Akamai",
        "asns": {"AS20940", "AS16625", "AS35994"},
        "keywords": ["akamai"],
    },
]

HIGH_CONFIDENCE_ORIGIN_PREFIXES = {"direct", "origin", "backend", "cpanel", "direct-connect"}
MEDIUM_CONFIDENCE_ORIGIN_PREFIXES = {"dev", "stage", "staging", "internal", "mail", "ftp", "vpn"}


def is_cdn_ip(
    asn_org: Optional[str] = None,
    asn: Optional[str] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Check if an ASN or Organization string matches a known CDN provider.
    Returns: (is_cdn, provider_name)
    """
    org_lower = (asn_org or "").lower()
    asn_upper = (asn or "").upper()

    for item in CDN_PROVIDERS:
        provider = item["provider"]
        if asn_upper and asn_upper in item["asns"]:
            return True, provider
        for kw in item["keywords"]:
            if kw in org_lower:
                return True, provider

    return False, None


def evaluate_waf_bypass(
    ip_records: List[Dict[str, any]],
) -> List[Dict[str, any]]:
    """
    Heuristic WAF / CDN origin bypass detection:
    If a domain has some IPs behind a CDN, inspect non-CDN IPs that have
    hostnames associated with origin reveals (e.g. direct.example.com, origin.example.com).
    Marks records with `is_waf_bypass = True` and confidence score.
    """
    # 1. Check if the attack surface includes CDN-fronted IPs
    has_cdn = any(ip.get("is_cdn", False) for ip in ip_records)
    if not has_cdn:
        return ip_records

    # 2. Inspect non-CDN IPs
    for ip in ip_records:
        if ip.get("is_cdn", False):
            continue

        hostnames: List[str] = ip.get("hostnames") or []
        for host in hostnames:
            first_label = host.split(".")[0].lower()

            if first_label in HIGH_CONFIDENCE_ORIGIN_PREFIXES:
                ip["is_waf_bypass"] = True
                ip["bypass_confidence"] = "HIGH"
                break
            elif first_label in MEDIUM_CONFIDENCE_ORIGIN_PREFIXES:
                ip["is_waf_bypass"] = True
                ip["bypass_confidence"] = "MEDIUM"
                break

    return ip_records
