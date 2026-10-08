from __future__ import annotations

import logging
from typing import Dict, List, Optional

import dns.asyncresolver
import dns.reversename
import httpx

logger = logging.getLogger(__name__)

IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,countryCode,isp,org,as,query"
REQUEST_TIMEOUT = 5.0


async def resolve_dns_records(hostname: str) -> Dict[str, List[str]]:
    """
    Query DNS records (A, AAAA, MX, NS, TXT) for a given hostname.
    """
    records: Dict[str, List[str]] = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
    }

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2.5
    resolver.lifetime = 3.5

    for r_type in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            answers = await resolver.resolve(hostname, r_type)
            for rdata in answers:
                if r_type == "MX":
                    # e.g. "10 mail.example.com."
                    val = f"{rdata.preference} {str(rdata.exchange).rstrip('.')}"
                else:
                    val = str(rdata).strip('"').rstrip(".")
                records[r_type].append(val)
        except Exception:
            pass

    return records


async def reverse_dns_lookup(ip_address: str) -> Optional[str]:
    """Perform reverse PTR lookup for an IP."""
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2.5
        resolver.lifetime = 3.5
        rev_name = dns.reversename.from_address(ip_address)
        answers = await resolver.resolve(rev_name, "PTR")
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except Exception:
        pass
    return None


async def query_ip_intel(
    ip_address: str,
    client: httpx.AsyncClient,
) -> Dict[str, Optional[str]]:
    """
    Query ASN, organization, and country code for an IP.
    Returns: {"asn": "AS13335", "asn_org": "Cloudflare, Inc.", "country_code": "US", "cidr": None}
    """
    url = IP_API_URL.format(ip=ip_address)
    intel: Dict[str, Optional[str]] = {
        "asn": None,
        "asn_org": None,
        "country_code": None,
        "cidr": None,
    }
    try:
        resp = await client.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                as_field = data.get("as", "")  # e.g. "AS13335 Cloudflare, Inc."
                if as_field:
                    parts = as_field.split(" ", 1)
                    intel["asn"] = parts[0]
                    if len(parts) > 1:
                        intel["asn_org"] = parts[1]
                else:
                    intel["asn_org"] = data.get("org") or data.get("isp")

                intel["country_code"] = data.get("countryCode")
    except Exception as exc:
        logger.debug("IP intel query failed for %s: %s", ip_address, exc)

    return intel
