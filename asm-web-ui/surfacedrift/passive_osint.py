from __future__ import annotations

import asyncio
import logging
import re
from typing import Dict, List, Optional, Set

import httpx

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
REQUEST_TIMEOUT = 3.5


def clean_hostname(raw: str, root_domain: str) -> Optional[str]:
    """
    Clean and validate a discovered hostname.
    - Strips wildcards (*.example.com -> example.com)
    - Lowercases
    - Strips spaces and trailing/leading dots
    - Verifies hostname belongs to root_domain
    """
    if not raw:
        return None

    cleaned = raw.strip().lower()
    # Strip any leading wildcard prefix e.g. *. or *.*. or ..
    cleaned = re.sub(r"^[\*\.\s]+", "", cleaned)
    cleaned = cleaned.strip(" .")

    if not cleaned:
        return None

    # Must match domain or end with .domain
    root = root_domain.lower().strip()
    if cleaned == root or cleaned.endswith(f".{root}"):
        # Check basic characters (alphanumeric, hyphens, dots)
        if re.match(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$", cleaned):
            return cleaned

    return None


async def query_crtsh(domain: str, client: httpx.AsyncClient) -> Set[str]:
    """Query Certificate Transparency logs via crt.sh."""
    url = CRTSH_URL.format(domain=domain)
    found: Set[str] = set()
    try:
        resp = await asyncio.wait_for(client.get(url, timeout=REQUEST_TIMEOUT), timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for entry in data:
                    name_value = entry.get("name_value")
                    if name_value:
                        for line in str(name_value).splitlines():
                            for part in line.split():
                                h = clean_hostname(part, domain)
                                if h:
                                    found.add(h)
    except Exception as exc:
        logger.warning("crt.sh query failed for %s: %s", domain, exc)
    return found


async def query_hackertarget(domain: str, client: httpx.AsyncClient) -> Set[str]:
    """Query HackerTarget hostsearch endpoint (CSV response: host,ip)."""
    url = HACKERTARGET_URL.format(domain=domain)
    found: Set[str] = set()
    try:
        resp = await asyncio.wait_for(client.get(url, timeout=REQUEST_TIMEOUT), timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            text = resp.text
            # Check for API error messages
            if "error" not in text.lower() and "api count exceeded" not in text.lower():
                for line in text.splitlines():
                    parts = line.strip().split(",")
                    if parts:
                        h = clean_hostname(parts[0], domain)
                        if h:
                            found.add(h)
    except Exception as exc:
        logger.warning("HackerTarget query failed for %s: %s", domain, exc)
    return found


async def query_otx(domain: str, client: httpx.AsyncClient) -> Set[str]:
    """Query AlienVault OTX Passive DNS endpoint."""
    url = OTX_URL.format(domain=domain)
    found: Set[str] = set()
    try:
        resp = await asyncio.wait_for(client.get(url, timeout=REQUEST_TIMEOUT), timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            records = data.get("passive_dns", [])
            for r in records:
                hostname = r.get("hostname")
                if hostname:
                    h = clean_hostname(hostname, domain)
                    if h:
                        found.add(h)
    except Exception as exc:
        logger.warning("AlienVault OTX query failed for %s: %s", domain, exc)
    return found


async def run_passive_enumeration(
    domain: str,
    client: Optional[httpx.AsyncClient] = None,
) -> List[Dict[str, any]]:
    """
    Run concurrent passive reconnaissance across all supported sources.
    Returns deduplicated list of records with discovered sources:
    [
        {"subdomain": "api.example.com", "sources": ["crt.sh", "otx"]},
        ...
    ]
    """
    root_domain = domain.lower().strip().lstrip("http://").lstrip("https://").rstrip("/")

    close_client = False
    if client is None:
        client = httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
        )
        close_client = True

    try:
        # Run all passive sources concurrently with exception isolation
        crt_task = query_crtsh(root_domain, client)
        ht_task = query_hackertarget(root_domain, client)
        otx_task = query_otx(root_domain, client)

        results = await asyncio.gather(
            crt_task, ht_task, otx_task, return_exceptions=True
        )

        crt_hosts = results[0] if isinstance(results[0], set) else set()
        ht_hosts = results[1] if isinstance(results[1], set) else set()
        otx_hosts = results[2] if isinstance(results[2], set) else set()

        subdomain_sources: Dict[str, List[str]] = {}

        for host in crt_hosts:
            subdomain_sources.setdefault(host, []).append("crt.sh")

        for host in ht_hosts:
            subdomain_sources.setdefault(host, []).append("hackertarget")

        for host in otx_hosts:
            subdomain_sources.setdefault(host, []).append("otx")

        # Always ensure the root domain is included
        if root_domain not in subdomain_sources:
            subdomain_sources[root_domain] = ["root_seed"]

        output = [
            {"subdomain": sub, "sources": sorted(list(set(sources)))}
            for sub, sources in sorted(subdomain_sources.items())
        ]
        return output
    finally:
        if close_client:
            await client.aclose()
