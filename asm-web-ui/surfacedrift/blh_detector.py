from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

import dns.asyncresolver
import httpx

logger = logging.getLogger(__name__)

HREF_REGEX = re.compile(r"""<a[^>]+href=["'](https?://[^"'>]+)["']""", re.IGNORECASE)

# Well-known platforms that won't be hijackable / unregistered
EXCLUDED_DOMAINS = {
    "google.com", "www.google.com", "facebook.com", "twitter.com", "x.com",
    "linkedin.com", "instagram.com", "youtube.com", "github.com", "apple.com",
    "microsoft.com", "amazon.com", "cloudflare.com", "wikipedia.org", "w3.org",
}


async def check_domain_dns(domain: str) -> bool:
    """
    Check if a domain resolves. Returns True if domain is alive, False if NXDOMAIN.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 1.5
    resolver.lifetime = 1.5
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    try:
        await resolver.resolve(domain, "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # Double check with CNAME/NS before declaring NXDOMAIN
        try:
            await resolver.resolve(domain, "NS")
            return True
        except Exception:
            return False
    except Exception:
        # Timeout, SERVFAIL or connection error — consider active or transient
        return True


async def detect_broken_link_hijacking(
    target_domain: str,
    max_links_to_check: int = 25,
) -> Dict[str, Any]:
    """
    Crawl the target's primary website, extract external links, and test for expired/NXDOMAIN domains.
    """
    clean_target = target_domain.lower().strip().lstrip("http://").lstrip("https://").rstrip("/")
    homepage_url = f"https://{clean_target}"

    outbound_domains: Set[str] = set()
    link_map: Dict[str, str] = {}  # domain -> original href

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=5.0) as client:
        try:
            resp = await client.get(homepage_url)
            if resp.status_code != 200 and not homepage_url.startswith("http://"):
                resp = await client.get(f"http://{clean_target}")

            if resp.status_code == 200:
                raw_links = HREF_REGEX.findall(resp.text)
                for link in raw_links:
                    try:
                        parsed = urlparse(link)
                        ext_host = parsed.netloc.lower().split(":")[0]
                        # Filter out internal/subdomain links and common platforms
                        if ext_host and not ext_host.endswith(clean_target) and ext_host not in EXCLUDED_DOMAINS:
                            if ext_host not in outbound_domains and len(outbound_domains) < max_links_to_check:
                                outbound_domains.add(ext_host)
                                link_map[ext_host] = link
                    except Exception:
                        pass
        except Exception as exc:
            logger.debug("Failed crawling %s for outbound links: %s", homepage_url, exc)

    # Concurrently check DNS resolution for external links
    vulnerable_links: List[Dict[str, Any]] = []

    async def _check(dom: str):
        is_live = await check_domain_dns(dom)
        if not is_live:
            vulnerable_links.append({
                "expired_domain": dom,
                "original_link": link_map.get(dom, ""),
                "status": "NXDOMAIN",
                "risk": "Domain registration is available — an attacker can acquire this domain and hijack outbound traffic",
                "severity": "HIGH",
            })

    tasks = [_check(dom) for dom in outbound_domains]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    return {
        "external_domains_tested": len(outbound_domains),
        "broken_links_found": len(vulnerable_links),
        "vulnerable_links": vulnerable_links,
    }
