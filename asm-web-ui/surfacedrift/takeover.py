from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

import dns.asyncresolver

logger = logging.getLogger(__name__)

# Known vulnerable service fingerprints
TAKEOVER_SIGNATURES: List[Dict[str, str]] = [
    {
        "service": "GitHub Pages",
        "cname": "github.io",
        "fingerprint": "There isn't a GitHub Pages site here",
    },
    {
        "service": "AWS S3",
        "cname": "s3.amazonaws.com",
        "fingerprint": "The specified bucket does not exist",
    },
    {
        "service": "AWS S3",
        "cname": "s3-website",
        "fingerprint": "NoSuchBucket",
    },
    {
        "service": "Heroku",
        "cname": "herokuapp.com",
        "fingerprint": "Heroku | No such app",
    },
    {
        "service": "Heroku",
        "cname": "herokudns.com",
        "fingerprint": "No such app",
    },
    {
        "service": "Shopify",
        "cname": "myshopify.com",
        "fingerprint": "Sorry, this shop is currently unavailable.",
    },
    {
        "service": "Fastly",
        "cname": "fastly.net",
        "fingerprint": "Fastly error: unknown domain",
    },
    {
        "service": "Ghost",
        "cname": "ghost.io",
        "fingerprint": "The thing you were looking for is no longer here",
    },
    {
        "service": "WordPress.com",
        "cname": "wordpress.com",
        "fingerprint": "Do you want to register ",
    },
    {
        "service": "Surge.sh",
        "cname": "surge.sh",
        "fingerprint": "project not found",
    },
    {
        "service": "Bitbucket",
        "cname": "bitbucket.io",
        "fingerprint": "Repository not found",
    },
    {
        "service": "Zendesk",
        "cname": "zendesk.com",
        "fingerprint": "Help Center Closed",
    },
    {
        "service": "Tumblr",
        "cname": "domains.tumblr.com",
        "fingerprint": "Whatever you were looking for doesn't seem to exist at this URL",
    },
    {
        "service": "HelpJuice",
        "cname": "helpjuice.com",
        "fingerprint": "We could not find what you're looking for",
    },
]


@dataclass
class TakeoverResult:
    """Subdomain takeover verification result."""
    subdomain: str
    is_vulnerable: bool = False
    cname: Optional[str] = None
    service: Optional[str] = None
    matched_signature: Optional[str] = None


async def resolve_cname(hostname: str) -> Optional[str]:
    """Resolve CNAME record for a hostname using dnspython."""
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0
        answers = await resolver.resolve(hostname, "CNAME")
        for rdata in answers:
            target = str(rdata.target).rstrip(".")
            return target.lower()
    except Exception as exc:
        logger.debug("CNAME resolution failed for %s: %s", hostname, exc)
    return None


def verify_takeover(
    subdomain: str,
    cname: Optional[str],
    http_body: str,
) -> TakeoverResult:
    """
    Perform two-tier verification:
    1. CNAME points to a known vulnerable third-party provider suffix.
    2. Response body contains that provider's dangling/unclaimed signature.
    """
    if not cname:
        return TakeoverResult(subdomain=subdomain, is_vulnerable=False)

    cname_lower = cname.lower().strip()
    body_text = http_body or ""

    for sig in TAKEOVER_SIGNATURES:
        cname_pattern = sig["cname"].lower()
        if cname_pattern in cname_lower:
            # First tier passed: CNAME points to provider
            fingerprint = sig["fingerprint"]
            if fingerprint.lower() in body_text.lower():
                # Second tier passed: Body contains unclaimed error signature
                return TakeoverResult(
                    subdomain=subdomain,
                    is_vulnerable=True,
                    cname=cname_lower,
                    service=sig["service"],
                    matched_signature=fingerprint,
                )

    return TakeoverResult(
        subdomain=subdomain,
        is_vulnerable=False,
        cname=cname_lower,
    )


async def audit_subdomains_takeover(
    subdomains: List[str],
    concurrency: int = 15,
    timeout: float = 4.0,
) -> List[TakeoverResult]:
    """Concurrently check a list of subdomains for dangling CNAME takeover vulnerabilities."""
    import asyncio
    import httpx

    sem = asyncio.Semaphore(concurrency)
    results: List[TakeoverResult] = []

    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
        async def _check_one(sub: str) -> TakeoverResult:
            async with sem:
                cname = await resolve_cname(sub)
                if not cname:
                    return TakeoverResult(subdomain=sub, is_vulnerable=False)

                # Check if CNAME matches any signature pattern
                matches_provider = any(sig["cname"].lower() in cname.lower() for sig in TAKEOVER_SIGNATURES)
                if not matches_provider:
                    return TakeoverResult(subdomain=sub, is_vulnerable=False, cname=cname)

                # Fetch HTTP body to test fingerprint
                body = ""
                for proto in ("https://", "http://"):
                    try:
                        resp = await client.get(f"{proto}{sub}", headers={"User-Agent": "SurfaceDrift/0.1.0"})
                        body = resp.text
                        break
                    except Exception:
                        continue

                return verify_takeover(sub, cname, body)

        tasks = [_check_one(s) for s in subdomains]
        if tasks:
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for item in outcomes:
                if isinstance(item, TakeoverResult):
                    results.append(item)

    return results

