from __future__ import annotations

import asyncio
import html
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0
DEFAULT_CONCURRENCY = 25
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 SurfaceDrift/0.1.0"

# ─── Technology Signatures ───────────────────────────────────────────────────

# Patterns checked against headers (lowercased key and value) and response body snippet
TECH_SIGNATURES: Dict[str, Dict[str, List[re.Pattern]]] = {
    # Web Servers
    "Nginx": {
        "headers": [re.compile(r"nginx", re.IGNORECASE)],
    },
    "Apache": {
        "headers": [re.compile(r"apache", re.IGNORECASE)],
    },
    "Microsoft IIS": {
        "headers": [re.compile(r"microsoft-iis", re.IGNORECASE)],
    },
    "Caddy": {
        "headers": [re.compile(r"caddy", re.IGNORECASE)],
    },
    "LiteSpeed": {
        "headers": [re.compile(r"litespeed", re.IGNORECASE)],
    },
    # CDNs & Proxies
    "Cloudflare": {
        "headers": [
            re.compile(r"cloudflare", re.IGNORECASE),
            re.compile(r"cf-ray", re.IGNORECASE),
            re.compile(r"cf-cache-status", re.IGNORECASE),
        ],
    },
    "AWS CloudFront": {
        "headers": [
            re.compile(r"cloudfront", re.IGNORECASE),
            re.compile(r"x-amz-cf-id", re.IGNORECASE),
            re.compile(r"x-amz-cf-pop", re.IGNORECASE),
        ],
    },
    "Akamai": {
        "headers": [
            re.compile(r"akamai", re.IGNORECASE),
            re.compile(r"x-akamai", re.IGNORECASE),
        ],
    },
    "Fastly": {
        "headers": [
            re.compile(r"fastly", re.IGNORECASE),
            re.compile(r"x-fastly", re.IGNORECASE),
        ],
    },
    # CMS & Frameworks
    "Next.js": {
        "headers": [re.compile(r"x-powered-by:\s*next\.js", re.IGNORECASE)],
        "body": [
            re.compile(r"/_next/static/", re.IGNORECASE),
            re.compile(r"<div id=\"__next\"", re.IGNORECASE),
            re.compile(r"__NEXT_DATA__", re.IGNORECASE),
        ],
    },
    "WordPress": {
        "headers": [
            re.compile(r"wp-json", re.IGNORECASE),
            re.compile(r"x-powered-by:\s*wp", re.IGNORECASE),
        ],
        "body": [
            re.compile(r"/wp-content/", re.IGNORECASE),
            re.compile(r"/wp-includes/", re.IGNORECASE),
            re.compile(r"generator\" content=\"wordpress", re.IGNORECASE),
        ],
    },
    "Drupal": {
        "headers": [re.compile(r"x-generator:\s*drupal", re.IGNORECASE)],
        "body": [
            re.compile(r"drupal\.settings", re.IGNORECASE),
            re.compile(r"generator\" content=\"drupal", re.IGNORECASE),
        ],
    },
    "Django": {
        "headers": [re.compile(r"csrftoken", re.IGNORECASE)],
        "body": [re.compile(r"csrfmiddlewaretoken", re.IGNORECASE)],
    },
    "Laravel": {
        "headers": [re.compile(r"laravel_session", re.IGNORECASE)],
        "body": [re.compile(r"laravel", re.IGNORECASE)],
    },
    "Express": {
        "headers": [re.compile(r"x-powered-by:\s*express", re.IGNORECASE)],
    },
    "Ruby on Rails": {
        "headers": [
            re.compile(r"x-powered-by:\s*phusion passenger", re.IGNORECASE),
            re.compile(r"_rails_session", re.IGNORECASE),
        ],
    },
    "Spring Boot": {
        "headers": [re.compile(r"x-application-context", re.IGNORECASE)],
        "body": [re.compile(r"whitelabel error page", re.IGNORECASE)],
    },
}


def extract_title(html_content: str) -> Optional[str]:
    """Extract and unescape HTML page title from body text."""
    if not html_content:
        return None
    match = re.search(r"<title(?:\s+[^>]*)?>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
    if match:
        raw_title = match.group(1).strip()
        # Clean newlines and consecutive whitespace
        cleaned = re.sub(r"\s+", " ", raw_title)
        unescaped = html.unescape(cleaned).strip()
        return unescaped if unescaped else None
    return None


def detect_technologies(
    headers: Dict[str, str],
    body_snippet: str = "",
) -> List[str]:
    """Detect technologies from HTTP response headers and initial body snippet."""
    detected: Set[str] = set()

    # Flatten headers to strings: "header_name: header_value"
    header_strings = [f"{k}: {v}" for k, v in headers.items()]
    header_blob = "\n".join(header_strings)

    for tech_name, rules in TECH_SIGNATURES.items():
        # Check header patterns
        header_patterns = rules.get("headers", [])
        for pattern in header_patterns:
            if pattern.search(header_blob):
                detected.add(tech_name)
                break

        # Check body patterns
        body_patterns = rules.get("body", [])
        if body_snippet and tech_name not in detected:
            for pattern in body_patterns:
                if pattern.search(body_snippet):
                    detected.add(tech_name)
                    break

    return sorted(list(detected))


@dataclass
class ProbeResult:
    """Result of probing an individual host."""
    subdomain: str
    is_live: bool = False
    http_status: Optional[int] = None
    https_status: Optional[int] = None
    preferred_url: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)
    page_title: Optional[str] = None
    server_banner: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    screenshot_url: Optional[str] = None


async def probe_single_scheme(
    url: str,
    client: httpx.AsyncClient,
    timeout: float = DEFAULT_TIMEOUT,
) -> Optional[httpx.Response]:
    """Perform GET request following redirects, returning final response."""
    try:
        resp = await client.get(url, timeout=timeout, follow_redirects=True)
        return resp
    except Exception as exc:
        logger.debug("Failed probe for %s: %s", url, exc)
        return None


async def probe_host(
    subdomain: str,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    timeout: float = DEFAULT_TIMEOUT,
) -> ProbeResult:
    """
    Probe a host on both HTTPS (preferred) and HTTP.
    Captures status, redirects, headers, title, and detected technologies.
    """
    async with semaphore:
        result = ProbeResult(subdomain=subdomain)

        # 1. Try HTTPS first
        https_url = f"https://{subdomain}"
        http_url = f"http://{subdomain}"

        https_resp = await probe_single_scheme(https_url, client, timeout)
        http_resp = await probe_single_scheme(http_url, client, timeout)

        best_resp: Optional[httpx.Response] = None

        if https_resp is not None:
            result.is_live = True
            result.https_status = https_resp.status_code
            best_resp = https_resp
            result.preferred_url = str(https_resp.url)

        if http_resp is not None:
            result.is_live = True
            result.http_status = http_resp.status_code
            if best_resp is None:
                best_resp = http_resp
                result.preferred_url = str(http_resp.url)

        if best_resp is not None:
            # Build redirect chain
            chain = [str(r.url) for r in best_resp.history]
            chain.append(str(best_resp.url))
            result.redirect_chain = chain

            # Extract headers
            resp_headers = {k.lower(): v for k, v in best_resp.headers.items()}
            result.headers = resp_headers
            result.server_banner = resp_headers.get("server")

            # Extract body snippet (first 64KB for title & tech detection)
            body_text = ""
            try:
                body_text = best_resp.text[:65536]
            except Exception:
                pass

            result.page_title = extract_title(body_text)
            result.tech_stack = detect_technologies(resp_headers, body_text)

        return result


async def probe_subdomains(
    hostnames: List[str],
    max_concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT,
    client: Optional[httpx.AsyncClient] = None,
) -> List[ProbeResult]:
    """
    Concurrently probe a list of hostnames with concurrency throttling.
    """
    if not hostnames:
        return []

    close_client = False
    if client is None:
        client = httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            verify=False,  # Security scanner needs to inspect hosts with self-signed/expired certs
            follow_redirects=True,
        )
        close_client = True

    semaphore = asyncio.Semaphore(max_concurrency)
    try:
        tasks = [
            probe_host(host, client, semaphore, timeout)
            for host in hostnames
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        probed: List[ProbeResult] = []
        for host, r in zip(hostnames, results):
            if isinstance(r, ProbeResult):
                probed.append(r)
            else:
                # Return dead/unreachable result on unexpected task failure
                probed.append(ProbeResult(subdomain=host, is_live=False))

        return probed
    finally:
        if close_client:
            await client.aclose()
