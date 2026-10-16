from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

API_PATHS = [
    {"path": "/swagger.json", "type": "Swagger 2.0 / OpenAPI Specification"},
    {"path": "/swagger/v1/swagger.json", "type": "Swagger 2.0 Specification"},
    {"path": "/v2/api-docs", "type": "Springfox Swagger Specification"},
    {"path": "/v3/api-docs", "type": "Springdoc OpenAPI Specification"},
    {"path": "/openapi.json", "type": "OpenAPI Specification (JSON)"},
    {"path": "/openapi.yaml", "type": "OpenAPI Specification (YAML)"},
    {"path": "/api/docs", "type": "Interactive API Documentation"},
    {"path": "/docs", "type": "FastAPI / Redoc Documentation"},
    {"path": "/api-docs", "type": "API Documentation Portal"},
    {"path": "/api/swagger", "type": "Swagger UI Portal"},
    {"path": "/graphql", "type": "GraphQL Endpoint"},
    {"path": "/graphiql", "type": "GraphiQL Interactive IDE"},
]

GRAPHQL_INTROSPECTION_QUERY = {"query": "{__schema{types{name}}}"}


async def probe_endpoint(
    client: httpx.AsyncClient,
    base_url: str,
    path_def: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    """Probe a single API documentation or specification path."""
    target_url = urljoin(base_url, path_def["path"])
    try:
        # Check GET first
        resp = await client.get(target_url, timeout=3.0)
        status = resp.status_code
        content_type = resp.headers.get("content-type", "").lower()
        body_snippet = resp.text[:800].lower()

        # Swagger / OpenAPI check
        if status == 200:
            if "swagger" in body_snippet or "openapi" in body_snippet or "swagger-ui" in body_snippet:
                return {
                    "url": target_url,
                    "path": path_def["path"],
                    "type": path_def["type"],
                    "status_code": status,
                    "details": "Exposed API Specification / Documentation",
                    "severity": "MED",
                }

        # Check GraphQL Introspection if path is /graphql
        if "graphql" in path_def["path"]:
            try:
                gql_resp = await client.post(
                    target_url,
                    json=GRAPHQL_INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                    timeout=3.5,
                )
                if gql_resp.status_code == 200 and "__schema" in gql_resp.text:
                    return {
                        "url": target_url,
                        "path": path_def["path"],
                        "type": "GraphQL Introspection Enabled",
                        "status_code": gql_resp.status_code,
                        "details": "GraphQL Introspection is actively enabled — full API schema is enumerable",
                        "severity": "HIGH",
                    }
            except Exception:
                pass

    except Exception:
        pass

    return None


async def discover_shadow_apis(
    live_hosts: List[str],
    concurrency: int = 10,
) -> Dict[str, Any]:
    """
    Probe live hosts for common developer and API documentation endpoints.
    """
    endpoints_found: List[Dict[str, Any]] = []
    hosts_to_probe = live_hosts[:15]  # Limit to top 15 live hosts for speed

    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=3.5) as client:
        async def _bounded_probe(h: str, p_def: Dict[str, str]):
            async with semaphore:
                # Ensure protocol
                base = h if h.startswith("http://") or h.startswith("https://") else f"https://{h}"
                res = await probe_endpoint(client, base, p_def)
                if res:
                    endpoints_found.append(res)

        tasks = []
        for host in hosts_to_probe:
            for p_def in API_PATHS:
                tasks.append(_bounded_probe(host, p_def))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    return {
        "hosts_probed_count": len(hosts_to_probe),
        "exposed_endpoints_count": len(endpoints_found),
        "endpoints": endpoints_found,
    }
