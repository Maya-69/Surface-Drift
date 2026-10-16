from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

# Common sensitive configuration files and debug endpoints with validation signatures
CONFIG_PROBE_TARGETS = [
    {
        "path": "/.env",
        "description": "Environment Configuration File",
        "severity": "CRITICAL",
        "signatures": ["DB_", "APP_", "SECRET", "KEY=", "API_"],
    },
    {
        "path": "/.git/config",
        "description": "Exposed Git Repository Configuration",
        "severity": "CRITICAL",
        "signatures": ["[core]", "repositoryformatversion"],
    },
    {
        "path": "/.DS_Store",
        "description": "macOS Directory Metadata File",
        "severity": "MED",
        "signatures": ["Bud1", "\x00\x00\x00\x01"],
    },
    {
        "path": "/server-status",
        "description": "Apache Mod-Status Internal Telemetry",
        "severity": "HIGH",
        "signatures": ["Apache Server Status", "Server Version:"],
    },
    {
        "path": "/phpinfo.php",
        "description": "Exposed PHP Information / Environment Dump",
        "severity": "HIGH",
        "signatures": ["PHP Version", "Configuration File (php.ini) Path"],
    },
    {
        "path": "/backup.zip",
        "description": "Public Archive / Backup Dump",
        "severity": "CRITICAL",
        "signatures": ["PK\x03\x04", "application/zip"],
    },
    {
        "path": "/web.config",
        "description": "IIS Web Server Configuration File",
        "severity": "HIGH",
        "signatures": ["<configuration>", "<system.webServer>"],
    },
]


async def probe_single_path(
    client: httpx.AsyncClient,
    base_url: str,
    probe_def: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Test a sensitive configuration path against a target host with content signature validation."""
    target_url = urljoin(base_url, probe_def["path"])
    try:
        resp = await client.get(target_url, timeout=3.0)
        # Verify 200 OK
        if resp.status_code == 200:
            content_snippet = resp.text[:1000]
            raw_bytes = resp.content[:64]
            content_type = resp.headers.get("content-type", "").lower()

            # Verify signature to avoid custom 200 OK error pages
            matched = False
            for sig in probe_def["signatures"]:
                if sig in content_snippet or sig.encode() in raw_bytes or sig in content_type:
                    matched = True
                    break

            if matched:
                return {
                    "url": target_url,
                    "path": probe_def["path"],
                    "description": probe_def["description"],
                    "severity": probe_def["severity"],
                    "status_code": resp.status_code,
                    "details": f"Sensitive file {probe_def['path']} is publicly accessible without authentication",
                }
    except Exception:
        pass
    return None


async def probe_exposed_configurations(
    live_hosts: List[str],
    concurrency: int = 10,
) -> Dict[str, Any]:
    """
    Asynchronously test live endpoints for exposed sensitive configuration files,
    backups, and administrative debug consoles.
    """
    exposed_files: List[Dict[str, Any]] = []
    hosts_to_probe = live_hosts[:12]  # Test top 12 active endpoints

    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=3.5) as client:
        async def _bounded_check(host: str, p_def: Dict[str, Any]):
            async with semaphore:
                base = host if host.startswith("http://") or host.startswith("https://") else f"https://{host}"
                res = await probe_single_path(client, base, p_def)
                if res:
                    exposed_files.append(res)

        tasks = []
        for host in hosts_to_probe:
            for p_def in CONFIG_PROBE_TARGETS:
                tasks.append(_bounded_check(host, p_def))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    return {
        "hosts_tested_count": len(hosts_to_probe),
        "exposed_configs_found": len(exposed_files),
        "exposed_files": exposed_files,
    }
