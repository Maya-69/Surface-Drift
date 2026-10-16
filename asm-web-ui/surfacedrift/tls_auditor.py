from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import ssl
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)


async def audit_host_tls(hostname: str, port: int = 443, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
    """
    Perform an async TLS connection handshake, extracting certificate validity,
    protocol versions, and cipher suites.
    """
    clean_host = hostname.strip().lower().lstrip("https://").lstrip("http://").split("/")[0].split(":")[0]
    if not clean_host:
        return None

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    loop = asyncio.get_running_loop()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(clean_host, port, ssl=ssl_context, server_hostname=clean_host),
            timeout=timeout,
        )
        
        ssl_obj: Optional[ssl.SSLSocket] = writer.get_extra_info("ssl_object")
        if not ssl_obj:
            writer.close()
            await writer.wait_closed()
            return None

        # Extract cert details
        peercert = ssl_obj.getpeercert(binary_form=False)
        cipher_info = ssl_obj.cipher()  # (cipher_name, tls_version, bits)
        tls_version = ssl_obj.version()

        writer.close()
        await writer.wait_closed()

        issues: List[str] = []
        severity = "LOW"
        days_left: Optional[int] = None
        not_after_str: str = "Unknown"
        issuer_str: str = "Unknown"

        if peercert:
            # Parse expiration date
            not_after = peercert.get("notAfter")
            if not_after:
                not_after_str = not_after
                try:
                    # e.g., 'May 28 12:00:00 2027 GMT'
                    exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now_dt = datetime.now(timezone.utc)
                    days_left = (exp_dt - now_dt).days
                    if days_left < 0:
                        issues.append("Certificate has EXPIRED")
                        severity = "HIGH"
                    elif days_left < 30:
                        issues.append(f"Certificate expires in {days_left} days")
                        severity = "HIGH" if days_left < 14 else "MED"
                except Exception:
                    pass

            # Extract issuer
            issuer_tuples = peercert.get("issuer", ())
            issuer_parts = []
            for rdn in issuer_tuples:
                for k, v in rdn:
                    if k in ("organizationName", "commonName"):
                        issuer_parts.append(v)
            if issuer_parts:
                issuer_str = " / ".join(issuer_parts)

        # Protocol check
        if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            issues.append(f"Deprecated insecure protocol {tls_version} in use")
            severity = "HIGH"

        # Check HSTS header via lightweight HTTP HEAD request
        hsts_enabled = False
        try:
            async with httpx.AsyncClient(verify=False, timeout=3.0) as client:
                head_resp = await client.head(f"https://{clean_host}")
                if "strict-transport-security" in head_resp.headers:
                    hsts_enabled = True
                else:
                    issues.append("Missing HSTS (Strict-Transport-Security) header")
                    if severity == "LOW":
                        severity = "MED"
        except Exception:
            pass

        return {
            "hostname": clean_host,
            "port": port,
            "tls_version": tls_version or "Unknown",
            "cipher": cipher_info[0] if cipher_info else "Unknown",
            "cipher_bits": cipher_info[2] if cipher_info else 0,
            "issuer": issuer_str,
            "expiration_date": not_after_str,
            "days_until_expiration": days_left,
            "hsts_enabled": hsts_enabled,
            "issues": issues,
            "severity": severity,
            "status": "SECURE" if not issues else ("HIGH_RISK" if severity == "HIGH" else "WARNING"),
        }

    except Exception as exc:
        logger.debug("TLS audit error for %s: %s", clean_host, exc)
        return None


async def audit_cryptographic_posture(
    target_hosts: List[str],
    max_hosts: int = 15,
) -> Dict[str, Any]:
    """
    Concurrently evaluate TLS posture, expiration dates, ciphers, and HSTS
    across discovered HTTPS endpoints.
    """
    unique_hosts = list(dict.fromkeys(target_hosts))[:max_hosts]
    tasks = [audit_host_tls(h) for h in unique_hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    valid_certs = [r for r in results if isinstance(r, dict) and r is not None]

    expiring_soon_count = sum(1 for c in valid_certs if c.get("days_until_expiration") is not None and c["days_until_expiration"] < 30)
    missing_hsts_count = sum(1 for c in valid_certs if not c.get("hsts_enabled"))
    weak_protocol_count = sum(1 for c in valid_certs if "Deprecated" in " ".join(c.get("issues", [])))

    return {
        "endpoints_audited": len(valid_certs),
        "expiring_soon_count": expiring_soon_count,
        "missing_hsts_count": missing_hsts_count,
        "weak_protocol_count": weak_protocol_count,
        "certificates": valid_certs,
    }
