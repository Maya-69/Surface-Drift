from __future__ import annotations

import logging
from typing import Optional, Set, Tuple

import httpx

logger = logging.getLogger(__name__)

FIRST_EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve}"
REQUEST_TIMEOUT = 5.0

# Embedded critical subset of known actively exploited CISA KEV CVEs
# (in production, synchronized periodically from https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
KNOWN_CISA_KEV_SUBSET: Set[str] = {
    "CVE-2021-44228",  # Log4Shell
    "CVE-2023-34362",  # MOVEit Transfer SQLi
    "CVE-2023-4966",   # Citrix Bleed
    "CVE-2024-1709",   # ConnectWise ScreenConnect
    "CVE-2024-3400",   # Palo Alto PAN-OS Command Injection
    "CVE-2023-22515",  # Atlassian Confluence Broken Access Control
    "CVE-2023-2868",   # Barracuda Email Security Gateway
    "CVE-2022-26134",  # Atlassian Confluence OGNL Injection
    "CVE-2021-26855",  # Microsoft Exchange ProxyLogon
    "CVE-2020-1472",   # Zerologon
    "CVE-2017-0144",   # EternalBlue
    "CVE-2019-19781",  # Citrix ADC
    "CVE-2023-20198",  # Cisco IOS XE Web UI
}


async def query_epss_score(
    cve_id: str,
    client: httpx.AsyncClient,
) -> Tuple[Optional[float], Optional[float]]:
    """
    Query FIRST.org EPSS API for Exploit Prediction Scoring System data.
    Returns: (epss_score, epss_percentile)
    """
    clean_cve = cve_id.strip().upper()
    url = FIRST_EPSS_URL.format(cve=clean_cve)

    try:
        resp = await client.get(url, timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            rows = data.get("data", [])
            if rows:
                item = rows[0]
                epss = float(item["epss"]) if "epss" in item else None
                percentile = float(item["percentile"]) if "percentile" in item else None
                return epss, percentile
    except Exception as exc:
        logger.debug("EPSS lookup failed for %s: %s", clean_cve, exc)

    return None, None


def is_cisa_kev_listed(
    cve_id: str,
    custom_catalog: Optional[Set[str]] = None,
) -> bool:
    """Check if CVE is in the CISA Known Exploited Vulnerabilities catalog."""
    clean_cve = cve_id.strip().upper()
    catalog = custom_catalog if custom_catalog is not None else KNOWN_CISA_KEV_SUBSET
    return clean_cve in catalog


def compute_priority_tag(
    cve_id: Optional[str] = None,
    cvss_score: Optional[float] = None,
    epss_score: Optional[float] = None,
    cisa_kev: bool = False,
) -> str:
    """
    Prioritize threat exposure based on active exploitation (CTEM paradigm):
    - HIGH: CISA KEV confirmed exploited OR EPSS >= 0.20 (or CVSS >= 7.0)
    - MED: EPSS >= 0.05 (or CVSS >= 4.0)
    - LOW: Standard informational or low severity (<5% EPSS)
    """
    # Guard against positional argument calls: (cve, epss, is_kev)
    if isinstance(epss_score, bool):
        cisa_kev = epss_score
        epss_score = cvss_score if isinstance(cvss_score, (float, int)) else None
        cvss_score = None
    elif isinstance(cvss_score, float) and cvss_score <= 1.0 and epss_score is None:
        epss_score = cvss_score
        cvss_score = None

    if cisa_kev:
        return "HIGH"

    if epss_score is not None:
        if epss_score >= 0.20:
            return "HIGH"
        if epss_score >= 0.05:
            return "MED"
        return "LOW"

    if cvss_score is not None:
        if cvss_score >= 7.0:
            return "HIGH"
        if cvss_score >= 4.0:
            return "MED"
        return "LOW"

    return "LOW"
