from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Set

import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 SurfaceDrift/0.1.0"
REQUEST_TIMEOUT = 5.0

KEYWORDS = [
    "backup",
    "assets",
    "data",
    "logs",
    "prod",
    "dev",
    "public",
    "static",
    "storage",
    "media",
    "internal",
    "corp",
    "archive",
]


@dataclass
class CloudBucketAuditResult:
    """Audit result for a single cloud storage bucket."""
    bucket_name: str
    provider: str  # "AWS_S3", "AZURE_BLOB", "GCP_GCS"
    url: str
    access_level: str  # "PUBLIC_READ_WRITE", "PUBLIC_LISTABLE", "PROTECTED", "NON_EXISTENT"
    http_status_code: Optional[int] = None
    response_snippet: Optional[str] = None
    is_dangerous: bool = False


def generate_bucket_permutations(
    domain: str,
    company_name: Optional[str] = None,
) -> List[str]:
    """
    Generate realistic candidate bucket names based on domain and company.
    e.g. acme, acme-backup, acme-assets, acme.com-data
    """
    # Extract domain base (e.g. 'example' from 'example.com')
    clean = domain.lower().strip().lstrip("http://").lstrip("https://").rstrip("/")
    base_name = clean.split(".")[0]

    seeds: Set[str] = {clean, base_name}
    if company_name:
        company_clean = re.sub(r"[^a-z0-9\-]", "", company_name.lower().strip())
        if company_clean:
            seeds.add(company_clean)

    permutations: Set[str] = set()

    for seed in seeds:
        # Bare name
        permutations.add(seed)
        # Separators: hyphen and dot
        for kw in KEYWORDS:
            permutations.add(f"{seed}-{kw}")
            permutations.add(f"{kw}-{seed}")

    # S3 naming constraints: 3-63 chars, lowercase alphanumeric, hyphens
    valid_names = [
        name for name in sorted(permutations)
        if 3 <= len(name) <= 63 and re.match(r"^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$", name)
    ]
    return valid_names


def classify_s3_response(status_code: int, body_text: str) -> str:
    """Classify S3 bucket access level based on HTTP response."""
    if status_code == 200:
        if "<ListBucketResult" in body_text or "<Contents>" in body_text:
            return "PUBLIC_LISTABLE"
        return "PUBLIC_LISTABLE"
    elif status_code in (403, 401):
        return "PROTECTED"
    elif status_code == 404 or "NoSuchBucket" in body_text:
        return "NON_EXISTENT"
    return "NON_EXISTENT"


def classify_azure_response(status_code: int, body_text: str) -> str:
    """Classify Azure Blob Container access level based on HTTP response."""
    if status_code == 200:
        if "<EnumerationResults" in body_text or "<Blobs>" in body_text:
            return "PUBLIC_LISTABLE"
        return "PUBLIC_LISTABLE"
    elif status_code in (403, 401):
        return "PROTECTED"
    elif status_code == 404 or "ContainerNotFound" in body_text or "AccountNotFound" in body_text:
        return "NON_EXISTENT"
    return "NON_EXISTENT"


def classify_gcp_response(status_code: int, body_text: str) -> str:
    """Classify GCP Cloud Storage access level based on HTTP response."""
    if status_code == 200:
        if "<ListBucketResult" in body_text or '"items":' in body_text:
            return "PUBLIC_LISTABLE"
        return "PUBLIC_LISTABLE"
    elif status_code in (403, 401):
        return "PROTECTED"
    elif status_code == 404 or "NoSuchBucket" in body_text:
        return "NON_EXISTENT"
    return "NON_EXISTENT"


async def check_s3_bucket(
    bucket_name: str,
    client: httpx.AsyncClient,
) -> CloudBucketAuditResult:
    """Audit AWS S3 bucket endpoint."""
    url = f"https://{bucket_name}.s3.amazonaws.com"
    try:
        resp = await client.get(url, timeout=REQUEST_TIMEOUT)
        snippet = resp.text[:512]
        level = classify_s3_response(resp.status_code, snippet)
        return CloudBucketAuditResult(
            bucket_name=bucket_name,
            provider="AWS_S3",
            url=url,
            access_level=level,
            http_status_code=resp.status_code,
            response_snippet=snippet if level != "NON_EXISTENT" else None,
            is_dangerous=level in ("PUBLIC_READ_WRITE", "PUBLIC_LISTABLE"),
        )
    except Exception as exc:
        logger.debug("S3 check failed for %s: %s", bucket_name, exc)
        return CloudBucketAuditResult(
            bucket_name=bucket_name,
            provider="AWS_S3",
            url=url,
            access_level="NON_EXISTENT",
        )


async def check_azure_container(
    bucket_name: str,
    client: httpx.AsyncClient,
) -> CloudBucketAuditResult:
    """Audit Azure Blob Container endpoint."""
    clean_name = bucket_name.replace(".", "").replace("-", "")
    url = f"https://{clean_name}.blob.core.windows.net/?comp=list"
    try:
        resp = await client.get(url, timeout=REQUEST_TIMEOUT)
        snippet = resp.text[:512]
        level = classify_azure_response(resp.status_code, snippet)
        return CloudBucketAuditResult(
            bucket_name=clean_name,
            provider="AZURE_BLOB",
            url=url,
            access_level=level,
            http_status_code=resp.status_code,
            response_snippet=snippet if level != "NON_EXISTENT" else None,
            is_dangerous=level in ("PUBLIC_READ_WRITE", "PUBLIC_LISTABLE"),
        )
    except Exception as exc:
        logger.debug("Azure check failed for %s: %s", bucket_name, exc)
        return CloudBucketAuditResult(
            bucket_name=clean_name,
            provider="AZURE_BLOB",
            url=url,
            access_level="NON_EXISTENT",
        )


async def check_gcp_bucket(
    bucket_name: str,
    client: httpx.AsyncClient,
) -> CloudBucketAuditResult:
    """Audit GCP Cloud Storage bucket endpoint."""
    url = f"https://storage.googleapis.com/{bucket_name}"
    try:
        resp = await client.get(url, timeout=REQUEST_TIMEOUT)
        snippet = resp.text[:512]
        level = classify_gcp_response(resp.status_code, snippet)
        return CloudBucketAuditResult(
            bucket_name=bucket_name,
            provider="GCP_GCS",
            url=url,
            access_level=level,
            http_status_code=resp.status_code,
            response_snippet=snippet if level != "NON_EXISTENT" else None,
            is_dangerous=level in ("PUBLIC_READ_WRITE", "PUBLIC_LISTABLE"),
        )
    except Exception as exc:
        logger.debug("GCP check failed for %s: %s", bucket_name, exc)
        return CloudBucketAuditResult(
            bucket_name=bucket_name,
            provider="GCP_GCS",
            url=url,
            access_level="NON_EXISTENT",
        )


async def audit_cloud_storage(
    domain: str,
    company_name: Optional[str] = None,
    max_concurrency: int = 20,
    client: Optional[httpx.AsyncClient] = None,
) -> List[CloudBucketAuditResult]:
    """
    Generate permutations and concurrently audit S3, Azure, and GCP buckets.
    Only returns existing buckets (PROTECTED or PUBLIC_LISTABLE / PUBLIC_READ_WRITE).
    """
    bucket_names = generate_bucket_permutations(domain, company_name)
    if not bucket_names:
        return []

    close_client = False
    if client is None:
        client = httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            follow_redirects=True,
        )
        close_client = True

    semaphore = asyncio.Semaphore(max_concurrency)

    async def _audit_single(name: str) -> List[CloudBucketAuditResult]:
        async with semaphore:
            s3_res = await check_s3_bucket(name, client)
            azure_res = await check_azure_container(name, client)
            gcp_res = await check_gcp_bucket(name, client)
            return [s3_res, azure_res, gcp_res]

    try:
        tasks = [_audit_single(name) for name in bucket_names]
        nested = await asyncio.gather(*tasks, return_exceptions=True)

        found: List[CloudBucketAuditResult] = []
        for group in nested:
            if isinstance(group, list):
                for res in group:
                    # Filter out NON_EXISTENT buckets to keep scan data clean & focused
                    if res.access_level != "NON_EXISTENT":
                        found.append(res)
        return found
    finally:
        if close_client:
            await client.aclose()
