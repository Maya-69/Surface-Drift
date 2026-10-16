from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Set, Tuple

import dns.asyncresolver
import dns.resolver

logger = logging.getLogger(__name__)

# Common homoglyph mappings (visual lookalikes)
HOMOGLYPHS = {
    "o": ["0"],
    "l": ["1", "i"],
    "i": ["1", "l"],
    "e": ["3"],
    "a": ["4"],
    "s": ["5"],
    "w": ["vv"],
    "m": ["rn"],
}

COMMON_PHISHING_PREFIXES = ["login-", "verify-", "account-", "secure-", "auth-"]
ALTERNATIVE_TLDS = [".co", ".net", ".org", ".io", ".info", ".security", ".xyz", ".cc"]


def generate_domain_permutations(root_domain: str, max_permutations: int = 24) -> List[Tuple[str, str]]:
    """
    Generate typosquatting, brand impersonation, and homoglyph lookalike domain permutations.
    Returns: List of (permuted_domain, variation_type)
    """
    clean = root_domain.lower().strip()
    if "." not in clean:
        return []

    parts = clean.split(".")
    name = parts[0]
    tld = "." + ".".join(parts[1:])

    permutations: List[Tuple[str, str]] = []
    seen: Set[str] = {clean}

    # 1. Homoglyphs (lookalikes)
    for char, subs in HOMOGLYPHS.items():
        if char in name:
            for sub in subs:
                perm = name.replace(char, sub, 1) + tld
                if perm not in seen:
                    seen.add(perm)
                    permutations.append((perm, "Homoglyph / Lookalike"))

    # 2. Character Omission (common typing mistakes)
    if len(name) > 3:
        for i in range(len(name)):
            omitted = name[:i] + name[i+1:]
            perm = omitted + tld
            if perm not in seen:
                seen.add(perm)
                permutations.append((perm, "Character Omission"))

    # 3. Transposition (swapped adjacent letters)
    for i in range(len(name) - 1):
        swapped = name[:i] + name[i+1] + name[i] + name[i+2:]
        perm = swapped + tld
        if perm not in seen:
            seen.add(perm)
            permutations.append((perm, "Character Transposition"))

    # 4. Phishing Prefix
    for pfx in COMMON_PHISHING_PREFIXES:
        perm = pfx + name + tld
        if perm not in seen:
            seen.add(perm)
            permutations.append((perm, "Phishing Prefix"))

    # 5. Alternative TLD swaps
    for alt_tld in ALTERNATIVE_TLDS:
        if alt_tld != tld:
            perm = name + alt_tld
            if perm not in seen:
                seen.add(perm)
                permutations.append((perm, "TLD Swap"))

    return permutations[:max_permutations]


async def resolve_squat_domain(
    perm_domain: str,
    variation_type: str,
    resolver: dns.asyncresolver.Resolver,
) -> Optional[Dict[str, Any]]:
    """
    Check if a lookalike domain is registered and resolves to an IP.
    If active, checks for MX mail server records indicating weaponized phishing capability.
    """
    try:
        # Check A record
        a_answers = await resolver.resolve(perm_domain, "A")
        ips = [str(rdata) for rdata in a_answers]
        if not ips:
            return None

        # Check MX records
        has_mx = False
        mx_hosts: List[str] = []
        try:
            mx_answers = await resolver.resolve(perm_domain, "MX")
            mx_hosts = [str(r.exchange).rstrip(".") for r in mx_answers]
            has_mx = len(mx_hosts) > 0
        except Exception:
            pass

        threat_level = "CRITICAL" if has_mx else "HIGH"
        risk_desc = (
            "Active Lookalike with Mail Servers (Active Phishing/Weaponized Email Threat)"
            if has_mx
            else "Active Lookalike Resolving to IP (Brand Impersonation / Potential Squat)"
        )

        return {
            "domain": perm_domain,
            "variation_type": variation_type,
            "ip_addresses": ips,
            "primary_ip": ips[0],
            "has_mx": has_mx,
            "mx_hosts": mx_hosts,
            "threat_level": threat_level,
            "severity": threat_level,
            "description": risk_desc,
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None
    except Exception:
        return None


async def audit_typosquatting_threats(
    root_domain: str,
    max_permutations: int = 20,
    concurrency: int = 10,
) -> Dict[str, Any]:
    """
    Generate brand permutations and query DNS asynchronously for active lookalikes and phishing mailservers.
    """
    permutations = generate_domain_permutations(root_domain, max_permutations=max_permutations)

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 1.5
    resolver.lifetime = 1.8
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded_check(domain: str, v_type: str):
        async with semaphore:
            return await resolve_squat_domain(domain, v_type, resolver)

    tasks = [_bounded_check(d, vt) for d, vt in permutations]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    active_squats = [r for r in results if isinstance(r, dict) and r is not None]
    weaponized_count = sum(1 for s in active_squats if s.get("has_mx"))

    return {
        "root_domain": root_domain,
        "permutations_tested_count": len(permutations),
        "active_squats_count": len(active_squats),
        "weaponized_phishing_count": weaponized_count,
        "active_squats": active_squats,
    }
