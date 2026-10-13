from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

import dns.asyncresolver

logger = logging.getLogger(__name__)


def parse_spf_record(txt_records: List[str]) -> Tuple[Optional[str], str, Optional[str]]:
    """
    Parse SPF record from list of TXT records.
    Returns: (record_text, status, all_mechanism)
    status: STRICT (-all), SOFT_FAIL (~all), NEUTRAL (?all), PERMISSIVE (+all), NOT_FOUND
    """
    for txt in txt_records:
        cleaned = txt.strip().strip('"')
        if cleaned.startswith("v=spf1") or "v=spf1 " in cleaned:
            # Match ending 'all' mechanism
            match = re.search(r"([\+\-\~\?]?all)\b", cleaned, re.IGNORECASE)
            mech = match.group(1).lower() if match else None

            if mech == "-all":
                status = "STRICT"
            elif mech == "~all":
                status = "SOFT_FAIL"
            elif mech == "+all":
                status = "PERMISSIVE"
            elif mech == "?all":
                status = "NEUTRAL"
            else:
                status = "NONE"

            return cleaned, status, mech

    return None, "NOT_FOUND", None


def parse_dmarc_record(
    txt_records: List[str],
) -> Tuple[Optional[str], str, Optional[str], Optional[int]]:
    """
    Parse DMARC record from list of TXT records.
    Returns: (record_text, status, policy, pct)
    status: REJECT, QUARANTINE, NONE, NOT_FOUND
    """
    for txt in txt_records:
        cleaned = txt.strip().strip('"')
        if cleaned.startswith("v=DMARC1") or "v=DMARC1;" in cleaned:
            # Policy match
            policy_match = re.search(r"\bp=([a-zA-Z]+)", cleaned, re.IGNORECASE)
            policy = policy_match.group(1).lower() if policy_match else None

            # Percentage match
            pct_match = re.search(r"\bpct=([0-9]+)", cleaned, re.IGNORECASE)
            pct = int(pct_match.group(1)) if pct_match else 100

            if policy == "reject":
                status = "REJECT"
            elif policy == "quarantine":
                status = "QUARANTINE"
            elif policy == "none":
                status = "NONE"
            else:
                status = "NONE"

            return cleaned, status, policy, pct

    return None, "NOT_FOUND", None, None


def evaluate_email_spoofability(
    spf_status: str,
    dmarc_status: str,
    dmarc_pct: Optional[int] = 100,
) -> Tuple[bool, str]:
    """
    Assess whether the target domain can be trivially spoofed in phishing/BEC campaigns:
    - SECURE_ENFORCED: DMARC is REJECT (or QUARANTINE with 100% enforcement) and SPF is not permissive.
    - WEAK_POLICY: DMARC is QUARANTINE with pct < 100, or SPF SOFT_FAIL without DMARC enforcement.
    - TRIVIAL_SPOOFING_POSSIBLE: DMARC is NONE or missing, or SPF is +all/missing.
    Returns: (spoofable: bool, risk_flag: str)
    """
    pct = dmarc_pct if dmarc_pct is not None else 100

    if dmarc_status == "REJECT" and pct == 100:
        return False, "SECURE_ENFORCED"

    if dmarc_status == "QUARANTINE" and pct == 100 and spf_status in ("STRICT", "SOFT_FAIL"):
        return False, "SECURE_ENFORCED"

    if dmarc_status == "QUARANTINE" and pct < 100:
        return True, "WEAK_POLICY"

    if dmarc_status == "NONE":
        return True, "TRIVIAL_SPOOFING_POSSIBLE"

    if dmarc_status == "NOT_FOUND":
        if spf_status == "STRICT":
            return True, "WEAK_POLICY"
        return True, "TRIVIAL_SPOOFING_POSSIBLE"

    return True, "TRIVIAL_SPOOFING_POSSIBLE"


async def audit_email_security(domain: str) -> Dict[str, any]:
    """
    Query DNS TXT for SPF and _dmarc records and evaluate spoofing posture.
    """
    clean_domain = domain.lower().strip().lstrip("http://").lstrip("https://").rstrip("/")
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.5

    # 1. Query root TXT for SPF
    root_txt: List[str] = []
    try:
        answers = await resolver.resolve(clean_domain, "TXT")
        for rdata in answers:
            root_txt.append(str(rdata))
    except Exception:
        pass

    # 2. Query _dmarc.{domain} for DMARC
    dmarc_txt: List[str] = []
    try:
        answers = await resolver.resolve(f"_dmarc.{clean_domain}", "TXT")
        for rdata in answers:
            dmarc_txt.append(str(rdata))
    except Exception:
        pass

    spf_rec, spf_status, all_mech = parse_spf_record(root_txt)
    dmarc_rec, dmarc_status, policy, pct = parse_dmarc_record(dmarc_txt)
    spoofable, risk_flag = evaluate_email_spoofability(spf_status, dmarc_status, pct)

    return {
        "spf_record": spf_rec,
        "spf_status": spf_status,
        "spf_all_mechanism": all_mech,
        "dmarc_record": dmarc_rec,
        "dmarc_status": dmarc_status,
        "dmarc_policy": policy,
        "dmarc_pct": pct,
        "spoofable": spoofable,
        "risk_flag": risk_flag,
    }
