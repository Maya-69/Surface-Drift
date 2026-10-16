from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Sensitive / Admin ports exposed directly to the public internet
ADMIN_PORTS = {
    6379: "Redis Database",
    27017: "MongoDB Database",
    9200: "Elasticsearch Cluster",
    3389: "Microsoft RDP Remote Desktop",
    23: "Insecure Telnet",
    5432: "PostgreSQL Database",
    3306: "MySQL Database",
}


@dataclass
class ScoreBreakdownItem:
    """Individual deduction reason."""
    category: str
    description: str
    deduction: int


@dataclass
class RiskEvaluation:
    """Composite risk score and letter grade with itemized deduction trail."""
    score: int
    grade: str
    breakdown: List[ScoreBreakdownItem] = field(default_factory=list)


def calculate_risk_score(
    critical_vulns_count: int = 0,
    high_vulns_count: int = 0,
    takeovers_count: int = 0,
    public_buckets_count: int = 0,
    exposed_admin_ports_count: int = 0,
    waf_bypass_count: int = 0,
    email_risk_flag: str = "SECURE_ENFORCED",
    exposed_configs_count: int = 0,
    leaked_secrets_count: int = 0,
    shadow_apis_count: int = 0,
    eol_findings_count: int = 0,
    broken_links_count: int = 0,
) -> RiskEvaluation:
    """
    Compute enterprise attack surface composite score (0-100) and letter grade (A-F).
    """
    score = 100
    breakdown: List[ScoreBreakdownItem] = []

    # 1. Critical Weaponized Vulnerabilities (KEV or EPSS > 0.60): -35 each
    if critical_vulns_count > 0:
        deduction = critical_vulns_count * 35
        score -= deduction
        breakdown.append(
            ScoreBreakdownItem(
                category="VULNERABILITY",
                description=f"{critical_vulns_count} weaponized or CISA KEV vulnerability found",
                deduction=deduction,
            )
        )

    # 2. Confirmed Subdomain Takeovers: -30 each
    if takeovers_count > 0:
        deduction = takeovers_count * 30
        score -= deduction
        breakdown.append(
            ScoreBreakdownItem(
                category="SUBDOMAIN_TAKEOVER",
                description=f"{takeovers_count} verified subdomain takeover vulnerability",
                deduction=deduction,
            )
        )

    # 3. Public Cloud Storage Buckets (PUBLIC_LISTABLE / READ_WRITE): -25 each
    if public_buckets_count > 0:
        deduction = public_buckets_count * 25
        score -= deduction
        breakdown.append(
            ScoreBreakdownItem(
                category="CLOUD_EXPOSURE",
                description=f"{public_buckets_count} publicly accessible cloud storage bucket",
                deduction=deduction,
            )
        )

    # 4. Unprotected Database / Admin Ports: -20 each
    if exposed_admin_ports_count > 0:
        deduction = exposed_admin_ports_count * 20
        score -= deduction
        breakdown.append(
            ScoreBreakdownItem(
                category="PORT_EXPOSURE",
                description=f"{exposed_admin_ports_count} unauthenticated or sensitive database/admin port exposed",
                deduction=deduction,
            )
        )

    # 5. Email Security Posture
    if email_risk_flag == "TRIVIAL_SPOOFING_POSSIBLE":
        score -= 20
        breakdown.append(
            ScoreBreakdownItem(
                category="EMAIL_SECURITY",
                description="Trivial email spoofing possible (missing or p=none DMARC)",
                deduction=20,
            )
        )
    elif email_risk_flag == "WEAK_POLICY":
        score -= 10
        breakdown.append(
            ScoreBreakdownItem(
                category="EMAIL_SECURITY",
                description="Weak email security policy (~all without full DMARC enforcement)",
                deduction=10,
            )
        )

    # 6. High Severity CVEs (CVSS >= 7.0): -15 each
    if high_vulns_count > 0:
        deduction = high_vulns_count * 15
        score -= deduction
        breakdown.append(
            ScoreBreakdownItem(
                category="VULNERABILITY",
                description=f"{high_vulns_count} high-severity CVE vulnerability",
                deduction=deduction,
            )
        )

    # 7. WAF Origin Bypass Discovered: -15
    if waf_bypass_count > 0:
        deduction = min(waf_bypass_count * 15, 30)
        score -= deduction
        breakdown.append(
            ScoreBreakdownItem(
                category="INFRASTRUCTURE",
                description=f"{waf_bypass_count} potential WAF / CDN origin IP bypass detected",
                deduction=deduction,
            )
        )

    # 8. Exposed Configuration Files (/.git, /.env, backup.zip): -25 each
    if exposed_configs_count > 0:
        deduction = min(exposed_configs_count * 25, 40)
        score -= deduction
        breakdown.append(
            ScoreBreakdownItem(
                category="EXPOSED_CONFIG",
                description=f"{exposed_configs_count} exposed sensitive configuration or backup file",
                deduction=deduction,
            )
        )

    # 9. Leaked Credentials / Secrets in JavaScript: -25 each
    if leaked_secrets_count > 0:
        deduction = min(leaked_secrets_count * 25, 40)
        score -= deduction
        breakdown.append(
            ScoreBreakdownItem(
                category="LEAKED_SECRET",
                description=f"{leaked_secrets_count} hardcoded credentials or API tokens leaked in client-side JS",
                deduction=deduction,
            )
        )

    # 10. Shadow APIs & Unauthenticated Swagger / GraphQL Introspection: -10 each
    if shadow_apis_count > 0:
        deduction = min(shadow_apis_count * 10, 20)
        score -= deduction
        breakdown.append(
            ScoreBreakdownItem(
                category="SHADOW_API",
                description=f"{shadow_apis_count} exposed API documentation or enabled GraphQL introspection",
                deduction=deduction,
            )
        )

    # 11. End-of-Life & Legacy Stack: -10 each
    if eol_findings_count > 0:
        deduction = min(eol_findings_count * 10, 20)
        score -= deduction
        breakdown.append(
            ScoreBreakdownItem(
                category="EOL_SOFTWARE",
                description=f"{eol_findings_count} End-of-Life or vulnerable runtime dependency",
                deduction=deduction,
            )
        )

    # 12. Broken Link Hijacking (NXDOMAIN external links): -10 each
    if broken_links_count > 0:
        deduction = min(broken_links_count * 10, 20)
        score -= deduction
        breakdown.append(
            ScoreBreakdownItem(
                category="LINK_HIJACKING",
                description=f"{broken_links_count} expired external domain in outbound links (BLH risk)",
                deduction=deduction,
            )
        )

    # Clamp score between 0 and 100
    clamped_score = max(0, min(100, score))

    # Convert to grade
    if clamped_score >= 90:
        grade = "A"
    elif clamped_score >= 80:
        grade = "B"
    elif clamped_score >= 70:
        grade = "C"
    elif clamped_score >= 60:
        grade = "D"
    else:
        grade = "F"

    return RiskEvaluation(
        score=clamped_score,
        grade=grade,
        breakdown=breakdown,
    )
