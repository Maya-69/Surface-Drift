"""
MITRE ATT&CK Matrix Mapping Engine for SurfaceDrift
Aligns external attack surface findings with MITRE ATT&CK Enterprise Matrix tactics and techniques.
"""

from __future__ import annotations
from typing import Any, Dict, List

# Official MITRE ATT&CK Enterprise Catalog Definitions for SurfaceDrift
MITRE_CATALOG: Dict[str, Dict[str, Any]] = {
    "http_probing": {
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "subtechnique_id": "T1592.002",
        "subtechnique_name": "Gather Victim Host Information: Software",
        "mitre_url": "https://attack.mitre.org/techniques/T1046/",
        "description": "Adversaries probe host ports (80/443) and extract banners to map services and technology stacks."
    },
    "subdomain_takeovers": {
        "tactic_id": "TA0042",
        "tactic_name": "Resource Development",
        "technique_id": "T1584",
        "technique_name": "Compromise Infrastructure",
        "subtechnique_id": "T1584.001",
        "subtechnique_name": "Domains: Subdomain Takeover",
        "mitre_url": "https://attack.mitre.org/techniques/T1584/001/",
        "description": "Adversaries claim dangling CNAME records on third-party cloud services to impersonate legitimate domains."
    },
    "cloud_storage": {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1596",
        "technique_name": "Search Open Technical Databases",
        "subtechnique_id": "T1596.001",
        "subtechnique_name": "Cloud Storage Permutations (AWS S3, Azure Blob, GCP)",
        "mitre_url": "https://attack.mitre.org/techniques/T1596/001/",
        "description": "Adversaries query cloud storage endpoints to discover unauthenticated public read/write object stores."
    },
    "waf_bypass": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1564",
        "technique_name": "Hide Artifacts / Origin Exposure",
        "subtechnique_id": "T1590.005",
        "subtechnique_name": "Gather Victim Network Information: IP Addresses (Direct Origin)",
        "mitre_url": "https://attack.mitre.org/techniques/T1564/",
        "description": "Adversaries discover backend origin IPs bypassing edge CDN/WAF filters to deliver uninspected attacks."
    },
    "threat_prioritization": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "subtechnique_id": "CISA-KEV",
        "subtechnique_name": "Actively Weaponized Exploits (EPSS + CISA KEV)",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Adversaries exploit known vulnerabilities in public perimeter applications for unauthorized ingress."
    },
    "email_security": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "subtechnique_id": "T1566.002",
        "subtechnique_name": "Spearphishing Link / Unauthenticated Email Spoofing",
        "mitre_url": "https://attack.mitre.org/techniques/T1566/002/",
        "description": "Adversaries forge email sender identities when SPF and DMARC enforcement policies are permissive or missing."
    },
    "js_secrets": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "subtechnique_id": "T1552.001",
        "subtechnique_name": "Credentials In Files / Frontend JS Scripts",
        "mitre_url": "https://attack.mitre.org/techniques/T1552/001/",
        "description": "Adversaries search client-side script bundles for embedded API keys, private tokens, and cloud secrets."
    },
    "shadow_apis": {
        "tactic_id": "TA0007",
        "tactic_name": "Discovery",
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "subtechnique_id": "T1595.002",
        "subtechnique_name": "Vulnerability Scanning: Undocumented APIs & Swagger Specs",
        "mitre_url": "https://attack.mitre.org/techniques/T1595/002/",
        "description": "Adversaries probe for unauthenticated API schema endpoints (Swagger, OpenAPI, GraphQL) to map internal endpoints."
    },
    "eol_software": {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "subtechnique_id": "EOL-Legacy",
        "subtechnique_name": "Unsupported Legacy Software Runtimes",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/",
        "description": "Adversaries target unpatched and unsupported End-of-Life runtimes with known public exploit vectors."
    },
    "broken_links": {
        "tactic_id": "TA0042",
        "tactic_name": "Resource Development",
        "technique_id": "T1584",
        "technique_name": "Compromise Infrastructure",
        "subtechnique_id": "T1584.004",
        "subtechnique_name": "Broken Link Hijacking (NXDOMAIN)",
        "mitre_url": "https://attack.mitre.org/techniques/T1584/",
        "description": "Adversaries register abandoned or expired external domains linked from legitimate sites to hijack web traffic."
    },
    "waf_history": {
        "tactic_id": "TA0043",
        "tactic_name": "Reconnaissance",
        "technique_id": "T1596",
        "technique_name": "Search Open Technical Databases",
        "subtechnique_id": "T1596.002",
        "subtechnique_name": "Historical DNS & Certificate Transparency",
        "mitre_url": "https://attack.mitre.org/techniques/T1596/002/",
        "description": "Adversaries inspect historical DNS and SSL records to locate pre-CDN backend IP infrastructure."
    },
    "exposed_configs": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials",
        "subtechnique_id": "T1552.005",
        "subtechnique_name": "Exposed Configurations (.env, .git, Backups)",
        "mitre_url": "https://attack.mitre.org/techniques/T1552/005/",
        "description": "Adversaries download exposed environment and version control files to extract private credentials and secrets."
    },
    "tls_posture": {
        "tactic_id": "TA0005",
        "tactic_name": "Defense Evasion",
        "technique_id": "T1588",
        "technique_name": "Obtain Capabilities",
        "subtechnique_id": "T1588.003",
        "subtechnique_name": "Weak Cryptographic Ciphers & Missing HSTS",
        "mitre_url": "https://attack.mitre.org/techniques/T1588/003/",
        "description": "Adversaries exploit legacy TLS protocols or missing HSTS to stage Man-in-the-Middle (MitM) traffic interception."
    },
    "breach_intel": {
        "tactic_id": "TA0006",
        "tactic_name": "Credential Access",
        "technique_id": "T1589",
        "technique_name": "Gather Victim Identity Information",
        "subtechnique_id": "T1589.001",
        "subtechnique_name": "Credentials: Leaked Corporate Account Credentials",
        "mitre_url": "https://attack.mitre.org/techniques/T1589/001/",
        "description": "Adversaries utilize public breach dumps containing corporate emails to conduct credential stuffing and password spraying."
    },
    "typosquatting": {
        "tactic_id": "TA0042",
        "tactic_name": "Resource Development",
        "technique_id": "T1583",
        "technique_name": "Acquire Infrastructure",
        "subtechnique_id": "T1583.001",
        "subtechnique_name": "Domains: Typosquatting & Lookalike Phishing Domains",
        "mitre_url": "https://attack.mitre.org/techniques/T1583/001/",
        "description": "Adversaries acquire similar brand domains to stage impersonation attacks against employees or clients."
    }
}


def generate_mitre_matrix(findings: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates SurfaceDrift findings and returns a structured MITRE ATT&CK coverage breakdown.
    """
    tactics: Dict[str, Dict[str, Any]] = {
        "TA0043": {"name": "Reconnaissance", "techniques": [], "finding_count": 0, "has_critical": False},
        "TA0042": {"name": "Resource Development", "techniques": [], "finding_count": 0, "has_critical": False},
        "TA0001": {"name": "Initial Access", "techniques": [], "finding_count": 0, "has_critical": False},
        "TA0005": {"name": "Defense Evasion", "techniques": [], "finding_count": 0, "has_critical": False},
        "TA0006": {"name": "Credential Access", "techniques": [], "finding_count": 0, "has_critical": False},
        "TA0007": {"name": "Discovery", "techniques": [], "finding_count": 0, "has_critical": False},
    }

    technique_entries: List[Dict[str, Any]] = []

    for key, meta in MITRE_CATALOG.items():
        finding_data = findings.get(key)
        has_findings = False
        count = 0
        severity = "INFO"

        if key == "http_probing" and finding_data:
            count = finding_data.get("live_hosts_count", 0)
            has_findings = count > 0
            severity = "LOW"
        elif key == "subdomain_takeovers" and finding_data:
            count = finding_data.get("count", 0)
            has_findings = count > 0
            severity = "CRITICAL" if count > 0 else "INFO"
        elif key == "cloud_storage" and finding_data:
            count = finding_data.get("public_count", 0)
            has_findings = count > 0
            severity = "HIGH" if count > 0 else "INFO"
        elif key == "waf_bypass" and finding_data:
            count = finding_data.get("count", 0)
            has_findings = count > 0
            severity = "HIGH" if count > 0 else "INFO"
        elif key == "threat_prioritization" and finding_data:
            crit = finding_data.get("critical_count", 0)
            high = finding_data.get("high_count", 0)
            count = crit + high
            has_findings = count > 0
            severity = "CRITICAL" if crit > 0 else ("HIGH" if high > 0 else "INFO")
        elif key == "email_security" and finding_data:
            has_findings = bool(finding_data.get("spoofable"))
            count = 1 if has_findings else 0
            severity = "HIGH" if has_findings else "LOW"
        elif key == "js_secrets" and finding_data:
            count = finding_data.get("secrets_found_count", 0)
            has_findings = count > 0
            severity = "HIGH" if count > 0 else "INFO"
        elif key == "shadow_apis" and finding_data:
            count = finding_data.get("exposed_endpoints_count", 0)
            has_findings = count > 0
            severity = "MEDIUM" if count > 0 else "INFO"
        elif key == "eol_software" and finding_data:
            count = finding_data.get("eol_findings_count", 0)
            has_findings = count > 0
            severity = "MEDIUM" if count > 0 else "INFO"
        elif key == "broken_links" and finding_data:
            count = finding_data.get("broken_links_found", 0)
            has_findings = count > 0
            severity = "HIGH" if count > 0 else "INFO"
        elif key == "waf_history" and finding_data:
            count = finding_data.get("origin_bypasses_found", 0)
            has_findings = count > 0
            severity = "HIGH" if count > 0 else "INFO"
        elif key == "exposed_configs" and finding_data:
            count = finding_data.get("exposed_configs_found", 0)
            has_findings = count > 0
            severity = "CRITICAL" if count > 0 else "INFO"
        elif key == "tls_posture" and finding_data:
            weak = finding_data.get("weak_protocol_count", 0)
            exp = finding_data.get("expiring_soon_count", 0)
            count = weak + exp
            has_findings = count > 0
            severity = "MEDIUM" if count > 0 else "INFO"
        elif key == "breach_intel" and finding_data:
            count = finding_data.get("compromised_identities_count", 0)
            has_findings = count > 0
            severity = "HIGH" if count > 0 else "INFO"
        elif key == "typosquatting" and finding_data:
            count = finding_data.get("active_threats_count", 0)
            has_findings = count > 0
            severity = "MEDIUM" if count > 0 else "INFO"

        entry = {
            "key": key,
            "tactic_id": meta["tactic_id"],
            "tactic_name": meta["tactic_name"],
            "technique_id": meta["technique_id"],
            "technique_name": meta["technique_name"],
            "subtechnique_id": meta["subtechnique_id"],
            "subtechnique_name": meta["subtechnique_name"],
            "mitre_url": meta["mitre_url"],
            "description": meta["description"],
            "has_findings": has_findings,
            "findings_count": count,
            "severity": severity,
        }
        technique_entries.append(entry)

        # Aggregate to tactic
        t_id = meta["tactic_id"]
        if t_id in tactics:
            tactics[t_id]["techniques"].append(entry)
            if has_findings:
                tactics[t_id]["finding_count"] += count
                if severity in {"CRITICAL", "HIGH"}:
                    tactics[t_id]["has_critical"] = True

    total_techniques_audited = len(technique_entries)
    techniques_with_findings = sum(1 for t in technique_entries if t["has_findings"])
    tactics_with_findings = sum(1 for t in tactics.values() if t["finding_count"] > 0)

    return {
        "framework": "MITRE ATT&CK Enterprise Matrix v15",
        "tactics": tactics,
        "techniques": technique_entries,
        "summary": {
            "total_tactics_monitored": len(tactics),
            "tactics_with_exposure": tactics_with_findings,
            "total_techniques_audited": total_techniques_audited,
            "techniques_with_findings": techniques_with_findings,
        }
    }
