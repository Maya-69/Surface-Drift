from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def generate_automated_playbooks(
    target_domain: str,
    findings: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Synthesize actionable copy-paste CLI commands, DNS records, and configuration snippets
    for every detected vulnerability or security gap.
    """
    playbooks: List[Dict[str, Any]] = []
    clean_domain = target_domain.lower().strip()

    # 1. Email Security: DMARC Remediation
    email_sec = findings.get("email_security", {})
    if email_sec.get("spoofable") or email_sec.get("dmarc_status") == "NOT_FOUND":
        snip = f'_dmarc.{clean_domain}.  3600  IN  TXT  "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@{clean_domain}; ruf=mailto:dmarc-forensics@{clean_domain}; adkim=s; aspf=s;"'
        desc = "RFC 7489 standard DMARC policy instruction. Rejects any spoofed email pretending to originate from your organization at the recipient mail server."
        playbooks.append({
            "id": "playbook-dmarc-enforce",
            "title": f"Enforce Strict DMARC Reject Policy for @{clean_domain}",
            "category": "Email Security & Identity",
            "severity": "HIGH",
            "affected_asset": clean_domain,
            "action_type": "DNS TXT Record",
            "snippet_language": "dns",
            "snippet": snip,
            "code_snippet": snip,
            "explanation": desc,
            "description": desc,
        })

    # 2. Email Security: SPF Hard-Fail Upgrade
    if email_sec.get("spf_all_mechanism") in ("~all", "?all", "+all"):
        snip = f'{clean_domain}.  3600  IN  TXT  "v=spf1 include:_spf.google.com include:mailgun.org -all"'
        desc = "Replaces soft-fail (~all) with hard-fail (-all) to prevent unauthenticated relay abuse."
        playbooks.append({
            "id": "playbook-spf-harden",
            "title": f"Upgrade SPF Mechanism to Strict Hard-Fail (-all)",
            "category": "Email Security & Identity",
            "severity": "MEDIUM",
            "affected_asset": clean_domain,
            "action_type": "DNS TXT Record",
            "snippet_language": "dns",
            "snippet": snip,
            "code_snippet": snip,
            "explanation": desc,
            "description": desc,
        })

    # 3. Public Cloud Storage Buckets
    cloud_data = findings.get("cloud_storage", {})
    for bucket in cloud_data.get("buckets", []):
        if bucket.get("is_dangerous") or bucket.get("access_level") in ("PUBLIC_READ_WRITE", "PUBLIC_LISTABLE"):
            b_name = bucket.get("bucket_name", "target-bucket")
            snip = (
                f"aws s3api put-public-access-block \\\n"
                f"  --bucket {b_name} \\\n"
                f'  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"'
            )
            desc = "Enforces AWS S3 Public Access Block at bucket level, immediately revoking public list and download permissions."
            playbooks.append({
                "id": f"playbook-s3-block-{b_name}",
                "title": f"Block All Public Access to AWS S3 Bucket: '{b_name}'",
                "category": "Cloud Storage (AWS S3)",
                "severity": "CRITICAL",
                "affected_asset": b_name,
                "action_type": "AWS CLI Command",
                "snippet_language": "bash",
                "snippet": snip,
                "code_snippet": snip,
                "explanation": desc,
                "description": desc,
            })

    # 4. Subdomain Takeovers
    takeovers = findings.get("subdomain_takeovers", {}).get("items", [])
    for t in takeovers:
        sub = t.get("subdomain", f"sub.{clean_domain}")
        cname = t.get("cname", "orphaned.service.com")
        snip = (
            f"# In your authoritative DNS provider (Cloudflare, Route53, GoDaddy):\n"
            f"# Delete orphaned CNAME record to prevent hostile subdomain takeover:\n"
            f"# Record Host: {sub}\n"
            f"# CNAME Target: {cname}"
        )
        desc = f"The third-party service '{t.get('service', 'Cloud')}' was deleted, but the CNAME remains. Deleting the CNAME prevents adversaries from registering the dangling endpoint."
        playbooks.append({
            "id": f"playbook-takeover-{sub}",
            "title": f"Remove Orphaned CNAME Pointer for Subdomain Takeover: '{sub}'",
            "category": "DNS Hygiene & Asset Management",
            "severity": "CRITICAL",
            "affected_asset": sub,
            "action_type": "DNS De-provisioning",
            "snippet_language": "bash",
            "snippet": snip,
            "code_snippet": snip,
            "explanation": desc,
            "description": desc,
        })

    # 5. Missing HSTS Header / Weak TLS
    tls_data = findings.get("tls_posture", {})
    for cert in tls_data.get("certificates", []):
        if cert.get("missing_hsts"):
            h = cert.get("hostname", clean_domain)
            snip = (
                "# Nginx Server Block:\n"
                'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n\n'
                "# Apache VirtualHost Block:\n"
                'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"'
            )
            desc = "Prevents SSL stripping attacks and cookie hijacking by instructing modern web browsers to communicate exclusively over HTTPS."
            playbooks.append({
                "id": f"playbook-hsts-{h}",
                "title": f"Enable HTTP Strict Transport Security (HSTS) on '{h}'",
                "category": "Cryptographic Posture",
                "severity": "MEDIUM",
                "affected_asset": h,
                "action_type": "Web Server Config",
                "snippet_language": "nginx",
                "snippet": snip,
                "code_snippet": snip,
                "explanation": desc,
                "description": desc,
            })
            break

    # 6. Exposed Sensitive Configuration / Git Repositories
    configs = findings.get("exposed_configs", {}).get("exposed_files", [])
    for cfg in configs:
        path = cfg.get("path", "/.env")
        snip = (
            "# Nginx configuration (add inside server {} block):\n"
            "location ~* /\\.(?:git|env|svn|hg) {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}\n\n"
            "# Deny access to archive/backup artifacts:\n"
            "location ~* \\.(?:zip|tar|tar\\.gz|sql|bak|backup|config)$ {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        )
        desc = "Restricts the web server from serving hidden repository directories (.git), credentials (.env), and database backup archives."
        playbooks.append({
            "id": f"playbook-config-{path.replace('/', '-')}",
            "title": f"Block Public Access to Sensitive File: '{path}'",
            "category": "Web Server Hardening",
            "severity": "CRITICAL",
            "affected_asset": path,
            "action_type": "Nginx Security Block",
            "snippet_language": "nginx",
            "snippet": snip,
            "code_snippet": snip,
            "explanation": desc,
            "description": desc,
        })
        break

    # 7. Leaked Secrets in JavaScript
    secrets = findings.get("js_secrets", {}).get("findings", [])
    for sec in secrets:
        s_type = sec.get("secret_type", "API Key")
        redacted = sec.get("redacted_value", "REDACTED")
        snip = (
            f"# 1. Immediately revoke this {s_type} in your cloud/SaaS console.\n"
            "# 2. Re-issue key with restrictive IP and domain constraints.\n"
            "# 3. Purge key from git revision history:\n"
            f'git filter-repo --replace-text <(echo "{redacted}==>REDACTED_KEY")'
        )
        desc = "Client-side credentials can be harvested by any visitor. Move API calls to server-side backend proxies."
        playbooks.append({
            "id": "playbook-secrets-revoke",
            "title": f"Revoke and Rotate Leaked {s_type} in JavaScript Bundle",
            "category": "Secret & Key Management",
            "severity": "HIGH",
            "affected_asset": sec.get("script_url", clean_domain),
            "action_type": "Secret Revocation & Purge",
            "snippet_language": "bash",
            "snippet": snip,
            "code_snippet": snip,
            "explanation": desc,
            "description": desc,
        })
        break

    # 8. Typosquatting Brand Defense
    squats = findings.get("typosquatting", {}).get("active_squats", [])
    for sq in squats:
        if sq.get("has_mx"):
            sq_dom = sq.get("domain")
            mx_list = ", ".join(sq.get("mx_hosts", []))
            snip = (
                f"Subject: URGENT: Phishing Domain Takedown Request — {sq_dom}\n\n"
                "To the Abuse Desk of Registrar / Hosting Provider:\n\n"
                f'We have detected an active brand impersonation domain "{sq_dom}" targeting our legitimate domain "{clean_domain}".\n'
                f"This domain is actively configured with MX mail exchangers ({mx_list}) and is being used for unauthorized phishing / business email compromise.\n\n"
                f"Please immediately suspend DNS delegation for domain {sq_dom} pursuant to your Acceptable Use Policy."
            )
            desc = "Active lookalikes with mail records indicate targeted phishing. Immediate registrar notification shuts down attacker email infrastructure."
            playbooks.append({
                "id": f"playbook-squat-{sq_dom}",
                "title": f"Submit Takedown Notice for Active Phishing Typosquat: '{sq_dom}'",
                "category": "Brand Protection & Threat Intel",
                "severity": "CRITICAL",
                "affected_asset": sq_dom,
                "action_type": "Registrar Takedown Notice",
                "snippet_language": "text",
                "snippet": snip,
                "code_snippet": snip,
                "explanation": desc,
                "description": desc,
            })
            break

    # Default fallback playbook if perimeter is clean
    if not playbooks:
        snip = (
            "# Continuous monitoring curl check:\n"
            f'curl -s -X POST https://api.surfacedrift.io/api/v1/scans -H "Content-Type: application/json" -d \'{{"target_domain": "{clean_domain}"}}\''
        )
        desc = "No critical vulnerabilities or misconfigurations detected. Maintain scheduled recurring drift scans."
        playbooks.append({
            "id": "playbook-baseline-clean",
            "title": f"Perimeter Hardening Verification for {clean_domain}",
            "category": "Continuous Threat Exposure Management",
            "severity": "INFO",
            "affected_asset": clean_domain,
            "action_type": "Scheduled CTEM Scan",
            "snippet_language": "bash",
            "snippet": snip,
            "code_snippet": snip,
            "explanation": desc,
            "description": desc,
        })

    return playbooks
