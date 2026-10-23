"""
SurfaceDrift Attack Graph Engine
Constructs directed multi-hop attack path graphs from reconnaissance and CTEM findings.
Models adversary traversal from perimeter assets to high-impact compromise sinks.
"""

from __future__ import annotations
from typing import Any, Dict, List, Set


def build_attack_graph(
    target: str,
    subdomains: List[str],
    ip_records: List[Dict[str, Any]],
    advanced_findings: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Builds a directed node-link attack graph and extracts distinct exploit attack chains.
    """
    nodes: List[Dict[str, Any]] = []
    links: List[Dict[str, Any]] = []
    seen_nodes: Set[str] = set()

    def add_node(node_id: str, label: str, node_type: str, severity: str = "INFO", meta: Dict[str, Any] = None) -> None:
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({
                "id": node_id,
                "label": label,
                "type": node_type,  # 'target', 'subdomain', 'ip', 'exposure', 'impact'
                "severity": severity,  # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
                "meta": meta or {}
            })

    def add_link(source: str, target_id: str, label: str = "", severity: str = "INFO") -> None:
        links.append({
            "source": source,
            "target": target_id,
            "label": label,
            "severity": severity
        })

    target_id = f"target_{target}"
    add_node(target_id, target, "target", "INFO", {"role": "Primary Scope"})

    # 1. Map Subdomain Assets (up to top 15 for readable visual graph)
    sample_subs = [s for s in subdomains if s and s != target][:15]
    for sub in sample_subs:
        s_id = f"sub_{sub}"
        add_node(s_id, sub, "subdomain", "LOW", {"fqdn": sub})
        add_link(target_id, s_id, "DNS Resolves", "INFO")

    # 2. Map IPs & WAF/CDN Infrastructure
    for ip_data in ip_records[:10]:
        ip_addr = ip_data.get("ip") or ip_data.get("ip_address") or ""
        if not ip_addr:
            continue
        ip_id = f"ip_{ip_addr}"
        is_cdn = bool(ip_data.get("is_cdn"))
        is_bypass = bool(ip_data.get("is_waf_bypass"))
        asn_name = ip_data.get("asn_description") or ip_data.get("cloud_provider") or "Direct Origin"

        sev = "HIGH" if is_bypass else ("LOW" if is_cdn else "INFO")
        lbl = f"{ip_addr} ({'WAF Bypass' if is_bypass else ('CDN Edge' if is_cdn else asn_name[:12])})"
        add_node(ip_id, lbl, "ip", sev, {"ip": ip_addr, "asn": asn_name, "is_bypass": is_bypass})

        # Link from target or subdomains
        add_link(target_id, ip_id, "Hosts", sev)

    # 3. Process High-Impact CTEM Findings into Multi-hop Attack Chains
    attack_chains: List[Dict[str, Any]] = []

    # A. Subdomain Takeover Chain
    takeovers = advanced_findings.get("subdomain_takeovers", {}).get("items") or []
    for idx, t in enumerate(takeovers[:5]):
        sub = t.get("subdomain", "")
        service = t.get("service", "Cloud Service")
        cname = t.get("cname", "")
        s_id = f"sub_{sub}"
        add_node(s_id, sub, "subdomain", "CRITICAL", {"cname": cname})

        exp_id = f"exp_takeover_{idx}"
        add_node(exp_id, f"Dangling CNAME ({service})", "exposure", "CRITICAL", {"cname": cname, "service": service})
        add_link(s_id, exp_id, "Points to Unclaimed", "CRITICAL")

        sink_id = f"sink_takeover_{idx}"
        add_node(sink_id, f"Full Impersonation & Session Hijack ({sub})", "impact", "CRITICAL", {"impact": "Domain Hijack"})
        add_link(exp_id, sink_id, "Enables Adversary", "CRITICAL")

        attack_chains.append({
            "title": f"Subdomain Takeover: {sub}",
            "severity": "CRITICAL",
            "path": [target, sub, f"Dangling {service} ({cname})", "Domain Impersonation / Cookie Theft"],
            "mitre": "T1584.001"
        })

    # B. WAF Origin Bypass Chain
    waf_bypasses = advanced_findings.get("waf_bypass", {}).get("origins") or []
    for idx, wb in enumerate(waf_bypasses[:3]):
        origin_ip = wb.get("ip_address") or wb.get("ip") or ""
        ip_id = f"ip_{origin_ip}"
        add_node(ip_id, f"{origin_ip} (Exposed Origin)", "ip", "HIGH", {"ip": origin_ip})

        exp_id = f"exp_waf_{idx}"
        add_node(exp_id, "WAF Edge Filter Bypass", "exposure", "HIGH", {"origin": origin_ip})
        add_link(ip_id, exp_id, "Exposes Backend", "HIGH")

        sink_id = f"sink_waf_{idx}"
        add_node(sink_id, "Direct Uninspected Exploitation / DDoS", "impact", "HIGH", {"impact": "Bypass WAF Rules"})
        add_link(exp_id, sink_id, "Direct Access", "HIGH")

        attack_chains.append({
            "title": f"Direct Origin Bypass: {origin_ip}",
            "severity": "HIGH",
            "path": [target, "CDN Edge", origin_ip, "Direct Web Application Attack"],
            "mitre": "T1564 / T1590"
        })

    # C. Cloud Storage Exposure Chain
    buckets = advanced_findings.get("cloud_storage", {}).get("buckets") or []
    public_buckets = [b for b in buckets if b.get("is_dangerous") or b.get("access_level") in {"PUBLIC_READ", "PUBLIC_WRITE"}]
    for idx, b in enumerate(public_buckets[:3]):
        b_name = b.get("bucket_name", "")
        provider = b.get("provider", "Cloud Storage")
        access = b.get("access_level", "PUBLIC_READ")

        exp_id = f"exp_bucket_{idx}"
        add_node(exp_id, f"Public {provider} ({b_name})", "exposure", "HIGH", {"access": access, "url": b.get("url")})
        add_link(target_id, exp_id, "Brute-forced Bucket", "HIGH")

        sink_id = f"sink_bucket_{idx}"
        add_node(sink_id, "Data Exfiltration & Object Poisoning", "impact", "HIGH", {"access": access})
        add_link(exp_id, sink_id, "Unauthenticated Read/Write", "HIGH")

        attack_chains.append({
            "title": f"Exposed Cloud Storage: {b_name}",
            "severity": "HIGH",
            "path": [target, f"{provider} Permutation", b_name, "Data Leakage / Exfiltration"],
            "mitre": "T1596.001 / T1530"
        })

    # D. Leaked JS Secrets Chain
    js_sec = advanced_findings.get("js_secrets", {}).get("findings") or []
    for idx, s in enumerate(js_sec[:3]):
        sec_type = s.get("secret_type", "Token")
        sev = s.get("severity", "HIGH")

        exp_id = f"exp_sec_{idx}"
        add_node(exp_id, f"Hardcoded Secret ({sec_type})", "exposure", sev, {"script": s.get("script_url")})
        add_link(target_id, exp_id, "Embedded in JS", sev)

        sink_id = f"sink_sec_{idx}"
        add_node(sink_id, f"Unauthorized API / Cloud Privilege Escalation", "impact", "CRITICAL", {"secret": sec_type})
        add_link(exp_id, sink_id, "Credential Stuffing", "CRITICAL")

        attack_chains.append({
            "title": f"Leaked {sec_type} in Frontend Scripts",
            "severity": "CRITICAL" if sev == "CRITICAL" else "HIGH",
            "path": [target, "Client Scripts", sec_type, "Cloud Privilege Escalation"],
            "mitre": "T1552.001"
        })

    # E. Exposed Config Files (.git, .env)
    exp_cfgs = advanced_findings.get("exposed_configs", {}).get("exposed_files") or []
    for idx, c in enumerate(exp_cfgs[:3]):
        desc = c.get("description", "Config File")
        url = c.get("url", "")

        exp_id = f"exp_cfg_{idx}"
        add_node(exp_id, f"Exposed {desc}", "exposure", "CRITICAL", {"url": url})
        add_link(target_id, exp_id, "Direct Web Hit", "CRITICAL")

        sink_id = f"sink_cfg_{idx}"
        add_node(sink_id, "Source Code Dump & Database Takeover", "impact", "CRITICAL", {"url": url})
        add_link(exp_id, sink_id, "Database Ingress", "CRITICAL")

        attack_chains.append({
            "title": f"Exposed Configuration: {desc}",
            "severity": "CRITICAL",
            "path": [target, url, desc, "Source Code & Database Compromise"],
            "mitre": "T1552.005"
        })

    # F. Email Impersonation Chain
    email_sec = advanced_findings.get("email_security") or {}
    if email_sec.get("spoofable"):
        exp_id = "exp_email_spoof"
        add_node(exp_id, "Missing / Ineffective DMARC (p=none)", "exposure", "HIGH", email_sec)
        add_link(target_id, exp_id, "DNS TXT Query", "HIGH")

        sink_id = "sink_email_spoof"
        add_node(sink_id, "Executive Impersonation & Business Email Compromise (BEC)", "impact", "HIGH", email_sec)
        add_link(exp_id, sink_id, "Direct Spoofing", "HIGH")

        attack_chains.append({
            "title": "Unauthenticated Email Spoofing (BEC)",
            "severity": "HIGH",
            "path": [target, "DNS SPF/DMARC", "Permissive Policy", "Executive Spearphishing"],
            "mitre": "T1566.002"
        })

    # G. Weaponized CVE Chain (EPSS / KEV)
    weaponized = advanced_findings.get("threat_prioritization", {}).get("cves") or []
    for idx, c in enumerate(weaponized[:3]):
        cve_id = c.get("cve_id", "")
        ip_addr = c.get("ip", "")
        is_kev = c.get("cisa_kev", False)
        epss = c.get("epss_score") or 0.0

        if is_kev or epss >= 0.50:
            exp_id = f"exp_cve_{idx}"
            add_node(exp_id, f"Weaponized {cve_id} (EPSS: {epss:.0%})", "exposure", "CRITICAL", c)
            ip_id = f"ip_{ip_addr}" if ip_addr else target_id
            add_link(ip_id, exp_id, "Runs Vulnerable Service", "CRITICAL")

            sink_id = f"sink_cve_{idx}"
            add_node(sink_id, f"Remote Code Execution (RCE) on {ip_addr or target}", "impact", "CRITICAL", c)
            add_link(exp_id, sink_id, "Weaponized Exploit", "CRITICAL")

            attack_chains.append({
                "title": f"Weaponized Vulnerability: {cve_id}",
                "severity": "CRITICAL",
                "path": [target, ip_addr or "Host", cve_id, "Remote Code Execution"],
                "mitre": "T1190"
            })

    return {
        "nodes": nodes,
        "links": links,
        "attack_chains": attack_chains,
        "summary": {
            "total_nodes": len(nodes),
            "total_links": len(links),
            "active_attack_chains_count": len(attack_chains),
        }
    }
