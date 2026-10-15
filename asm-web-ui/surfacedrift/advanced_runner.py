from __future__ import annotations

import asyncio
import json
import logging
import os
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .cdn_detector import evaluate_waf_bypass, is_cdn_ip
from .cloud_auditor import audit_cloud_storage
from .email_security import audit_email_security
from .epss_kev import compute_priority_tag, is_cisa_kev_listed, query_epss_score
from .gemini_summarizer import generate_executive_summary
from .http_probing import probe_subdomains
from .risk_scoring import calculate_risk_score
from .takeover import audit_subdomains_takeover

logger = logging.getLogger(__name__)


async def run_advanced_assessment(
    scan_id: str,
    target: str,
    subdomains: List[str],
    ip_records: List[Dict[str, Any]],
    ports_and_vulns: List[Dict[str, Any]],
    buckets_initial: List[str],
    email_sec_initial: Dict[str, Any],
    categories: List[str],
    output_dir: Path,
    artifacts_dir: Path,
    on_log: Optional[Callable[[str], Any]] = None,
) -> Dict[str, Any]:
    """
    Execute selected SurfaceDrift advanced CTEM and threat assessment engines
    sequentially and concurrently on top of initial reconnaissance data.
    Provides real-time telemetry events via `on_log`.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    logs_collected: List[str] = []

    def emit(line: str) -> None:
        logger.info("[SurfaceDrift] %s", line)
        logs_collected.append(line)
        if on_log:
            try:
                res = on_log(line)
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
            except Exception:
                pass

    enabled_cats = set(categories) if categories else {
        "http_probe", "takeover", "cloud_audit", "waf_bypass", "epss_kev", "email_sec"
    }

    emit(f"[-] SurfaceDrift CTEM Pipeline initialized for: {target}")
    emit(f"[i] Input reconnaissance scope: {len(subdomains)} subdomains, {len(ip_records)} IP records")
    emit(f"[i] Assessment categories enabled: {', '.join(sorted(enabled_cats))}")

    # Clean subdomains list: guarantee root domain is included
    all_subs = list(dict.fromkeys([target] + [s.strip().lower() for s in subdomains if s.strip()]))

    # 1. HTTP Probing & Tech Fingerprinting
    http_probed_results: List[Dict[str, Any]] = []
    live_count = 0
    if "http_probe" in enabled_cats:
        probe_limit = all_subs[:80]
        emit(f"[-] Starting HTTP/HTTPS probing across {len(probe_limit)} subdomains (concurrency=20)...")
        probe_objs = await probe_subdomains(probe_limit, max_concurrency=20, timeout=4.5)
        for obj in probe_objs:
            if obj.is_live:
                live_count += 1
                status_code = obj.https_status or obj.http_status or 200
                tech_snippet = ", ".join(obj.tech_stack[:3]) if obj.tech_stack else (obj.server_banner or "Online")
                emit(f"[+] [HTTP {status_code}] {obj.subdomain} — {tech_snippet}")
            http_probed_results.append({
                "subdomain": obj.subdomain,
                "is_live": obj.is_live,
                "http_status": obj.http_status,
                "https_status": obj.https_status,
                "page_title": obj.page_title,
                "server_banner": obj.server_banner,
                "tech_stack": obj.tech_stack,
                "redirect_chain": obj.redirect_chain,
            })
        emit(f"[+] HTTP Probing complete: {live_count} live web endpoints detected across {len(probe_limit)} targets")

    # 2. Subdomain Takeover Auditing
    takeovers_found: List[Dict[str, Any]] = []
    if "takeover" in enabled_cats:
        emit(f"[-] Querying DNS CNAME records for {len(all_subs[:80])} hostnames...")
        emit("[*] Auditing 14 cloud service signatures (GitHub Pages, AWS S3, Heroku, Shopify, Zendesk, Fastly, etc.)...")
        takeover_objs = await audit_subdomains_takeover(all_subs[:80], concurrency=15, timeout=4.0)
        for t in takeover_objs:
            if t.is_vulnerable:
                takeovers_found.append({
                    "subdomain": t.subdomain,
                    "cname": t.cname,
                    "service": t.service,
                    "matched_signature": t.matched_signature,
                })
                emit(f"[!] CRITICAL: Dangling CNAME takeover discovered on {t.subdomain} -> {t.cname} ({t.service})")
        if not takeovers_found:
            emit("[+] Subdomain takeover audit complete: 0 dangling CNAME endpoints detected")
        else:
            emit(f"[!] Subdomain takeover audit finished: {len(takeovers_found)} vulnerable hostnames found!")

    # 3. Cloud Storage Auditing
    cloud_buckets_found: List[Dict[str, Any]] = []
    public_buckets_count = 0
    if "cloud_audit" in enabled_cats:
        emit(f"[-] Generating cloud storage permutations for '{target}'...")
        emit("[*] Concurrently auditing AWS S3, Azure Blob, and GCP Cloud Storage buckets...")
        cloud_objs = await audit_cloud_storage(target, max_concurrency=12)
        for b in cloud_objs:
            if b.is_dangerous:
                public_buckets_count += 1
                emit(f"[!] WARNING: Exposed cloud bucket found: {b.bucket_name} ({b.provider}) — Access: {b.access_level}")
            else:
                emit(f"[+] Protected cloud bucket detected: {b.bucket_name} ({b.provider})")
            cloud_buckets_found.append({
                "bucket_name": b.bucket_name,
                "provider": b.provider,
                "url": b.url,
                "access_level": b.access_level,
                "http_status_code": b.http_status_code,
                "is_dangerous": b.is_dangerous,
            })
        if not cloud_buckets_found:
            emit("[+] Cloud storage audit complete: No exposed public buckets identified")
        else:
            emit(f"[+] Cloud storage audit complete: {len(cloud_buckets_found)} buckets tested ({public_buckets_count} public)")

    # 4. Infrastructure & WAF Origin Bypass
    waf_bypasses: List[Dict[str, Any]] = []
    enriched_ips: List[Dict[str, Any]] = []
    if "waf_bypass" in enabled_cats:
        emit(f"[-] Inspecting BGP ASNs and CDN edge routing for {len(ip_records)} IP addresses...")
        ip_payloads = []
        for rec in ip_records:
            ip_str = rec.get("ip") or rec.get("ip_address") or ""
            asn_org = rec.get("asn_description") or rec.get("asn_org") or ""
            asn = rec.get("asn") or ""
            is_cdn, provider = is_cdn_ip(asn_org=asn_org, asn=asn)
            ip_payloads.append({
                "ip_address": ip_str,
                "asn": asn,
                "asn_org": asn_org,
                "cloud_provider": provider or asn_org,
                "is_cdn": is_cdn,
                "hostnames": [target],
                "ports": rec.get("ports", []),
            })

        evaluated = evaluate_waf_bypass(ip_payloads)
        for item in evaluated:
            if item.get("is_waf_bypass"):
                waf_bypasses.append(item)
                emit(f"[!] Warning: Potential WAF origin bypass on IP {item.get('ip_address')} ({item.get('asn_org', 'Direct Origin')})")
            enriched_ips.append(item)
        if not waf_bypasses:
            emit("[+] WAF origin bypass analysis complete: All assets routed through recognized CDN edge")
        else:
            emit(f"[+] WAF origin bypass analysis complete: {len(waf_bypasses)} direct origins identified")
    else:
        enriched_ips = ip_records

    # 5. Threat Prioritization (EPSS & CISA KEV)
    weaponized_vulns: List[Dict[str, Any]] = []
    critical_vulns_count = 0
    high_vulns_count = 0
    if "epss_kev" in enabled_cats:
        emit("[-] Prioritizing vulnerabilities via FIRST.org EPSS and CISA KEV catalog...")
        import httpx
        async with httpx.AsyncClient(timeout=4.0) as client:
            for item in ports_and_vulns:
                v_list = item.get("vulnerabilities", [])
                for v in v_list:
                    cve = v.strip().upper()
                    if cve.startswith("CVE-"):
                        epss, percentile = await query_epss_score(cve, client)
                        is_kev = is_cisa_kev_listed(cve)
                        tag = compute_priority_tag(cve_id=cve, cvss_score=None, epss_score=epss, cisa_kev=is_kev)
                        if is_kev or (epss and epss >= 0.60):
                            critical_vulns_count += 1
                            emit(f"[!] HIGH WEAPONIZED CVE: {cve} (CISA KEV: {is_kev}, EPSS: {epss or 0:.1%}) on IP {item.get('ip')}")
                        elif tag == "HIGH":
                            high_vulns_count += 1
                            emit(f"[*] High-priority vulnerability: {cve} (EPSS: {epss or 0:.1%})")
                        elif tag == "MED":
                            emit(f"[*] Medium-priority vulnerability: {cve} (EPSS: {epss or 0:.1%})")

                        weaponized_vulns.append({
                            "cve_id": cve,
                            "ip": item.get("ip"),
                            "epss_score": epss,
                            "epss_percentile": percentile,
                            "cisa_kev": is_kev,
                            "priority_tag": tag,
                        })
        if not weaponized_vulns:
            emit("[+] Threat prioritization complete: Zero actively exploited CVEs detected")
        else:
            emit(f"[+] Threat prioritization complete: {len(weaponized_vulns)} CVEs evaluated ({critical_vulns_count} critical)")

    # 6. Email Security Posture
    email_sec_data: Dict[str, Any] = {}
    if "email_sec" in enabled_cats:
        emit(f"[-] Querying DNS TXT records for SPF and DMARC enforcement on '{target}'...")
        email_sec_data = await audit_email_security(target)
        spf = email_sec_data.get("spf_status", "NOT_FOUND")
        dmarc = email_sec_data.get("dmarc_status", "NOT_FOUND")
        spoof = email_sec_data.get("spoofable", False)
        if spoof:
            emit(f"[!] Email Spoofing Risk: SPF={spf}, DMARC={dmarc} — Unauthenticated email spoofing possible")
        else:
            emit(f"[+] Email Posture Enforced: SPF={spf}, DMARC={dmarc} — Spoofing prevented")
    else:
        email_sec_data = {
            "spf_status": "NOT_AUDITED",
            "dmarc_status": "NOT_AUDITED",
            "spoofable": False,
            "risk_flag": "NOT_AUDITED",
        }

    # Exposed Admin Ports check
    exposed_admin_ports = 0
    admin_port_numbers = {6379, 27017, 9200, 3389, 23, 5432, 3306}
    for item in ports_and_vulns:
        ports = item.get("ports", [])
        for p in ports:
            try:
                p_num = int(str(p).split("/")[0])
                if p_num in admin_port_numbers:
                    exposed_admin_ports += 1
                    emit(f"[!] Warning: Exposed sensitive administration port {p} detected on IP {item.get('ip')}")
            except Exception:
                pass

    # 7. Compute Composite Risk Score & Grade
    emit("[-] Computing composite SurfaceDrift posture score and letter grade...")
    risk_eval = calculate_risk_score(
        critical_vulns_count=critical_vulns_count,
        high_vulns_count=high_vulns_count,
        takeovers_count=len(takeovers_found),
        public_buckets_count=public_buckets_count,
        exposed_admin_ports_count=exposed_admin_ports,
        waf_bypass_count=len(waf_bypasses),
        email_risk_flag=email_sec_data.get("risk_flag", "SECURE_ENFORCED"),
    )

    breakdown_dicts = [
        {"category": b.category, "description": b.description, "deduction": b.deduction}
        for b in risk_eval.breakdown
    ]
    emit(f"[+] Composite Posture Score: {risk_eval.score}/100 (Grade {risk_eval.grade})")
    for b in breakdown_dicts:
        emit(f"[*] Deduction [-{b['deduction']} pts] {b['category']}: {b['description']}")

    # 8. Generate Threat Summary
    emit("[-] Generating executive threat exposure summary...")
    ai_summary = generate_executive_summary(
        target=target,
        score=risk_eval.score,
        grade=risk_eval.grade,
        breakdown=breakdown_dicts,
        subdomains_count=len(all_subs),
        live_hosts_count=live_count,
        ips_count=len(ip_records),
        takeovers=takeovers_found,
        public_buckets=cloud_buckets_found,
        weaponized_vulns=weaponized_vulns,
        waf_bypasses=waf_bypasses,
        email_sec=email_sec_data,
    )
    emit(f"[+] Executive threat summary generated successfully")

    # 9. Structure Final Advanced Assessment Report
    advanced_report = {
        "scan_id": scan_id,
        "target": target,
        "categories_executed": list(enabled_cats),
        "posture": {
            "score": risk_eval.score,
            "grade": risk_eval.grade,
            "breakdown": breakdown_dicts,
        },
        "ai_executive_summary": ai_summary,
        "findings": {
            "http_probing": {
                "live_hosts_count": live_count,
                "results": http_probed_results,
            },
            "subdomain_takeovers": {
                "count": len(takeovers_found),
                "items": takeovers_found,
            },
            "cloud_storage": {
                "count": len(cloud_buckets_found),
                "public_count": public_buckets_count,
                "buckets": cloud_buckets_found,
            },
            "waf_bypass": {
                "count": len(waf_bypasses),
                "origins": waf_bypasses,
                "all_ips": enriched_ips,
            },
            "threat_prioritization": {
                "critical_count": critical_vulns_count,
                "high_count": high_vulns_count,
                "cves": weaponized_vulns,
            },
            "email_security": email_sec_data,
        },
        "logs": logs_collected,
    }

    # 10. Persist SurfaceDrift Artifacts to Disk
    emit("[-] Saving SurfaceDrift structured artifacts to disk...")
    try:
        (output_dir / "surfacedrift_advanced_report.json").write_text(
            json.dumps(advanced_report, indent=2), encoding="utf-8"
        )
        (output_dir / "surfacedrift_executive_summary.md").write_text(
            ai_summary.get("content", ""), encoding="utf-8"
        )
        (output_dir / "surfacedrift_takeover_audit.json").write_text(
            json.dumps(takeovers_found, indent=2), encoding="utf-8"
        )
        (output_dir / "surfacedrift_http_probes.json").write_text(
            json.dumps(http_probed_results, indent=2), encoding="utf-8"
        )
        (output_dir / "surfacedrift_risk_score.json").write_text(
            json.dumps({"score": risk_eval.score, "grade": risk_eval.grade, "breakdown": breakdown_dicts}, indent=2),
            encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("Could not write all SurfaceDrift JSON files: %s", exc)

    # 11. Create Consolidated Combined ZIP Archive
    combined_zip_name = f"surfacedrift-complete-{scan_id}.zip"
    combined_zip_path = artifacts_dir / combined_zip_name
    emit(f"[-] Packaging all reconnaissance and CTEM assets into consolidated ZIP: {combined_zip_name}...")
    try:
        with zipfile.ZipFile(combined_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in sorted(output_dir.rglob("*")):
                if p.is_file() and not p.name.endswith(".zip"):
                    arcname = p.relative_to(output_dir)
                    zf.write(p, arcname=str(arcname))
        advanced_report["combined_zip_name"] = combined_zip_name
        advanced_report["combined_zip_size"] = combined_zip_path.stat().st_size
        size_kb = advanced_report["combined_zip_size"] / 1024
        emit(f"[+] Consolidated report bundle ready: {combined_zip_name} ({size_kb:.1f} KB)")
    except Exception as exc:
        logger.error("Failed creating combined zip: %s", exc)

    emit("[+] SurfaceDrift assessment completed successfully!")
    return advanced_report
