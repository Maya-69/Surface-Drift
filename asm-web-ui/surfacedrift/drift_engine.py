from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


def generate_asset_hash(
    subdomains: List[str],
    ip_records: List[str],
    open_ports: List[str],
    buckets: List[str],
) -> str:
    """
    Generate deterministic SHA-256 fingerprint of current asset inventory.
    """
    components = [
        "|".join(sorted(set(subdomains))),
        "|".join(sorted(set(ip_records))),
        "|".join(sorted(set(open_ports))),
        "|".join(sorted(set(buckets))),
    ]
    raw_key = "###".join(components).encode("utf-8")
    return hashlib.sha256(raw_key).hexdigest()


def compute_surface_drift(
    prior_snapshot: Dict[str, Any],
    current_snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compute fine-grained continuous threat exposure delta between two snapshots.

    Each snapshot expects raw_json format containing:
    {
        "subdomains": ["api.example.com", ...],
        "open_ports": ["1.2.3.4:443", "1.2.3.4:80", ...],
        "vulnerabilities": ["CVE-2021-44228", ...],
        "takeovers": ["docs.example.com", ...],
        "public_buckets": ["example-backup", ...],
        "risk_score": 85,
        "grade": "B"
    }
    """
    prior_subs: Set[str] = set(prior_snapshot.get("subdomains") or [])
    curr_subs: Set[str] = set(current_snapshot.get("subdomains") or [])

    prior_ports: Set[str] = set(prior_snapshot.get("open_ports") or [])
    curr_ports: Set[str] = set(current_snapshot.get("open_ports") or [])

    prior_vulns: Set[str] = set(prior_snapshot.get("vulnerabilities") or [])
    curr_vulns: Set[str] = set(current_snapshot.get("vulnerabilities") or [])

    prior_takeovers: Set[str] = set(prior_snapshot.get("takeovers") or [])
    curr_takeovers: Set[str] = set(current_snapshot.get("takeovers") or [])

    prior_buckets: Set[str] = set(prior_snapshot.get("public_buckets") or [])
    curr_buckets: Set[str] = set(current_snapshot.get("public_buckets") or [])

    new_subdomains = sorted(list(curr_subs - prior_subs))
    removed_subdomains = sorted(list(prior_subs - curr_subs))

    new_open_ports = sorted(list(curr_ports - prior_ports))
    closed_ports = sorted(list(prior_ports - curr_ports))

    new_vulnerabilities = sorted(list(curr_vulns - prior_vulns))
    resolved_vulnerabilities = sorted(list(prior_vulns - curr_vulns))

    new_takeovers = sorted(list(curr_takeovers - prior_takeovers))
    resolved_takeovers = sorted(list(prior_takeovers - curr_takeovers))

    new_public_buckets = sorted(list(curr_buckets - prior_buckets))
    resolved_public_buckets = sorted(list(prior_buckets - curr_buckets))

    prior_score = prior_snapshot.get("risk_score", 100)
    curr_score = current_snapshot.get("risk_score", 100)
    score_delta = curr_score - prior_score

    prior_grade = prior_snapshot.get("grade", "A")
    curr_grade = current_snapshot.get("grade", "A")
    grade_changed = prior_grade != curr_grade

    has_critical_drift = bool(
        new_takeovers
        or new_public_buckets
        or new_vulnerabilities
        or (score_delta <= -15)
    )

    has_drift = bool(
        new_subdomains
        or removed_subdomains
        or new_open_ports
        or closed_ports
        or new_vulnerabilities
        or resolved_vulnerabilities
        or new_takeovers
        or resolved_takeovers
        or new_public_buckets
        or score_delta != 0
    )

    return {
        "has_drift": has_drift,
        "has_critical_drift": has_critical_drift,
        "score_delta": score_delta,
        "prior_score": prior_score,
        "current_score": curr_score,
        "grade_changed": grade_changed,
        "prior_grade": prior_grade,
        "current_grade": curr_grade,
        "new_subdomains": new_subdomains,
        "removed_subdomains": removed_subdomains,
        "new_open_ports": new_open_ports,
        "closed_ports": closed_ports,
        "new_vulnerabilities": new_vulnerabilities,
        "resolved_vulnerabilities": resolved_vulnerabilities,
        "new_takeovers": new_takeovers,
        "resolved_takeovers": resolved_takeovers,
        "new_public_buckets": new_public_buckets,
        "resolved_public_buckets": resolved_public_buckets,
    }
