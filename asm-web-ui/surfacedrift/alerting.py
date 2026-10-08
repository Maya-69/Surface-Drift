from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

COLOR_CRITICAL = 0xEF4444  # Red
COLOR_HIGH = 0xF97316      # Orange
COLOR_INFO = 0x43E2D2      # Aqua / Cyan


def format_slack_alert(
    domain: str,
    drift: Dict[str, Any],
) -> Dict[str, Any]:
    """Format structured Slack webhook notification."""
    is_critical = drift.get("has_critical_drift", False)
    header_text = (
        f"🚨 *CRITICAL ATTACK SURFACE DRIFT DETECTED: {domain}*"
        if is_critical
        else f"🛡️ *SurfaceDrift Snapshot Change Detected: {domain}*"
    )

    score_text = (
        f"*Risk Score:* {drift.get('current_score')} (Delta: {drift.get('score_delta'):+d}) | "
        f"*Grade:* {drift.get('current_grade')}"
    )

    changes = []
    if drift.get("new_takeovers"):
        changes.append(f"• ⚠️ *New Subdomain Takeover:* {', '.join(drift['new_takeovers'])}")
    if drift.get("new_public_buckets"):
        changes.append(f"• 🔓 *New Public Buckets:* {', '.join(drift['new_public_buckets'])}")
    if drift.get("new_vulnerabilities"):
        changes.append(f"• 💥 *New Vulnerabilities:* {', '.join(drift['new_vulnerabilities'])}")
    if drift.get("new_subdomains"):
        changes.append(f"• 🌐 *New Subdomains ({len(drift['new_subdomains'])}):* {', '.join(drift['new_subdomains'][:5])}")
    if drift.get("new_open_ports"):
        changes.append(f"• 🚪 *New Open Ports:* {', '.join(drift['new_open_ports'][:5])}")

    body_text = "\n".join(changes) if changes else "No critical changes recorded."

    return {
        "text": header_text,
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": header_text},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": score_text},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": body_text},
            },
        ],
    }


def format_discord_alert(
    domain: str,
    drift: Dict[str, Any],
) -> Dict[str, Any]:
    """Format structured Discord webhook notification."""
    is_critical = drift.get("has_critical_drift", False)
    color = COLOR_CRITICAL if is_critical else COLOR_INFO

    fields = [
        {
            "name": "Score & Grade",
            "value": f"{drift.get('current_score')} ({drift.get('score_delta'):+d}) — Grade {drift.get('current_grade')}",
            "inline": True,
        }
    ]

    if drift.get("new_takeovers"):
        fields.append({
            "name": "⚠️ New Takeovers",
            "value": "\n".join(drift["new_takeovers"][:5]),
            "inline": False,
        })
    if drift.get("new_public_buckets"):
        fields.append({
            "name": "🔓 Public Storage Buckets",
            "value": "\n".join(drift["new_public_buckets"][:5]),
            "inline": False,
        })
    if drift.get("new_subdomains"):
        fields.append({
            "name": f"🌐 New Subdomains ({len(drift['new_subdomains'])})",
            "value": "\n".join(drift["new_subdomains"][:5]),
            "inline": False,
        })

    return {
        "content": f"**SurfaceDrift Alert for {domain}**",
        "embeds": [
            {
                "title": f"Drift Detected: {domain}",
                "color": color,
                "fields": fields,
            }
        ],
    }


async def send_webhook_alert(
    webhook_url: str,
    payload: Dict[str, Any],
    client: httpx.AsyncClient,
    max_retries: int = 3,
) -> bool:
    """
    Send webhook alert with exponential backoff for transient failures and rate limits.
    """
    for attempt in range(max_retries):
        try:
            resp = await client.post(webhook_url, json=payload, timeout=6.0)
            if resp.status_code in (200, 204):
                return True
            elif resp.status_code == 429 or resp.status_code >= 500:
                await asyncio.sleep(0.05 * (2 ** attempt))
                continue
            else:
                logger.warning("Webhook rejected with status %d: %s", resp.status_code, resp.text)
                return False
        except Exception as exc:
            if attempt == max_retries - 1:
                logger.warning("Failed to deliver webhook to %s: %s", webhook_url, exc)
                return False
            await asyncio.sleep(0.05 * (2 ** attempt))

    return False
