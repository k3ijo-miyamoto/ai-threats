from __future__ import annotations

import logging
import os
from typing import Any

import requests

log = logging.getLogger(__name__)


class TeamsNotifier:
    """Send messages to a Microsoft Teams Incoming Webhook (MessageCard format)."""

    REQUEST_TIMEOUT = 20

    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = webhook_url or os.environ.get("TEAMS_WEBHOOK_URL") or ""

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def notify(self, record: dict[str, Any]) -> bool:
        if not self.enabled:
            log.info("[teams] webhook not configured, skipping (priority=%s, title=%s)",
                     record.get("priority"), (record.get("title") or "")[:80])
            return False

        priority = record.get("priority") or "Low"
        title = record.get("title") or "(no title)"
        url = record.get("url") or ""
        category = record.get("category") or "Unknown"
        company_impact = record.get("company_impact") or "Unknown"
        affected = record.get("affected_asset") or "-"
        reason = record.get("reason") or "-"
        action = record.get("recommended_action") or "-"
        severity = record.get("severity") or "Low"
        source = record.get("source") or "-"
        threat_id = record.get("threat_id") or "-"

        theme = {"High": "D13438", "Medium": "F7630C", "Low": "2D7D9A", "Critical": "8E0000"}.get(
            priority, "2D7D9A"
        )

        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": f"[AI Threat Watch] {priority} - {title[:80]}",
            "themeColor": theme,
            "title": f"[AI Threat Watch] {priority} Risk - {category}",
            "sections": [
                {
                    "activityTitle": title,
                    "activitySubtitle": f"{source} | {threat_id}",
                    "facts": [
                        {"name": "Severity", "value": severity},
                        {"name": "Company Impact", "value": company_impact},
                        {"name": "Affected Asset", "value": affected or "-"},
                        {"name": "Reason", "value": reason},
                        {"name": "Recommended Action", "value": action},
                    ],
                    "markdown": True,
                }
            ],
            "potentialAction": [
                {
                    "@type": "OpenUri",
                    "name": "Open source",
                    "targets": [{"os": "default", "uri": url}],
                }
            ] if url else [],
        }

        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                timeout=self.REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            log.warning("Teams notify failed for %s: %s", threat_id, exc)
            return False
        return True
