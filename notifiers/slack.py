from __future__ import annotations

import logging
import os
from typing import Any

import requests

log = logging.getLogger(__name__)


class SlackNotifier:
    """Send messages to a Slack Incoming Webhook (Block Kit format)."""

    REQUEST_TIMEOUT = 20

    _PRIORITY_EMOJI = {
        "Critical": ":rotating_light:",
        "High": ":warning:",
        "Medium": ":large_orange_diamond:",
        "Low": ":information_source:",
    }

    def __init__(self, webhook_url: str | None = None) -> None:
        self.webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL") or ""

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def notify(self, record: dict[str, Any]) -> bool:
        if not self.enabled:
            log.info(
                "[slack] webhook not configured, skipping (priority=%s, title=%s)",
                record.get("priority"),
                (record.get("title") or "")[:80],
            )
            return False

        priority = record.get("priority") or "Low"
        severity = record.get("severity") or "Low"
        title = (record.get("title") or "(no title)")[:300]
        url = record.get("url") or ""
        category = record.get("category") or "Unknown"
        company_impact = record.get("company_impact") or "Unknown"
        affected = record.get("affected_asset") or "-"
        reason = (record.get("reason") or "-")[:1000]
        action = (record.get("recommended_action") or "-")[:1000]
        source = record.get("source") or "-"
        threat_id = record.get("threat_id") or "-"

        emoji = self._PRIORITY_EMOJI.get(priority, ":information_source:")

        header_text = f"{emoji} [AI Threat Watch] {priority} Risk — {category}"
        title_md = f"<{url}|{_slack_escape(title)}>" if url else _slack_escape(title)

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header_text[:150], "emoji": True},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{title_md}*"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity*\n{severity}"},
                    {"type": "mrkdwn", "text": f"*Company Impact*\n{company_impact}"},
                    {"type": "mrkdwn", "text": f"*Affected Asset*\n{_slack_escape(affected or '-')}"},
                    {"type": "mrkdwn", "text": f"*Source*\n{_slack_escape(source)}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Reason*\n{_slack_escape(reason)}"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Recommended Action*\n{_slack_escape(action)}"},
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"`{threat_id}` · {_slack_escape(source)}"},
                ],
            },
        ]

        payload = {
            "text": f"[AI Threat Watch] {priority} - {title[:100]}",  # fallback for notifications
            "blocks": blocks,
        }

        try:
            resp = requests.post(
                self.webhook_url,
                json=payload,
                timeout=self.REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            log.warning("Slack notify failed for %s: %s", threat_id, exc)
            return False
        return True


def _slack_escape(text: str) -> str:
    """Escape Slack mrkdwn special characters: & < >."""
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
