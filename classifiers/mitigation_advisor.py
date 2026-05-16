from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger(__name__)


_SYSTEM_PROMPT = """You are an AI security analyst writing actionable mitigations
for a security team that maintains an AI-using enterprise. Given one threat
intelligence item and a list of the company's AI assets, write 3-5 concrete,
specific mitigation actions tailored to THIS threat.

Rules:
- Output Markdown bullet list. No headers, no preamble, no closing remarks.
- Each bullet is one short sentence (<=180 chars). Imperative voice.
- Be specific to the named technology/CVE in the item. Avoid generic advice
  like "patch promptly" unless that is genuinely the primary action.
- If the threat plausibly touches one of the listed company assets, name it
  in at least one bullet (e.g., "On GitHub Copilot Business, ...").
- If the item is purely informational (e.g., a blog post about AI defense),
  output exactly: NO_ACTION
- Reply in English unless the source title is in another language.
"""


class MitigationAdvisor:
    """Generate per-item mitigation advice using Claude."""

    def __init__(
        self,
        company_assets: list[dict[str, Any]] | None = None,
        model: str = "claude-haiku-4-5-20251001",
        api_key: str | None = None,
    ) -> None:
        try:
            import anthropic  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("anthropic package not installed") from exc

        self._anthropic = anthropic
        self._client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
        self._model = model
        self._assets = company_assets or []

    @property
    def assets_blob(self) -> str:
        lines = []
        for a in self._assets:
            name = a.get("name", "?")
            cat = a.get("category", "?")
            access = ", ".join(a.get("data_access") or [])
            lines.append(f"- {name} ({cat}; data access: {access or 'n/a'})")
        return "\n".join(lines) or "(no assets defined)"

    def advise(self, record: dict[str, Any]) -> str:
        title = record.get("title") or ""
        summary = record.get("summary") or ""
        category = record.get("category") or ""
        severity = record.get("severity") or ""
        source = record.get("source") or ""
        url = record.get("url") or ""

        user = (
            f"Company AI assets:\n{self.assets_blob}\n\n"
            f"Threat item:\n"
            f"- Title: {title}\n"
            f"- Category: {category}\n"
            f"- Severity: {severity}\n"
            f"- Source: {source}\n"
            f"- URL: {url}\n"
            f"- Summary: {summary[:1500]}\n"
        )

        try:
            resp = self._client.messages.create(
                model=self._model,
                max_tokens=600,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user}],
            )
            parts = [getattr(b, "text", "") for b in resp.content]
            text = "".join(parts).strip()
        except Exception as exc:  # noqa: BLE001
            log.warning("MitigationAdvisor failed for %s: %s", record.get("threat_id"), exc)
            return ""

        if text.strip().upper().startswith("NO_ACTION"):
            return ""
        return text[:2000]
